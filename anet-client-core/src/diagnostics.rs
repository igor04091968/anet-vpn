//! Bounded observations only: never changes VPN state, authentication or routes.
use crate::{
    config::{CoreConfig, TransportMode},
    connection_limits::{ConnectionLimiter, LimitedTcpStream},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpSocket,
    time::{Instant, timeout},
};
pub use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DiagnosticOptions {
    pub extended: bool,
    pub helper_path: Option<String>,
    pub timeout_ms: u64,
    /// Require a dedicated HTTPS echo endpoint; never POST arbitrary user data.
    pub echo_endpoint: Option<String>,
    pub active_session: bool,
    /// Opaque physical-network identifier; do not include SSID or subscriber data.
    pub network_context: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Observation {
    pub endpoint_index: usize,
    pub host: String,
    pub port: u16,
    pub transport: String,
    pub stage: String,
    pub status: String,
    pub code: String,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub schema_version: u32,
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub created_at_ms: u64,
    pub cancelled: bool,
    pub extended: bool,
    pub network_context: String,
    pub max_connections: usize,
    pub min_connect_interval_ms: u64,
    pub observations: Vec<Observation>,
    pub recommendations: Vec<String>,
}
impl DiagnosticReport {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
/// Android supplies physical-network DNS and binds/protects each socket before connect.
#[async_trait]
pub trait SocketEnvironment: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
    fn prepare(&self, _fd: i32) -> io::Result<()> {
        Ok(())
    }
}
pub struct SystemEnvironment;
#[async_trait]
impl SocketEnvironment for SystemEnvironment {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .take(8)
            .collect())
    }
}
async fn dial(
    limiter: &ConnectionLimiter,
    env: &dyn SocketEnvironment,
    address: SocketAddr,
) -> io::Result<LimitedTcpStream> {
    let permit = limiter.acquire().await?;
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        env.prepare(socket.as_raw_fd())?;
    }
    let stream = socket.connect(address).await?;
    Ok(LimitedTcpStream::from_stream(stream, permit))
}
async fn native_tls(stream: LimitedTcpStream, host: String) -> io::Result<()> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(
        crate::transport::bounded_http::AhttpServerVerifier,
    ))
    .with_no_client_auth();
    let sni = rustls::pki_types::ServerName::try_from(host).map_err(io::Error::other)?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(sni, stream)
        .await
        .map_err(io::Error::other)?;
    Ok(())
}
fn outcome(r: Result<io::Result<()>, tokio::time::error::Elapsed>) -> (&'static str, &'static str) {
    match r {
        Ok(Ok(())) => ("passed", "completed"),
        Err(_) => ("inconclusive", "timeout_or_budget_busy"),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            ("failed", "connection_refused")
        }
        Ok(Err(_)) => ("inconclusive", "network_or_protocol_error"),
    }
}
pub async fn run(
    config: &CoreConfig,
    options: DiagnosticOptions,
    cancel: CancellationToken,
    environment: Arc<dyn SocketEnvironment>,
) -> DiagnosticReport {
    run_shared(
        config,
        Arc::new(ConnectionLimiter::new(&config.connection_limits)),
        options,
        cancel,
        environment,
    )
    .await
}
pub(crate) async fn run_shared(
    config: &CoreConfig,
    limiter: Arc<ConnectionLimiter>,
    options: DiagnosticOptions,
    cancel: CancellationToken,
    environment: Arc<dyn SocketEnvironment>,
) -> DiagnosticReport {
    let duration = Duration::from_millis(if options.timeout_ms == 0 {
        5000
    } else {
        options.timeout_ms.clamp(100, 15000)
    });
    let mut report = DiagnosticReport { schema_version:2, profile_id:String::new(), created_at_ms:std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64, cancelled:false, extended:options.extended,
        network_context:options.network_context.chars().take(96).collect(), max_connections:config.connection_limits.max_connections,
        min_connect_interval_ms:config.connection_limits.min_connect_interval_ms, observations:vec![], recommendations:vec![
            "Ошибки сети не доказывают блокировку ТСПУ. TLS не подтверждает аутентификацию ANet; проверьте обычное подключение выбранного профиля.".into(),
            "Отпечаток uTLS относится только к диагностическому запросу. TLS-отпечаток рабочего транспорта автоматически не меняется.".into()] };
    // Cap endpoints and whole run independently of individual stages.
    let deadline = Instant::now() + Duration::from_secs(if options.extended { 180 } else { 60 });
    let remaining = || duration.min(deadline.saturating_duration_since(Instant::now()));
    for (index, server) in config.servers.iter().take(16).enumerate() {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        let (host, port) = match server.host_port() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mode = match server.mode() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let transport = format!("{mode:?}").to_lowercase();
        let mut add = |stage: &str,
                       status: &str,
                       code: &str,
                       started: Instant,
                       details: Option<serde_json::Value>| {
            report.observations.push(Observation {
                endpoint_index: index,
                host: host.clone(),
                port,
                transport: transport.clone(),
                stage: stage.into(),
                status: status.into(),
                code: code.into(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                details,
            })
        };
        let started = Instant::now();
        let resolved = tokio::select! { _=cancel.cancelled()=>break, r=timeout(remaining(), environment.resolve(&host,port))=>r };
        let addresses = match resolved {
            Ok(Ok(a)) if !a.is_empty() => {
                add("dns", "passed", "resolved", started, None);
                a
            }
            _ => {
                add(
                    "dns",
                    "inconclusive",
                    "resolution_failed_or_timeout",
                    started,
                    None,
                );
                continue;
            }
        };
        if mode == TransportMode::Quic {
            add(
                "protocol",
                "skipped",
                "requires_real_quic_gost_connection",
                Instant::now(),
                None,
            );
            continue;
        }
        // Try a bounded set of DNS answers; a broken first IPv6 answer is not a failed endpoint.
        let mut connected = None;
        let started = Instant::now();
        for address in addresses.into_iter().take(4) {
            let r = tokio::select! { _=cancel.cancelled()=>break, r=timeout(remaining(),dial(&limiter,environment.as_ref(),address))=>r };
            if let Ok(Ok(stream)) = r {
                connected = Some((stream, address));
                break;
            }
        }
        let Some((stream, address)) = connected else {
            add(
                "tcp",
                "inconclusive",
                "connect_failed_or_budget_busy",
                started,
                None,
            );
            continue;
        };
        add("tcp", "passed", "connected", started, None);
        let tls = server.dsn.starts_with("wss://") || server.dsn.starts_with("https://");
        if !tls {
            drop(stream);
            add(
                "protocol",
                "skipped",
                "requires_real_anet_authentication",
                Instant::now(),
                None,
            );
            continue;
        }
        let started = Instant::now();
        let r = tokio::select! { _=cancel.cancelled()=>break,r=timeout(remaining(),native_tls(stream,host.clone()))=>r };
        let (status, code) = outcome(r);
        add(
            "native_tls",
            status,
            code,
            started,
            Some(
                serde_json::json!({"certificate_validation":"not_checked","profile":"rustls_diagnostic","matches_transport_clienthello":false}),
            ),
        );
        if options.extended {
            for fingerprint in ["chrome", "firefox", "android"] {
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    break;
                }
                let started = Instant::now();
                if let Some(path) = options.helper_path.as_deref() {
                    let r = tokio::select! {_=cancel.cancelled()=>break,r=timeout(remaining(),dial(&limiter,environment.as_ref(),address))=>r};
                    match r {
                        Ok(Ok(stream)) => {
                            let result = helper::probe(
                                path,
                                stream,
                                &host,
                                fingerprint,
                                remaining(),
                                None,
                                cancel.clone(),
                            )
                            .await;
                            let status = result
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("inconclusive")
                                .to_owned();
                            let code = result
                                .get("code")
                                .and_then(|v| v.as_str())
                                .unwrap_or("helper_error")
                                .to_owned();
                            add("utls", &status, &code, started, Some(result));
                        }
                        _ => add(
                            "utls",
                            "inconclusive",
                            "connect_failed_or_budget_busy",
                            started,
                            None,
                        ),
                    }
                } else {
                    add("utls", "skipped", "helper_not_configured", started, None);
                    break;
                }
            }
            let started = Instant::now();
            let n = config.connection_limits.max_connections;
            if options.active_session
                || (n != 0 && n < 4)
                || config.connection_limits.min_connect_interval_ms != 0
            {
                add(
                    "parallel_tls_4",
                    "skipped",
                    "active_session_or_connection_policy",
                    started,
                    None,
                );
            } else {
                let jobs = (0..4).map(|_| async {
                    let stream = dial(&limiter, environment.as_ref(), address).await?;
                    native_tls(stream, host.clone()).await
                });
                let r = tokio::select! {_=cancel.cancelled()=>break,r=timeout(remaining(),futures::future::join_all(jobs))=>r};
                let completed = match r {
                    Ok(results) => results.iter().filter(|r| r.is_ok()).count(),
                    Err(_) => 0,
                };
                add(
                    "parallel_tls_4",
                    if completed == 4 {
                        "passed"
                    } else {
                        "inconclusive"
                    },
                    "native_parallel_observation",
                    started,
                    Some(
                        serde_json::json!({"completed":completed,"expected":4,"upstream_siberian_equivalent":false}),
                    ),
                );
            }
        }
    }
    // Transfer tests run only against a separately provided echo origin.
    if options.extended && !cancel.is_cancelled() {
        if let (Some(url), Some(helper_path)) = (&options.echo_endpoint, &options.helper_path) {
            if let Ok(uri) = url.parse::<http::Uri>() {
                if uri.scheme_str() == Some("https") && uri.host().is_some() {
                    let host = uri.host().unwrap();
                    let port = uri.port_u16().unwrap_or(443);
                    let started = Instant::now();
                    let task = async {
                        let addresses = environment.resolve(host, port).await?;
                        let address = *addresses
                            .first()
                            .ok_or_else(|| io::Error::other("empty DNS"))?;
                        dial(&limiter, environment.as_ref(), address).await
                    };
                    let r = tokio::select! {_=cancel.cancelled()=>None,r=timeout(remaining(),task)=>r.ok().and_then(Result::ok)};
                    if let Some(stream) = r {
                        let result = helper::probe(
                            helper_path,
                            stream,
                            host,
                            "android",
                            remaining(),
                            Some(uri.path()),
                            cancel.clone(),
                        )
                        .await;
                        report.observations.push(Observation {
                            endpoint_index: usize::MAX,
                            host: host.into(),
                            port,
                            transport: "echo_control".into(),
                            stage: "transfer_echo".into(),
                            status: result["status"].as_str().unwrap_or("inconclusive").into(),
                            code: result["code"].as_str().unwrap_or("helper_error").into(),
                            elapsed_ms: started.elapsed().as_millis() as u64,
                            details: Some(result),
                        });
                    }
                }
            }
        }
    }
    report.cancelled = cancel.is_cancelled();
    if Instant::now() >= deadline {
        report
            .recommendations
            .push("Достигнут предел длительности диагностики; часть проверок пропущена.".into());
    }
    report
}

#[cfg(unix)]
mod helper {
    use super::*;
    use libloading::Library;
    use std::{
        ffi::{CStr, CString, c_char},
        sync::atomic::{AtomicU64, Ordering},
    };
    static ID: AtomicU64 = AtomicU64::new(1);
    // Go starts runtime threads: never dlclose a Go shared library during process lifetime.
    static LIBRARIES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Arc<Library>>>,
    > = std::sync::OnceLock::new();
    pub(super) async fn probe(
        path: &str,
        stream: LimitedTcpStream,
        host: &str,
        profile: &str,
        duration: Duration,
        transfer: Option<&str>,
        cancel: CancellationToken,
    ) -> serde_json::Value {
        // Loading libraries is only allowed from an explicitly selected trusted local path.
        let library = {
            let mut libraries = LIBRARIES.get_or_init(Default::default).lock().unwrap();
            if let Some(library) = libraries.get(path) {
                library.clone()
            } else {
                let library = match unsafe { Library::new(path) } {
                    Ok(v) => Arc::new(v),
                    Err(_) => {
                        return serde_json::json!({"status":"skipped","code":"helper_unavailable"});
                    }
                };
                libraries.insert(path.to_owned(), library.clone());
                library
            }
        };
        type Probe = unsafe extern "C" fn(u64, i32, *const c_char) -> *mut c_char;
        type Cancel = unsafe extern "C" fn(u64);
        type Free = unsafe extern "C" fn(*mut c_char);
        let symbols = unsafe {
            (
                library.get::<Probe>(b"anet_dpi_probe\0"),
                library.get::<Cancel>(b"anet_dpi_cancel\0"),
                library.get::<Free>(b"anet_dpi_free\0"),
            )
        };
        let (probe, stop, free) = match symbols {
            (Ok(p), Ok(c), Ok(f)) => (*p, *c, *f),
            _ => return serde_json::json!({"status":"skipped","code":"helper_abi_mismatch"}),
        };
        let raw=CString::new(serde_json::json!({"fingerprint":profile,"sni":host,"timeout_ms":duration.as_millis(),"transfer_path":transfer.unwrap_or(""),"payload_bytes":65536}).to_string()).unwrap();
        let id = ID.fetch_add(1, Ordering::Relaxed);
        let lib = library.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            let _keep_library = lib;
            let _keep_socket = &stream;
            let ptr = unsafe { probe(id, stream.raw_fd(), raw.as_ptr()) };
            if ptr.is_null() {
                return serde_json::json!({"status":"inconclusive","code":"helper_empty_result"});
            }
            let result = unsafe { serde_json::from_slice(CStr::from_ptr(ptr).to_bytes()) };
            unsafe { free(ptr) };
            result.unwrap_or_else(
                |_| serde_json::json!({"status":"inconclusive","code":"helper_invalid_json"}),
            )
        });
        tokio::select! {r=&mut task=>r.unwrap_or_else(|_|serde_json::json!({"status":"inconclusive","code":"helper_task_failed"})),_ = cancel.cancelled()=> {
            // Retry cancellation until Go registers this probe; avoids the startup race.
            loop {
                unsafe {stop(id)};
                tokio::select! {_=&mut task=>break,_=tokio::time::sleep(Duration::from_millis(20))=>{}}
            }
            // The helper closed its duplicate; original socket retained N until then.
            serde_json::json!({"status":"cancelled","code":"cancelled"})
        }}
    }
}
#[cfg(not(unix))]
mod helper {
    use super::*;
    pub(super) async fn probe(
        _: &str,
        _: LimitedTcpStream,
        _: &str,
        _: &str,
        _: Duration,
        _: Option<&str>,
        _: CancellationToken,
    ) -> serde_json::Value {
        serde_json::json!({"status":"skipped","code":"helper_platform_unsupported"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(dsn: &str, n: usize) -> CoreConfig {
        let mut c: CoreConfig =
            toml::from_str(include_str!("../../contrib/config/client.toml")).unwrap();
        c.servers = vec![crate::config::ServerConfig {
            dsn: dsn.into(),
            ..Default::default()
        }];
        c.connection_limits.max_connections = n;
        c.connection_limits.min_connect_interval_ms = 0;
        c
    }
    fn tls_config() -> rustls::ServerConfig {
        let certs = rustls_pemfile::certs(
            &mut &include_bytes!("../tests/fixtures/connection-limit-test-cert.pem.fixture")[..],
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(
            &mut &include_bytes!("../tests/fixtures/connection-limit-test-key.pem.fixture")[..],
        )
        .unwrap()
        .unwrap();
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
    }
    #[tokio::test]
    async fn tls_report_is_sanitized_and_cap_skips_parallel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config()));
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(socket).await;
                });
            }
        });
        let c = config(
            &format!("https://localhost:{port}/secret-path?token=do-not-report"),
            1,
        );
        let report = run(
            &c,
            DiagnosticOptions {
                extended: true,
                ..Default::default()
            },
            CancellationToken::new(),
            Arc::new(SystemEnvironment),
        )
        .await;
        assert!(
            report
                .observations
                .iter()
                .any(|r| r.stage == "native_tls" && r.status == "passed")
        );
        assert!(
            report
                .observations
                .iter()
                .any(|r| r.stage == "parallel_tls_4" && r.status == "skipped")
        );
        let json = report.to_json().unwrap();
        assert!(!json.contains("do-not-report"));
        assert!(!json.contains("secret-path"));
        server.abort();
    }
    #[tokio::test]
    async fn cancellation_releases_shared_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let c = config(&format!("https://127.0.0.1:{}", address.port()), 1);
        let limiter = Arc::new(ConnectionLimiter::new(&c.connection_limits));
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let c = c.clone();
            let l = limiter.clone();
            let t = cancel.clone();
            async move {
                run_shared(
                    &c,
                    l,
                    DiagnosticOptions::default(),
                    t,
                    Arc::new(SystemEnvironment),
                )
                .await
            }
        });
        let (_socket, _) = listener.accept().await.unwrap();
        cancel.cancel();
        assert!(
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .cancelled
        );
        assert!(
            timeout(Duration::from_secs(1), limiter.acquire())
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn quic_never_reports_fake_tcp_success() {
        let c = config("quic://127.0.0.1:9", 1);
        let report = run(
            &c,
            DiagnosticOptions::default(),
            CancellationToken::new(),
            Arc::new(SystemEnvironment),
        )
        .await;
        assert!(!report.observations.iter().any(|r| r.stage == "tcp"));
        assert!(
            report
                .observations
                .iter()
                .any(|r| r.code == "requires_real_quic_gost_connection")
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn helper_uses_borrowed_socket_and_valid_json() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tools/dpi-helper/dist/libanet_dpi.so");
        if !path.exists() {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config()));
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(socket).await;
        });
        let l = ConnectionLimiter::new(&config("https://localhost", 1).connection_limits);
        let stream = l.connect_tcp(address).await.unwrap();
        let result = helper::probe(
            path.to_str().unwrap(),
            stream,
            "localhost",
            "android",
            Duration::from_secs(3),
            None,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result["status"], "passed", "{result}");
        assert_eq!(result["certificate_validation"], "not_checked");
        server.await.unwrap();
        assert!(timeout(Duration::from_secs(1), l.acquire()).await.is_ok());
    }
}
