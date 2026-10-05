//! Socket-level limits for AHTTP. HTTP request concurrency is not a connection cap.
use crate::{
    config::AhttpConfig,
    connection_limits::{ConnectionLimiter, LimitedTcpStream},
};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio_tungstenite::MaybeTlsStream;
use tower_service::Service;

#[derive(Clone)]
struct LimitedConnector {
    address: SocketAddr,
    host: String,
    port: u16,
    scheme: String,
    limiter: Arc<ConnectionLimiter>,
    tls: Arc<rustls::ClientConfig>,
    nodelay: bool,
    timeout: Duration,
}

struct HttpSocket {
    io: TokioIo<MaybeTlsStream<LimitedTcpStream>>,
    h2: bool,
}
impl Connection for HttpSocket {
    fn connected(&self) -> Connected {
        if self.h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}
impl hyper::rt::Read for HttpSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl hyper::rt::Write for HttpSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Service<http::Uri> for LimitedConnector {
    type Response = HttpSocket;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<HttpSocket>> + Send>>;
    fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            tokio::time::timeout(this.timeout, async {
                let scheme = uri.scheme_str().unwrap_or("http");
                let port = uri
                    .port_u16()
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                if uri.host() != Some(this.host.as_str())
                    || port != this.port
                    || scheme != this.scheme
                {
                    return Err(io::Error::other(
                        "AHTTP request changed the configured origin",
                    ));
                }
                // One pinned address: no parallel Happy Eyeballs attempts outside the limiter.
                let tcp = this.limiter.connect_tcp(this.address).await?;
                tcp.set_nodelay(this.nodelay)?;
                let (stream, h2) = if scheme == "https" {
                    let name = rustls::pki_types::ServerName::try_from(this.host)
                        .map_err(io::Error::other)?;
                    let tls = tokio_rustls::TlsConnector::from(this.tls)
                        .connect(name, tcp)
                        .await?;
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                    (MaybeTlsStream::Rustls(tls), h2)
                } else {
                    (MaybeTlsStream::Plain(tcp), false)
                };
                Ok(HttpSocket {
                    io: TokioIo::new(stream),
                    h2,
                })
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AHTTP connector timed out"))?
        })
    }
}

pub(super) struct BoundedHttpClient {
    client: Client<LimitedConnector, reqwest::Body>,
    timeout: Duration,
}
impl BoundedHttpClient {
    pub(super) fn new(
        url: &reqwest::Url,
        address: SocketAddr,
        config: &AhttpConfig,
        limiter: Arc<ConnectionLimiter>,
    ) -> Result<Self> {
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            // Preserve the existing AHTTP certificate policy; ANet authenticates its peer.
            .with_custom_certificate_verifier(Arc::new(AhttpServerVerifier))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = LimitedConnector {
            host: url.host_str().context("No AHTTP host")?.to_string(),
            port: url.port_or_known_default().context("No AHTTP port")?,
            scheme: url.scheme().to_string(),
            address,
            limiter,
            tls: Arc::new(tls),
            nodelay: config.tcp_nodelay,
            timeout: Duration::from_secs(config.timeout_secs),
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .timer(TokioTimer::new())
            .http2_adaptive_window(config.http2_adaptive_window)
            .http2_max_frame_size(config.http2_max_frame_size)
            .http2_keep_alive_interval(
                config
                    .http2_keep_alive_interval_secs
                    .map(Duration::from_secs),
            )
            .http2_keep_alive_while_idle(config.http2_keep_alive_while_idle);
        if let Some(size) = config.http2_max_header_list_size {
            builder.http2_max_header_list_size(size);
        }
        if let Some(timeout) = config.http2_keep_alive_timeout_secs {
            builder.http2_keep_alive_timeout(Duration::from_secs(timeout));
        }
        Ok(Self {
            client: builder.build(connector),
            timeout: Duration::from_secs(config.timeout_secs),
        })
    }

    async fn execute(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let mut request = request.build()?;
        let body = request
            .body_mut()
            .take()
            .unwrap_or_else(|| Bytes::new().into());
        let mut http_request = http::Request::builder()
            .method(request.method().clone())
            .uri(request.url().as_str())
            .body(body)?;
        *http_request.headers_mut() = request.headers().clone();
        let response = tokio::time::timeout(self.timeout, async {
            let response = self.client.request(http_request).await?;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            Ok::<_, anyhow::Error>(reqwest::Response::from(http::Response::from_parts(
                parts, bytes,
            )))
        })
        .await
        .context("AHTTP request timed out (including connection-limit wait)")??;
        Ok(response)
    }
}

pub(super) async fn send_request(
    request: reqwest::RequestBuilder,
    bounded: &Option<Arc<BoundedHttpClient>>,
) -> Result<reqwest::Response> {
    match bounded {
        Some(client) => client.execute(request).await,
        None => Ok(request.send().await?),
    }
}

// Match reqwest's previous danger_accept_invalid_certs policy: skip certificate
// trust/name validation, but still verify the peer's handshake signature.
#[derive(Debug)]
pub(crate) struct AhttpServerVerifier;
impl rustls::client::danger::ServerCertVerifier for AhttpServerVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionLimitsConfig;
    use http_body_util::Full;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    async fn tls_server(h2: bool) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = rustls_pemfile::certs(
            &mut include_bytes!("../../tests/fixtures/connection-limit-test-cert.pem.fixture")
                .as_slice(),
        )
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(
            &mut include_bytes!("../../tests/fixtures/connection-limit-test-key.pem.fixture")
                .as_slice(),
        )
        .unwrap()
        .unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = if h2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    if h2 {
                        let service = hyper::service::service_fn(|_request| async {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        });
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                        return;
                    }
                    let mut io = BufReader::new(tls);
                    loop {
                        let mut line = String::new();
                        let mut content_length = 0;
                        loop {
                            line.clear();
                            match io.read_line(&mut line).await {
                                Ok(0) | Err(_) => return,
                                _ => {}
                            }
                            if line == "\r\n" {
                                break;
                            }
                            if let Some((key, value)) = line.split_once(':') {
                                if key.eq_ignore_ascii_case("content-length") {
                                    content_length = value.trim().parse().unwrap();
                                }
                            }
                        }
                        let mut body = vec![0; content_length];
                        if io.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        if io
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if io.flush().await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepted, task)
    }

    #[tokio::test]
    async fn tls_pool_enforces_socket_cap_and_reuses_connections() {
        for (cap, h2) in [(1, false), (2, false), (1, true)] {
            let (addr, count, server) = tls_server(h2).await;
            let url =
                reqwest::Url::parse(&format!("https://localhost:{}/traffic", addr.port())).unwrap();
            let limiter = Arc::new(ConnectionLimiter::new(&ConnectionLimitsConfig {
                max_connections: cap,
                min_connect_interval_ms: 0,
            }));
            let config = AhttpConfig {
                pool_max_idle_per_host: cap,
                timeout_secs: 5,
                ..AhttpConfig::default()
            };
            let bounded = Some(Arc::new(
                BoundedHttpClient::new(&url, addr, &config, limiter).unwrap(),
            ));
            let request_client = reqwest::Client::new();
            let mut jobs = tokio::task::JoinSet::new();
            for _ in 0..20 {
                let bounded = bounded.clone();
                let request = request_client
                    .post(url.clone())
                    .header("Connection", "keep-alive")
                    .body("hello");
                jobs.spawn(async move {
                    let response = send_request(request, &bounded).await.unwrap();
                    assert_eq!(response.status(), http::StatusCode::OK);
                    assert_eq!(response.bytes().await.unwrap(), "ok");
                });
            }
            while let Some(result) = jobs.join_next().await {
                result.unwrap();
            }
            assert!(
                count.load(Ordering::SeqCst) <= cap,
                "pool opened more than {cap} sockets"
            );
            drop(bounded);
            server.abort();
        }
    }

    #[tokio::test]
    async fn failed_tls_handshake_releases_socket_slot() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });
        let url =
            reqwest::Url::parse(&format!("https://localhost:{}/traffic", address.port())).unwrap();
        let limiter = Arc::new(ConnectionLimiter::new(&ConnectionLimitsConfig {
            max_connections: 1,
            min_connect_interval_ms: 0,
        }));
        let bounded = Some(Arc::new(
            BoundedHttpClient::new(&url, address, &AhttpConfig::default(), limiter).unwrap(),
        ));
        for _ in 0..2 {
            let attempt = tokio::time::timeout(
                Duration::from_secs(2),
                send_request(reqwest::Client::new().post(url.clone()), &bounded),
            )
            .await;
            assert!(attempt.unwrap().is_err());
        }
        server.abort();
    }
    #[tokio::test]
    async fn cancelled_stalled_tls_attempt_releases_slot() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        });
        let url =
            reqwest::Url::parse(&format!("https://localhost:{}/traffic", address.port())).unwrap();
        let limiter = Arc::new(ConnectionLimiter::new(&ConnectionLimitsConfig {
            max_connections: 1,
            min_connect_interval_ms: 0,
        }));
        let config = AhttpConfig {
            timeout_secs: 1,
            ..AhttpConfig::default()
        };
        let bounded = Some(Arc::new(
            BoundedHttpClient::new(&url, address, &config, limiter.clone()).unwrap(),
        ));
        let job =
            tokio::spawn(
                async move { send_request(reqwest::Client::new().post(url), &bounded).await },
            );
        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .unwrap()
            .unwrap();
        job.abort();
        let _ = job.await;
        let permit = tokio::time::timeout(Duration::from_secs(2), limiter.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        server.abort();
    }
}
