//! Linux tuning uses system routes; it never changes networking during preview/export.
use anet_client_core::{client::AnetClient, diagnostics::DiagnosticReport, tuning};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};

async fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("network_state_timeout")??;
    ensure!(
        output.status.success() && output.stdout.len() <= 262144,
        "network_state_unavailable"
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn overlay(row: &Value) -> bool {
    let name = row["ifname"].as_str().unwrap_or_default();
    let kind = row["linkinfo"]["info_kind"].as_str().unwrap_or_default();
    matches!(
        kind,
        "tun" | "wireguard" | "gre" | "gretap" | "ipip" | "sit" | "vxlan"
    ) || ["tun", "tap", "wg", "anet", "ppp"]
        .iter()
        .any(|p| name.starts_with(p))
        || Path::new("/sys/class/net")
            .join(name)
            .join("tun_flags")
            .exists()
}
fn is_up(row: &Value) -> bool {
    row["flags"]
        .as_array()
        .is_some_and(|flags| flags.iter().any(|f| f == "UP"))
}
fn fingerprint(addresses: &[Value], routes: &[Value], extra: &str, exclude: &str) -> String {
    let mut links: Vec<_> = addresses
        .iter()
        .filter(|a| {
            a["ifname"].as_str() != Some(exclude)
                && is_up(a)
                && (overlay(a) || routes.iter().any(|r| r["dev"] == a["ifname"]))
        })
        .map(|a| {
            let mut ips: Vec<_> = a["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|ip| {
                    format!(
                        "{}/{}",
                        ip["local"].as_str().unwrap_or_default(),
                        ip["prefixlen"]
                    )
                })
                .collect();
            ips.sort();
            json!({"name":a["ifname"],"mac":a["address"],"overlay":overlay(a),"ips":ips})
        })
        .collect();
    links.sort_by_key(|a| a["name"].as_str().unwrap_or_default().to_owned());
    let mut defaults: Vec<_> = routes
        .iter()
        .filter(|r| {
            addresses
                .iter()
                .any(|a| a["ifname"] == r["dev"] && !overlay(a))
        })
        .map(|r| json!({"dev":r["dev"],"gateway":r["gateway"],"metric":r["metric"],"dst":r["dst"]}))
        .collect();
    defaults.sort_by_key(Value::to_string);
    format!(
        "linux-routes:{}",
        tuning::profile_id(&json!({"links":links,"default":defaults,"session":extra}).to_string())
    )
}
pub async fn network_context(exclude_tun: &str) -> Result<String> {
    let addresses: Vec<Value> =
        serde_json::from_str(&command("ip", &["-j", "-d", "address", "show"]).await?)?;
    let mut routes: Vec<Value> =
        serde_json::from_str(&command("ip", &["-j", "route", "show", "default"]).await?)?;
    routes.extend(serde_json::from_str::<Vec<Value>>(
        &command("ip", &["-j", "-6", "route", "show", "default"]).await?,
    )?);
    let nm = command(
        "nmcli",
        &["-t", "-f", "UUID,DEVICE", "connection", "show", "--active"],
    )
    .await
    .unwrap_or_default();
    let mut profiles: Vec<_> = nm
        .lines()
        .filter(|l| {
            let device = l.rsplit(':').next().unwrap_or_default();
            device != exclude_tun
                && addresses.iter().any(|a| {
                    a["ifname"].as_str() == Some(device)
                        && !overlay(a)
                        && routes.iter().any(|r| r["dev"] == a["ifname"])
                })
        })
        .collect();
    profiles.sort();
    let boot = tokio::fs::read_to_string("/proc/sys/kernel/random/boot_id").await?;
    let ns = tokio::fs::read_link("/proc/self/ns/net").await?;
    Ok(fingerprint(
        &addresses,
        &routes,
        &format!("{}|{}|{}", boot.trim(), ns.display(), profiles.join(";")),
        exclude_tun,
    ))
}
pub async fn guard_new_vpn() -> Result<()> {
    let addresses: Vec<Value> =
        serde_json::from_str(&command("ip", &["-j", "-d", "address", "show"]).await?)?;
    ensure!(
        !addresses.iter().any(|a| overlay(a) && is_up(a)),
        "An active VPN/tunnel exists. Preview/export are allowed; tuned connection requires stopping it manually. No existing VPN was changed."
    );
    Ok(())
}
#[cfg(target_os = "linux")]
fn acquire_lock(path: &Path) -> Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Another tuned VPN launch is running; existing connection was not changed"
    );
    Ok(file)
}
#[cfg(target_os = "linux")]
pub fn lock_launch() -> Result<std::fs::File> {
    acquire_lock(Path::new("/run/anet-client-tuning.lock"))
}

pub fn check_report(
    source: &str,
    report: &DiagnosticReport,
    selection: &str,
    network: &str,
) -> Result<()> {
    ensure!(
        report.network_context == network && network.starts_with("linux-routes:"),
        "network_changed_run_diagnosis_again"
    );
    tuning::suggest(source, report, selection)?;
    Ok(())
}
pub async fn read_report(path: &str) -> Result<DiagnosticReport> {
    Ok(serde_json::from_str(&read_private(path).await?)?)
}
async fn read_private(path: &str) -> Result<String> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1048576,
        "invalid_or_oversized_tuning_file"
    );
    Ok(tokio::fs::read_to_string(path).await?)
}
pub fn preview(source: &str, report: &DiagnosticReport, group: &str) -> Result<String> {
    let mut result = serde_json::to_value(tuning::suggest(source, report, group)?)?;
    // DSNs can include credentials/query tokens; preview only needs index/name/evidence.
    for candidate in result["candidates"].as_array_mut().unwrap() {
        candidate.as_object_mut().unwrap().remove("dsn");
    }
    Ok(serde_json::to_string_pretty(&result)?)
}
pub async fn distinct_output(source: &str, output: &str) -> Result<()> {
    let original = tokio::fs::canonicalize(source).await?;
    let output_path = Path::new(output);
    let candidate = if tokio::fs::try_exists(output_path).await? {
        tokio::fs::canonicalize(output_path).await?
    } else {
        let parent = output_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        tokio::fs::canonicalize(parent)
            .await?
            .join(output_path.file_name().context("invalid_output_name")?)
    };
    ensure!(
        original != candidate,
        "refusing_to_overwrite_original_profile"
    );
    Ok(())
}
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Cache {
    pub schema_version: u32,
    pub report: DiagnosticReport,
    pub group: String,
    pub candidate: usize,
    pub verified_at_ms: u64,
    pub verification: Value,
}
impl Cache {
    pub fn validate(&self, source: &str, group: &str, network: &str) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.group == group,
            "invalid_tuning_cache"
        );
        ensure!(
            self.verified_at_ms <= now_ms() && now_ms() - self.verified_at_ms <= 1800000,
            "expired_tuning_cache"
        );
        ensure!(
            self.verification["authenticated"] == true
                && self.verification["data_verified"] == true,
            "unverified_tuning_cache"
        );
        ensure!(
            self.verification["received_bytes"].as_u64().unwrap_or(0) >= 65536
                && self.verification["sent_bytes"].as_u64().unwrap_or(0) > 0,
            "insufficient_cached_data_exchange"
        );
        check_report(source, &self.report, group, network)?;
        let plan = tuning::suggest(source, &self.report, group)?;
        ensure!(
            plan.candidates
                .iter()
                .any(|c| c.index == self.candidate && self.verification["dsn"] == c.dsn),
            "cache_endpoint_mismatch"
        );
        Ok(())
    }
}
pub async fn read_cache(path: &str) -> Result<Cache> {
    let cache: Cache = serde_json::from_str(&read_private(path).await?)?;
    ensure!(cache.schema_version == 1, "unknown_cache_schema");
    Ok(cache)
}
pub async fn verify_connection(
    client: Arc<AnetClient>,
    source: String,
    report: DiagnosticReport,
    group: String,
    path: String,
    tun: String,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("No verified data exchange within 120 seconds; tuning cache not saved");
        }
        if network_context(&tun).await? != report.network_context {
            anyhow::bail!("Network changed; tuning cache not saved");
        }
        let verification = client.connection_verification();
        if verification["authenticated"] == true && verification["data_verified"] == true {
            let plan = tuning::suggest(&source, &report, &group)?;
            let candidate = plan
                .candidates
                .iter()
                .find(|c| verification["dsn"] == c.dsn)
                .context("unexpected_authenticated_endpoint")?
                .index;
            let cache = Cache {
                schema_version: 1,
                report,
                group,
                candidate,
                verified_at_ms: now_ms(),
                verification,
            };
            cache.validate(&source, &cache.group, &cache.report.network_context)?;
            super::write_report(&path, &serde_json::to_string_pretty(&cache)?).await?;
            log::info!(
                "Tuning confirmed and saved: transport={}, crypto={}, MTU={}, received >=64 KiB",
                cache.verification["transport"],
                cache.verification["crypto"],
                cache.verification["mtu"]
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_fingerprint_ignores_new_own_tun_but_tracks_other_vpn_and_ip() {
        let physical = json!({"ifname":"eth0","flags":["UP"],"address":"01","addr_info":[{"local":"192.0.2.1","prefixlen":24}]});
        let own = json!({"ifname":"anet-test","flags":["UP"],"addr_info":[],"linkinfo":{"info_kind":"tun"}});
        let route = json!({"dev":"eth0","gateway":"192.0.2.254","dst":"default","metric":100});
        let first = fingerprint(&[physical.clone()], &[route.clone()], "boot", "anet-test");
        assert_eq!(
            first,
            fingerprint(
                &[physical.clone(), own.clone()],
                &[route.clone()],
                "boot",
                "anet-test"
            )
        );
        assert_ne!(
            first,
            fingerprint(
                &[physical.clone(), own],
                &[route.clone()],
                "boot",
                "another-tun"
            )
        );
        let mut changed = physical;
        changed["addr_info"][0]["local"] = "192.0.2.2".into();
        assert_ne!(
            first,
            fingerprint(&[changed], &[route], "boot", "anet-test")
        );
    }
    #[tokio::test]
    async fn refuses_original_output_and_symlink_alias() {
        let dir = std::env::temp_dir().join(format!(
            "anet-tuning-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        tokio::fs::create_dir(&dir).await.unwrap();
        let source = dir.join("original.toml");
        tokio::fs::write(&source, "original").await.unwrap();
        assert!(
            distinct_output(source.to_str().unwrap(), source.to_str().unwrap())
                .await
                .is_err()
        );
        #[cfg(unix)]
        {
            let alias = dir.join("alias.toml");
            std::os::unix::fs::symlink(&source, &alias).unwrap();
            assert!(
                distinct_output(source.to_str().unwrap(), alias.to_str().unwrap())
                    .await
                    .is_err()
            );
        }
        assert!(
            distinct_output(
                source.to_str().unwrap(),
                dir.join("output.toml").to_str().unwrap()
            )
            .await
            .is_ok()
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    fn fixture() -> (String, Cache) {
        let source="[keys]\nprivate_key='test-private'\nserver_pub_key='test-public'\n[[servers]]\ndsn='quic://localhost:443'\n".to_string();
        let report: DiagnosticReport=serde_json::from_value(json!({"schema_version":2,"profile_id":tuning::profile_id(&source),"created_at_ms":now_ms(),"cancelled":false,"extended":false,"network_context":"linux-routes:test","max_connections":1,"min_connect_interval_ms":0,"observations":[],"recommendations":[]})).unwrap();
        let cache = Cache {
            schema_version: 1,
            report,
            group: String::new(),
            candidate: 0,
            verified_at_ms: now_ms(),
            verification: json!({"authenticated":true,"data_verified":true,"received_bytes":65536,"sent_bytes":100,"dsn":"quic://localhost:443"}),
        };
        (source, cache)
    }
    #[test]
    fn cache_requires_network_profile_verified_exchange_and_endpoint() {
        let (source, mut c) = fixture();
        assert!(c.validate(&source, "", "linux-routes:test").is_ok());
        assert!(c.validate(&source, "", "linux-routes:changed").is_err());
        assert!(
            c.validate(&(source.clone() + "#changed"), "", "linux-routes:test")
                .is_err()
        );
        c.verification["data_verified"] = false.into();
        assert!(c.validate(&source, "", "linux-routes:test").is_err());
        c.verification["data_verified"] = true.into();
        c.verification["dsn"] = "quic://forged:443".into();
        assert!(c.validate(&source, "", "linux-routes:test").is_err());
    }
    #[test]
    fn cache_expires_and_preview_omits_dsn() {
        let (source, mut c) = fixture();
        let preview: Value =
            serde_json::from_str(&super::preview(&source, &c.report, "").unwrap()).unwrap();
        assert!(preview["candidates"][0].get("dsn").is_none());
        c.verified_at_ms = now_ms() - 1800001;
        assert!(c.validate(&source, "", "linux-routes:test").is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lock_tests {
    use super::*;
    #[test]
    fn launch_lock_is_exclusive_and_released_on_drop() {
        let p = std::env::temp_dir().join(format!(
            "anet-launch-lock-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let first = acquire_lock(&p).unwrap();
        assert!(acquire_lock(&p).is_err());
        drop(first);
        drop(acquire_lock(&p).unwrap());
        std::fs::remove_file(p).unwrap();
    }
}
