//! GUI diagnostics use the same validated Linux CLI as the console client.
use anet_client_core::diagnostics::{CancellationToken, DiagnosticReport};
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

struct Cleanup {
    path: PathBuf,
    keep: bool,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
pub struct Session {
    pub source: String,
    pub config_id: String,
    pub report: DiagnosticReport,
    pub groups: Vec<(String, String)>,
    directory: PathBuf,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn cli() -> Result<PathBuf> {
    let sibling = std::env::current_exe()?.with_file_name("anet-client");
    if sibling.is_file() {
        return Ok(sibling);
    }
    let installed = PathBuf::from("/usr/local/sbin/anet-client");
    ensure!(
        installed.is_file(),
        "Не найден anet-client рядом с приложением или в /usr/local/sbin"
    );
    Ok(installed)
}
async fn call(args: &[String], cancel: &CancellationToken) -> Result<String> {
    let mut command = Command::new(cli()?);
    command.args(args).kill_on_drop(true);
    let output = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("Диагностика отменена"),
        result = tokio::time::timeout(Duration::from_secs(210), command.output()) => result.context("Время проверки истекло")??,
    };
    ensure!(output.stdout.len() <= 2_097_152, "Слишком большой отчёт");
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn groups(source: &str) -> Result<Vec<(String, String)>> {
    let config: anet_client_core::config::CoreConfig = toml::from_str(source)?;
    let mut groups = Vec::new();
    for endpoint in config.servers {
        if let Some(name) = endpoint.group_name.filter(|n| !n.trim().is_empty()) {
            let id = endpoint
                .group_id
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| name.clone());
            if !groups.iter().any(|(g, _)| g == &id) {
                groups.push((id, name));
            }
        }
    }
    if groups.is_empty() {
        groups.push((String::new(), "Все серверы".into()));
    }
    Ok(groups)
}
impl Session {
    pub async fn run(
        source: String,
        config_id: String,
        extended: bool,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let groups = groups(&source)?;
        let directory = crate::config::AppSettings::data_dir()
            .join(format!("diagnostics-{}", uuid::Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::create_dir_all(directory.parent().unwrap())?;
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&directory)?;
        let mut cleanup = Cleanup {
            path: directory.clone(),
            keep: false,
        };
        let result = async {
            let config = directory.join("client.toml");
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&config)?;
                file.write_all(source.as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(&config, &source)?;
            let mut args = vec![
                "--cfg".into(),
                config.to_string_lossy().into(),
                if extended {
                    "--diagnose-extended"
                } else {
                    "--diagnose"
                }
                .into(),
                "--diagnostics-json".into(),
                directory.join("report.json").to_string_lossy().into(),
            ];
            if extended {
                let sibling = std::env::current_exe()?.with_file_name("libanet_dpi.so");
                let helper = if sibling.is_file() {
                    sibling
                } else {
                    PathBuf::from("/usr/local/lib/anet/1.0.3/libanet_dpi.so")
                };
                ensure!(
                    helper.is_file(),
                    "Не найдена библиотека расширенной диагностики"
                );
                args.extend(["--dpi-helper".into(), helper.to_string_lossy().into()]);
            }
            let report: DiagnosticReport = serde_json::from_str(&call(&args, &cancel).await?)?;
            ensure!(
                report.profile_id == anet_client_core::tuning::profile_id(&source),
                "Профиль изменился"
            );
            Ok::<_, anyhow::Error>(report)
        }
        .await;
        match result {
            Ok(report) => {
                cleanup.keep = true;
                Ok(Self {
                    source,
                    config_id,
                    report,
                    groups,
                    directory,
                })
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(directory);
                Err(error)
            }
        }
    }
    pub async fn plan(&self, group: &str) -> Result<serde_json::Value> {
        let args = vec![
            "--cfg".into(),
            self.directory.join("client.toml").to_string_lossy().into(),
            "--tuning-report".into(),
            self.directory.join("report.json").to_string_lossy().into(),
            "--group".into(),
            group.into(),
        ];
        // CLI validates freshness, unchanged profile and current network before suggesting settings.
        Ok(serde_json::from_str(
            &call(&args, &CancellationToken::new()).await?,
        )?)
    }
    pub async fn export(&self, group: &str, candidate: usize, target: &Path) -> Result<()> {
        let args = vec![
            "--cfg".into(),
            self.directory.join("client.toml").to_string_lossy().into(),
            "--tuning-report".into(),
            self.directory.join("report.json").to_string_lossy().into(),
            "--group".into(),
            group.into(),
            "--tuning-candidate".into(),
            candidate.to_string(),
            "--tuning-output".into(),
            target.to_string_lossy().into(),
        ];
        call(&args, &CancellationToken::new()).await?;
        Ok(())
    }
}
