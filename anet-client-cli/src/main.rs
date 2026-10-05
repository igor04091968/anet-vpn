include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::platform::{create_route_manager, requires_elevated_privileges};
use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::process::exit;
use std::sync::Arc;
use tokio::fs::read_to_string;
use tokio::signal;

fn generate_ascii_art(tag: &str, build_type: &str, commit_hash: &str, build_time: &str) -> String {
    format!(
        r#"
                    ╔═══════════════════════════════════════════════════════════════╗
                    ║                                                               ║
                    ║                 █████╗ ███╗   ██╗███████╗████████╗            ║
                    ║                 ██╔══██╗████╗  ██║██╔════╝╚══██╔══╝           ║
                    ║                 ███████║██╔██╗ ██║█████╗     ██║              ║
                    ║                 ██╔══██║██║╚██╗██║██╔══╝     ██║              ║
                    ║                 ██║  ██║██║ ╚████║███████╗   ██║              ║
                    ║                 ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝              ║
                    ╠═══════════════════════════════════════════════════════════════╣
                    ║                                                               ║
                    ║                   Version:     {:<16}               ║
                    ║                   Build Type:  {:<16}               ║
                    ║                   Commit Hash: {:<16}               ║
                    ║                   Build Time:  {:<19}            ║
                    ║                                                               ║
                    ╚═══════════════════════════════════════════════════════════════╝
"#,
        tag, build_type, commit_hash, build_time
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = Opt::parse();
    let config: CoreConfig = toml::from_str(&read_to_string(&opt.cfg).await?)?;
    if !(opt.diagnose || opt.diagnose_extended)
        && (opt.diagnostics_json.is_some()
            || opt.dpi_helper.is_some()
            || opt.diagnostics_echo_endpoint.is_some())
    {
        anyhow::bail!("Diagnostic options require --diagnose or --diagnose-extended");
    }
    if opt.diagnose || opt.diagnose_extended {
        let cancel = anet_client_core::diagnostics::CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            token.cancel();
        });
        let report = anet_client_core::diagnostics::run(
            &config,
            anet_client_core::diagnostics::DiagnosticOptions {
                extended: opt.diagnose_extended,
                helper_path: opt.dpi_helper,
                echo_endpoint: opt.diagnostics_echo_endpoint,
                network_context: "system_routes".into(),
                ..Default::default()
            },
            cancel,
            Arc::new(anet_client_core::diagnostics::SystemEnvironment),
        )
        .await;
        let json = report.to_json()?;
        if let Some(path) = opt.diagnostics_json {
            write_report(&path, &json).await?;
        }
        println!("{json}");
        return Ok(());
    }

    // Проверка прав
    #[cfg(unix)]
    if unsafe { libc::geteuid() != 0 } && requires_elevated_privileges() {
        error!("ALCO-NET требует прав root (sudo).");
        exit(1);
    }

    // Вывод арта с тегом
    println!(
        "{}",
        generate_ascii_art(GIT_TAG, BUILD_TYPE, COMMIT_HASH, BUILD_TIME)
    );

    let route_mgr = create_route_manager(config.main.manual_routing)?;
    let tun_fac = Box::new(DesktopTunFactory::new(
        config.main.tun_name.clone(),
        !config.main.per_app.is_empty(),
    ));
    let client = Arc::new(AnetClient::new(config, tun_fac, route_mgr));

    let client_for_task = client.clone();
    let mut run_task = tokio::spawn(async move {
        if let Err(e) = client_for_task.start().await {
            error!("VPN connection loop exited with error: {}", e);
        }
    });

    info!("VPN Running. Press Ctrl+C to stop.");

    tokio::select! {
        res = &mut run_task => {
            // Цикл подключения завершился сам по себе (например, ошибка
            // конфигурации ещё до первого коннекта) — ждать Ctrl+C уже нечего.
            if let Err(e) = res {
                error!("VPN task panicked: {}", e);
            }
            exit(1);
        }
        ctrlc_result = signal::ctrl_c() => {
            ctrlc_result?;
            info!("Ctrl+C received. Stopping VPN and restoring system state...");
            client.stop().await?;
            let _ = run_task.await;
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./client.toml")]
    cfg: String,
    #[clap(long)]
    diagnose: bool,
    #[clap(long)]
    diagnose_extended: bool,
    #[clap(long)]
    diagnostics_json: Option<String>,
    #[clap(long)]
    dpi_helper: Option<String>,
    #[clap(long)]
    diagnostics_echo_endpoint: Option<String>,
}

/// Write a private report atomically; never leave a truncated destination on interruption.
async fn write_report(path: &str, json: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let path = std::path::Path::new(path);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".anet-report-{}-{stamp}.tmp", std::process::id()));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = async {
        let mut file = options.open(&temporary).await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
}
