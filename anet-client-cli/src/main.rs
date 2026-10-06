mod tuning;
include!(concat!(env!("OUT_DIR"), "/built.rs"));

use anet_client_cli::tun_factory::DesktopTunFactory;
use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::platform::{create_route_manager, requires_elevated_privileges};
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
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
    if std::env::args_os().len() == 1 && !std::path::Path::new(&opt.cfg).try_exists()? {
        Opt::command().print_help()?;
        println!("\n\nКонфигурация {} не найдена. Укажите файл: anet-client --cfg /путь/к/client.toml", opt.cfg);
        return Ok(());
    }
    if let Some(path) = &opt.reset_tuning_cache {
        tuning::read_cache(path).await?;
        tokio::fs::remove_file(path).await?;
        println!("Tuning cache removed; original profile unchanged.");
        return Ok(());
    }
    if !(opt.diagnose || opt.diagnose_extended)
        && (opt.diagnostics_json.is_some()
            || opt.dpi_helper.is_some()
            || opt.diagnostics_echo_endpoint.is_some())
    {
        anyhow::bail!("Diagnostic options require --diagnose or --diagnose-extended");
    }
    let source = read_to_string(&opt.cfg)
        .await
        .with_context(|| format!("Не удалось прочитать конфигурацию {}. Укажите существующий файл через --cfg", opt.cfg))?;
    let mut config: CoreConfig = toml::from_str(&source)?;
    let has_tuning = opt.tuning_report.is_some() || opt.tuning_connect;
    anyhow::ensure!(
        !(has_tuning && (opt.diagnose || opt.diagnose_extended)),
        "Run diagnosis and tuning separately"
    );
    anyhow::ensure!(
        has_tuning
            || (opt.tuning_candidate.is_none()
                && opt.tuning_output.is_none()
                && opt.tuning_cache.is_none()
                && opt.group.is_empty()),
        "Tuning options require --tuning-report or --tuning-connect"
    );
    let mut verify_tuning = None;
    if has_tuning {
        anyhow::ensure!(
            cfg!(target_os = "linux"),
            "Tuning CLI currently supports Linux only"
        );
        let network = tuning::network_context(&config.main.tun_name).await?;
        let (report, candidate) = if let Some(path) = &opt.tuning_report {
            (tuning::read_report(path).await?, opt.tuning_candidate)
        } else {
            let cache = tuning::read_cache(
                opt.tuning_cache
                    .as_deref()
                    .context("--tuning-connect requires --tuning-report or --tuning-cache")?,
            )
            .await?;
            cache.validate(&source, &opt.group, &network)?;
            (cache.report, Some(cache.candidate))
        };
        tuning::check_report(&source, &report, &opt.group, &network)?;
        println!("{}", tuning::preview(&source, &report, &opt.group)?);
        if let Some(candidate) = candidate {
            anyhow::ensure!(
                opt.tuning_output.is_some() || opt.tuning_connect,
                "Choose --tuning-output or --tuning-connect to apply"
            );
            let adjusted =
                anet_client_core::tuning::apply(&source, &report, &opt.group, candidate)?;
            if opt.tuning_connect {
                tuning::guard_new_vpn().await?;
            }
            if let Some(path) = &opt.tuning_output {
                tuning::distinct_output(&opt.cfg, path).await?;
                write_report(path, &adjusted).await?;
                info!("Tuned copy saved with mode 0600; original profile unchanged");
            }
            if !opt.tuning_connect {
                return Ok(());
            }
            if let Some(path) = &opt.tuning_cache {
                tuning::distinct_output(&opt.cfg, path).await?;
                if let Some(report_path) = &opt.tuning_report {
                    tuning::distinct_output(report_path, path).await?;
                }
                if let Some(output) = &opt.tuning_output {
                    tuning::distinct_output(output, path).await?;
                }
                verify_tuning = Some((report, path.clone()));
            }
            config = toml::from_str(&adjusted)?;
        } else {
            anyhow::ensure!(
                !opt.tuning_connect && opt.tuning_output.is_none() && opt.tuning_cache.is_none(),
                "Choose --tuning-candidate INDEX before applying"
            );
            return Ok(());
        }
    }
    if opt.diagnose || opt.diagnose_extended {
        let cancel = anet_client_core::diagnostics::CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            let _ = signal::ctrl_c().await;
            token.cancel();
        });
        #[cfg(target_os = "linux")]
        let network = tuning::network_context(&config.main.tun_name).await?;
        #[cfg(not(target_os = "linux"))]
        let network = "system_routes".to_string();
        #[cfg(target_os = "linux")]
        let active_session = tuning::active_tunnel().await?;
        #[cfg(not(target_os = "linux"))]
        let active_session = false;
        let mut report = anet_client_core::diagnostics::run(
            &config,
            anet_client_core::diagnostics::DiagnosticOptions {
                extended: opt.diagnose_extended,
                helper_path: opt.dpi_helper,
                echo_endpoint: opt.diagnostics_echo_endpoint,
                network_context: network,
                active_session,
                ..Default::default()
            },
            cancel,
            Arc::new(anet_client_core::diagnostics::SystemEnvironment),
        )
        .await;
        report.profile_id = anet_client_core::tuning::profile_id(&source);
        #[cfg(target_os = "linux")]
        report.recommendations.push("Linux diagnostics follow system routes and DNS; they are not automatically bound to the physical interface. A tuned connection refuses existing active VPN/tunnel interfaces.".into());
        let json = report.to_json()?;
        if let Some(path) = opt.diagnostics_json {
            tuning::distinct_output(&opt.cfg, &path).await?;
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

    #[cfg(target_os = "linux")]
    let _launch_lock = if opt.tuning_connect {
        let lock = tuning::lock_launch()?;
        tuning::guard_new_vpn().await?;
        Some(lock)
    } else {
        None
    };
    let route_mgr = create_route_manager(config.main.manual_routing)?;
    let tun_fac = Box::new(DesktopTunFactory::new(
        config.main.tun_name.clone(),
        !config.main.per_app.is_empty(),
    ));
    let config_tun_name = config.main.tun_name.clone();
    let client = Arc::new(AnetClient::new(config, tun_fac, route_mgr));

    let verification_task = verify_tuning.map(|(report, path)| {
        let client = client.clone();
        let source = source.clone();
        let group = opt.group.clone();
        let tun = config_tun_name.clone();
        tokio::spawn(async move {
            if let Err(error) =
                tuning::verify_connection(client, source, report, group, path, tun).await
            {
                log::warn!("{error}; original profile retained");
            }
        })
    });
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

    if let Some(task) = verification_task {
        task.abort();
    }
    Ok(())
}

#[derive(Debug, Parser)]
#[command(
    version = "1.0.3",
    about = "ANet VPN client with diagnostics and reversible connection tuning"
)]
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
    /// Preview a fresh diagnostic JSON bound to this profile and network.
    #[clap(long)]
    tuning_report: Option<String>,
    /// Original endpoint index from the preview (not its sorted row number).
    #[clap(long)]
    tuning_candidate: Option<usize>,
    /// Group id/name for a grouped profile.
    #[clap(long, default_value = "")]
    group: String,
    /// Write a separate private tuned TOML; never overwrite the source.
    #[clap(long)]
    tuning_output: Option<String>,
    /// Explicitly start VPN with selected tuning (requires root and no other active tunnel).
    #[clap(long)]
    tuning_connect: bool,
    /// Save verified settings here, or reuse them with --tuning-connect without a report.
    #[clap(long)]
    tuning_cache: Option<String>,
    /// Remove a recognized cache without starting a VPN.
    #[clap(long, exclusive = true)]
    reset_tuning_cache: Option<String>,
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
