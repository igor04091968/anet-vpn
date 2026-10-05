//! Turn bounded observations into reversible settings for authorized endpoints only.
use crate::{
    config::{CoreConfig, TransportMode},
    diagnostics::DiagnosticReport,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub index: usize,
    pub name: String,
    pub dsn: String,
    pub transport: String,
    pub evidence: String,
    pub score: i32,
}
#[derive(Debug, Serialize)]
pub struct ConnectionPlan {
    pub profile_id: String,
    pub network_context: String,
    pub max_connections: usize,
    pub min_connect_interval_ms: u64,
    pub ahttp_concurrency: usize,
    pub candidates: Vec<Candidate>,
    pub notes: Vec<String>,
}
/// Bind observations to endpoints, credentials, policy and routes without exposing them.
pub fn profile_id(config_text: &str) -> String {
    format!("{:x}", Sha256::digest(config_text.as_bytes()))
}
pub fn suggest(
    config_text: &str,
    report: &DiagnosticReport,
    selection: &str,
) -> anyhow::Result<ConnectionPlan> {
    anyhow::ensure!(!report.cancelled, "diagnosis_cancelled");
    anyhow::ensure!(
        report.profile_id == profile_id(config_text),
        "profile_changed_run_diagnosis_again"
    );
    anyhow::ensure!(
        !report.network_context.is_empty(),
        "network_context_missing"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    anyhow::ensure!(
        report.created_at_ms <= now && now - report.created_at_ms <= 30 * 60 * 1000,
        "diagnosis_expired"
    );
    let config: CoreConfig = toml::from_str(config_text)?;
    let grouped = config.servers.iter().any(|s| {
        s.group_name
            .as_deref()
            .is_some_and(|n| !n.trim().is_empty())
    });
    let mut candidates = Vec::new();
    for (index, server) in config.servers.iter().enumerate() {
        if grouped
            && server
                .group_id
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .or(server.group_name.as_deref())
                .unwrap_or("")
                .trim()
                != selection.trim()
        {
            continue;
        }
        let (host, port) = server.host_port()?;
        let mode = server.mode()?;
        let transport = format!("{mode:?}").to_lowercase();
        let rows: Vec<_> = report
            .observations
            .iter()
            .filter(|r| {
                r.endpoint_index == index
                    && r.host == host
                    && r.port == port
                    && r.transport == transport
            })
            .collect();
        let passed = |stage: &str| {
            rows.iter()
                .any(|r| r.stage == stage && r.status == "passed")
        };
        let tls = server.dsn.starts_with("https://") || server.dsn.starts_with("wss://");
        let (score, evidence) = if passed("tcp") && (!tls || passed("native_tls")) {
            (
                100,
                if tls {
                    "TCP/TLS прошли; нужна авторизация ANet"
                } else {
                    "TCP прошёл; нужен обмен ANet"
                },
            )
        } else if mode == TransportMode::Quic && passed("dns") {
            (60, "DNS прошёл; UDP/QUIC/GOST ещё не проверены")
        } else if rows.is_empty() {
            (40, "Не проверен; остаётся резервным вариантом")
        } else {
            (
                10,
                "Проверка неоднозначна или не прошла; остаётся резервным вариантом",
            )
        };
        candidates.push(Candidate {
            index,
            name: server.get_name(),
            dsn: server.dsn.clone(),
            transport,
            evidence: evidence.into(),
            score,
        });
    }
    anyhow::ensure!(!candidates.is_empty(), "no_endpoints_in_selected_group");
    candidates.sort_by_key(|c| (std::cmp::Reverse(c.score), c.index));
    let has_ahttp = candidates.iter().any(|c| c.transport == "ahttp");
    let proposed = if has_ahttp { 2 } else { 1 };
    let limit = if config.connection_limits.max_connections == 0 {
        proposed
    } else {
        proposed.min(config.connection_limits.max_connections)
    };
    if limit < 2 {
        // HTTP/1.1 AHTTP needs separate long-poll and upload sockets.
        candidates.retain(|c| c.transport != "ahttp");
        anyhow::ensure!(
            !candidates.is_empty(),
            "ahttp_requires_two_sockets_choose_other_transport_or_change_limit"
        );
    }
    let parallel_problem = report
        .observations
        .iter()
        .any(|r| r.stage == "parallel_tls_4" && r.status != "passed" && r.status != "skipped");
    let interval = config
        .connection_limits
        .min_connect_interval_ms
        .max(if parallel_problem { 1000 } else { 500 });
    let mut notes = vec![
        "Это предварительный подбор. Рабочий профиль подтверждается обычным ANet-подключением и передачей данных.".into(),
        "Ключи, алгоритм шифрования, адреса серверов и маршруты сохраняются. MTU принимается от авторизованного сервера.".into(),
        "uTLS-отпечатки используются только в диагностике; успешный отпечаток не подменяет рабочий транспорт.".into(),
    ];
    if parallel_problem {
        notes.push("Параллельный TLS-тест не прошёл: уменьшаем число соединений и разнос между попытками; причина ограничения ещё не доказана.".into());
    }
    if has_ahttp && limit < 2 {
        notes.push("Существующий N=1 сохранён. AHTTP исключён из подбора: для одновременного приёма и отправки ему нужны два внешних соединения.".into());
    }
    Ok(ConnectionPlan {
        profile_id: report.profile_id.clone(),
        network_context: report.network_context.clone(),
        max_connections: limit,
        min_connect_interval_ms: interval,
        ahttp_concurrency: config.ahttp.concurrency.clamp(1, 2),
        candidates,
        notes,
    })
}
/// Recompute the plan; never trust settings/DSNs supplied by a UI or imported JSON.
pub fn apply(
    config_text: &str,
    report: &DiagnosticReport,
    selection: &str,
    index: usize,
) -> anyhow::Result<String> {
    let plan = suggest(config_text, report, selection)?;
    anyhow::ensure!(
        plan.candidates.iter().any(|c| c.index == index),
        "endpoint_outside_selected_group"
    );
    let mut value: toml::Value = toml::from_str(config_text)?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid_config"))?;
    let mut limits = table
        .remove("connection_limits")
        .unwrap_or_else(|| toml::Value::Table(Default::default()));
    let limits_table = limits
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid_connection_limits"))?;
    limits_table.insert(
        "max_connections".into(),
        (plan.max_connections as i64).into(),
    );
    limits_table.insert(
        "min_connect_interval_ms".into(),
        (plan.min_connect_interval_ms as i64).into(),
    );
    table.insert("connection_limits".into(), limits);
    let servers = table
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing_servers"))?;
    let mut order: Vec<_> = plan.candidates.iter().map(|c| c.index).collect();
    order.retain(|i| *i != index);
    order.insert(0, index);
    let mut selected = Vec::new();
    for i in order {
        let mut server = servers[i].clone();
        // The source group is already scoped; keep the tested order at JNI startup.
        if let Some(t) = server.as_table_mut() {
            for key in ["group_id", "group_name", "weight", "weigth"] {
                t.remove(key);
            }
        }
        selected.push(server);
    }
    table.insert("servers".into(), toml::Value::Array(selected));
    let ahttp = table
        .entry("ahttp")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid_ahttp"))?;
    ahttp.insert("concurrency".into(), (plan.ahttp_concurrency as i64).into());
    let result = toml::to_string_pretty(&value)?;
    let mut validated: CoreConfig = toml::from_str(&result)?;
    validated.sanitize()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::Observation;
    fn fixture() -> (String, DiagnosticReport) {
        let text="[keys]\nprivate_key='unchanged-private'\nserver_pub_key='unchanged-public'\n[crypto]\nalgorithm='kuznyechik-mgm'\n[main]\ntun_name='anet'\nroute_for=['10.0.0.0/8']\n[[servers]]\ndsn='quic://first.example:443'\ngroup_name='pool'\ngroup_id='p'\n[[servers]]\ndsn='wss://second.example:443/path'\ngroup_name='pool'\ngroup_id='p'\n[[servers]]\ndsn='ssh://other.example:22'\ngroup_name='other'\ngroup_id='q'\n".to_string();
        let report = DiagnosticReport {
            schema_version: 2,
            profile_id: profile_id(&text),
            created_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            cancelled: false,
            extended: false,
            network_context: "android:test:wifi".into(),
            max_connections: 0,
            min_connect_interval_ms: 0,
            observations: vec![
                Observation {
                    endpoint_index: 1,
                    host: "second.example".into(),
                    port: 443,
                    transport: "websocket".into(),
                    stage: "tcp".into(),
                    status: "passed".into(),
                    code: "connected".into(),
                    elapsed_ms: 1,
                    details: None,
                },
                Observation {
                    endpoint_index: 1,
                    host: "second.example".into(),
                    port: 443,
                    transport: "websocket".into(),
                    stage: "native_tls".into(),
                    status: "passed".into(),
                    code: "completed".into(),
                    elapsed_ms: 2,
                    details: None,
                },
            ],
            recommendations: vec![],
        };
        (text, report)
    }
    #[test]
    fn ranks_native_tls_and_keeps_unproven_fallback() {
        let (t, r) = fixture();
        let p = suggest(&t, &r, "p").unwrap();
        assert_eq!(
            p.candidates.iter().map(|c| c.index).collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert_eq!(p.max_connections, 1);
    }
    #[test]
    fn preserves_keys_crypto_routes_and_scopes_group() {
        let (t, r) = fixture();
        let out = apply(&t, &r, "p", 1).unwrap();
        let a: toml::Value = toml::from_str(&t).unwrap();
        let b: toml::Value = toml::from_str(&out).unwrap();
        for key in ["keys", "crypto", "main"] {
            assert_eq!(a[key], b[key]);
        }
        assert_eq!(b["servers"].as_array().unwrap().len(), 2);
        assert_eq!(
            b["servers"][0]["dsn"].as_str(),
            Some("wss://second.example:443/path")
        );
    }
    #[test]
    fn rejects_stale_cancelled_and_cross_group() {
        let (t, mut r) = fixture();
        assert!(apply(&t, &r, "p", 2).is_err());
        assert!(suggest(&(t.clone() + "\n"), &r, "p").is_err());
        r.cancelled = true;
        assert!(suggest(&t, &r, "p").is_err());
    }
    #[test]
    fn diagnostic_fingerprint_does_not_rank_transport() {
        let (t, mut r) = fixture();
        r.observations[1].stage = "utls".into();
        let p = suggest(&t, &r, "p").unwrap();
        assert_eq!(p.candidates[0].index, 0);
    }
    #[test]
    fn keeps_stricter_existing_limits() {
        let (t, mut r) = fixture();
        let t = t + "[connection_limits]\nmax_connections=1\nmin_connect_interval_ms=2000\n";
        r.profile_id = profile_id(&t);
        let p = suggest(&t, &r, "p").unwrap();
        assert_eq!(p.max_connections, 1);
        assert_eq!(p.min_connect_interval_ms, 2000);
    }
    #[test]
    fn does_not_trust_forged_observation_target() {
        let (t, mut r) = fixture();
        r.observations[0].host = "fake.example".into();
        r.observations[1].host = "fake.example".into();
        assert_eq!(
            suggest(&t, &r, "p")
                .unwrap()
                .candidates
                .iter()
                .find(|c| c.index == 1)
                .unwrap()
                .score,
            40
        );
    }
    #[test]
    fn preserves_endpoint_crypto_and_excludes_ahttp_with_one_socket() {
        let (t, mut r) = fixture();
        let t =
            t.replace(
                "wss://second.example:443/path",
                "https://second.example:443/path",
            )
            .replace(
                "group_id='p'",
                "group_id='p'\ncrypto_algorithm='chacha20-poly1305'",
            ) + "[connection_limits]\nmax_connections=1\n";
        r.profile_id = profile_id(&t);
        let p = suggest(&t, &r, "p").unwrap();
        assert!(p.candidates.iter().all(|c| c.transport != "ahttp"));
        let applied: toml::Value = toml::from_str(&apply(&t, &r, "p", 0).unwrap()).unwrap();
        assert_eq!(
            applied["servers"][0]["crypto_algorithm"].as_str(),
            Some("chacha20-poly1305")
        );
    }
    #[test]
    fn rejects_expired_or_future_report() {
        let (t, mut r) = fixture();
        r.created_at_ms = 1;
        assert!(suggest(&t, &r, "p").is_err());
        r.created_at_ms = u64::MAX;
        assert!(suggest(&t, &r, "p").is_err());
    }
}
