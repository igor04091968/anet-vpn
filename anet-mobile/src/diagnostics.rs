use super::*;
use anet_client_core::diagnostics::{
    self, CancellationToken, DiagnosticOptions, SocketEnvironment,
};
use jni::sys::{jlong, jstring};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
#[derive(Default)]
struct Job {
    generation: u64,
    cancel: Option<CancellationToken>,
    report: String,
    running: bool,
}
static JOB: Mutex<Job> = Mutex::new(Job {
    generation: 0,
    cancel: None,
    report: String::new(),
    running: false,
});
pub(super) fn cancel_current() {
    if let Some(cancel) = &JOB.lock().unwrap().cancel {
        cancel.cancel();
    }
}
pub(super) async fn cancel_and_wait() {
    {
        let job = JOB.lock().unwrap();
        if let Some(cancel) = &job.cancel {
            cancel.cancel();
        }
    }
    while JOB.lock().unwrap().running {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}
struct AndroidEnvironment {
    vm: Arc<JavaVM>,
    activity: GlobalRef,
}
#[async_trait::async_trait]
impl SocketEnvironment for AndroidEnvironment {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let vm = self.vm.clone();
        let activity = self.activity.clone();
        let host = host.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut env = vm.attach_current_thread().map_err(io::Error::other)?;
            let string = env.new_string(host).map_err(io::Error::other)?;
            let value = env
                .call_method(
                    activity.as_obj(),
                    "resolveDiagnosticHost",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(string.as_ref())],
                )
                .map_err(io::Error::other)?
                .l()
                .map_err(io::Error::other)?;
            let result: String = env
                .get_string(&JString::from(value))
                .map_err(io::Error::other)?
                .into();
            Ok(result
                .lines()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .take(8)
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        })
        .await
        .map_err(io::Error::other)?
    }
    fn prepare(&self, fd: i32) -> io::Result<()> {
        let mut env = self.vm.attach_current_thread().map_err(io::Error::other)?;
        let value = env
            .call_method(
                self.activity.as_obj(),
                "prepareDiagnosticSocket",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .map_err(io::Error::other)?
            .z()
            .map_err(io::Error::other)?;
        if value {
            Ok(())
        } else {
            Err(io::Error::other("physical network preparation failed"))
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_startDiagnostics(
    mut env: JNIEnv,
    activity: JObject,
    config: JString,
    options: JString,
) -> jlong {
    let config: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let source_profile_id = anet_client_core::tuning::profile_id(&config);
    let config: CoreConfig = match toml::from_str(&config) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let options: String = match env.get_string(&options) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let mut options: DiagnosticOptions = match serde_json::from_str(&options) {
        Ok(o) => o,
        Err(_) => return -1,
    };
    let Ok(vm) = env.get_java_vm() else { return -1 };
    let Ok(activity) = env.new_global_ref(activity) else {
        return -1;
    };
    let Ok(_lifecycle) = CLIENT_LIFECYCLE.try_lock() else {
        return -2;
    };
    let client = CLIENT.lock().unwrap().clone();
    // Include connecting/reconnecting clients; their socket budget is also shared.
    options.active_session = client.is_some();
    let cancel = CancellationToken::new();
    let generation = {
        let mut job = JOB.lock().unwrap();
        if job.running {
            return -2;
        }
        job.generation += 1;
        job.cancel = Some(cancel.clone());
        job.report.clear();
        job.running = true;
        job.generation
    };
    let mut rt = RUNTIME.lock().unwrap();
    if rt.is_none() {
        *rt = Runtime::new().ok();
    }
    let Some(rt) = rt.as_ref() else {
        JOB.lock().unwrap().running = false;
        return -1;
    };
    rt.spawn(async move {
        let environment = Arc::new(AndroidEnvironment {
            vm: Arc::new(vm),
            activity,
        });
        let mut report = if let Some(client) = client {
            client.diagnose(options, cancel, environment).await
        } else {
            diagnostics::run(&config, options, cancel, environment).await
        };
        report.profile_id = source_profile_id;
        let mut job = JOB.lock().unwrap();
        if job.generation == generation {
            job.report = report.to_json().unwrap_or_else(|_| "{}".into());
            job.running = false;
            job.cancel = None;
        }
    });
    generation as jlong
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_cancelDiagnostics(_: JNIEnv, _: JObject) {
    if let Some(cancel) = &JOB.lock().unwrap().cancel {
        cancel.cancel();
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getDiagnosticsReport(
    env: JNIEnv,
    _: JObject,
) -> jstring {
    let job = JOB.lock().unwrap();
    let value = if job.running {
        "RUNNING"
    } else {
        job.report.as_str()
    };
    env.new_string(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Preview and apply use the immutable report/config binding; no network or client mutation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_planDiagnosticSettings(
    mut env: JNIEnv,
    _: JObject,
    config: JString,
    report: JString,
    selection: JString,
) -> jstring {
    let result = (|| -> anyhow::Result<String> {
        let config: String = env.get_string(&config)?.into();
        let report: String = env.get_string(&report)?.into();
        let selection: String = env.get_string(&selection)?.into();
        let report = serde_json::from_str(&report)?;
        Ok(serde_json::to_string(&anet_client_core::tuning::suggest(
            &config, &report, &selection,
        )?)?)
    })();
    let value = result.unwrap_or_else(|_| "{\"error\":\"Повторите диагностику выбранного профиля/группы; отменённый или устаревший отчёт применять нельзя\"}".into());
    env.new_string(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_applyDiagnosticSettings(
    mut env: JNIEnv,
    _: JObject,
    config: JString,
    report: JString,
    selection: JString,
    candidate: jni::sys::jint,
) -> jstring {
    let result = (|| -> anyhow::Result<String> {
        anyhow::ensure!(candidate >= 0, "invalid_candidate");
        let config: String = env.get_string(&config)?.into();
        let report: String = env.get_string(&report)?.into();
        let selection: String = env.get_string(&selection)?.into();
        let report = serde_json::from_str(&report)?;
        let adjusted =
            anet_client_core::tuning::apply(&config, &report, &selection, candidate as usize)?;
        Ok(serde_json::json!({"config":adjusted}).to_string())
    })();
    let value = result.unwrap_or_else(|_| {
        "{\"error\":\"Не удалось применить подбор; исходный профиль сохранён\"}".into()
    });
    env.new_string(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_alco_anet_MainActivity_getConnectionVerification(
    env: JNIEnv,
    _: JObject,
) -> jstring {
    let client = CLIENT.lock().unwrap().clone();
    let value = client
        .map(|c| c.connection_verification())
        .unwrap_or_else(|| serde_json::json!({"authenticated":false,"data_verified":false}));
    env.new_string(value.to_string())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
