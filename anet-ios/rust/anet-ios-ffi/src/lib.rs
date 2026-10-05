use anet_client_core::client::AnetClient;
use anet_client_core::config::CoreConfig;
use anet_client_core::events::{AnetEvent, ClientState, EventHandler};
use anet_client_core::traits::{RouteManager, TunFactory};
use anet_common::protocol::AuthResponse;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CString, c_char, c_void};
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_PACKET_BYTES: usize = 65_535;
const SETTINGS_TIMEOUT: Duration = Duration::from_secs(30);

pub const EVENT_DISCONNECTED: i32 = 0;
pub const EVENT_CONNECTING: i32 = 1;
pub const EVENT_CONNECTED: i32 = 2;
pub const EVENT_RECONNECTING: i32 = 3;
pub const EVENT_STOPPING: i32 = 4;
pub const EVENT_STOPPED: i32 = 5;
pub const EVENT_FAILED: i32 = 6;
pub const EVENT_STATUS: i32 = 100;
pub const EVENT_WARNING: i32 = 101;
pub const EVENT_ERROR: i32 = 102;
pub const EVENT_ACCOUNT: i32 = 103;
pub const EVENT_APPLY_SETTINGS: i32 = 1000;

type EventFn = unsafe extern "C" fn(*mut c_void, i32, *const c_char);
type PacketFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnetIosCallbacks {
    context: *mut c_void,
    on_event: Option<EventFn>,
    on_packet: Option<PacketFn>,
}

struct CallbackContext {
    context: usize,
    on_event: Option<EventFn>,
    on_packet: Option<PacketFn>,
}

// The host must keep `context` alive until `anet_ios_client_free` returns.
// Swift's provider owns the context and copies callback buffers synchronously.
unsafe impl Send for CallbackContext {}
unsafe impl Sync for CallbackContext {}

impl CallbackContext {
    fn emit_event(&self, code: i32, payload: &str) {
        let Some(callback) = self.on_event else {
            return;
        };
        let safe_payload = payload.replace('\0', "�");
        if let Ok(payload) = CString::new(safe_payload) {
            // SAFETY: the host guarantees callback context validity for the handle lifetime;
            // the C string remains alive for the duration of this callback.
            unsafe { callback(self.context as *mut c_void, code, payload.as_ptr()) };
        }
    }

    fn emit_packet(&self, packet: &[u8]) {
        if let Some(callback) = self.on_packet {
            // SAFETY: packet data remains alive for the duration of this callback. The host
            // must copy it before returning.
            unsafe { callback(self.context as *mut c_void, packet.as_ptr(), packet.len()) };
        }
    }
}

struct IosEventHandler(RwLock<Option<Arc<CallbackContext>>>);

struct IosEventHandlerProxy(Arc<IosEventHandler>);

static IOS_EVENT_HANDLER: OnceLock<Arc<IosEventHandler>> = OnceLock::new();

fn install_event_handler(callbacks: Arc<CallbackContext>) {
    let handler = IOS_EVENT_HANDLER.get_or_init(|| {
        let handler = Arc::new(IosEventHandler(RwLock::new(None)));
        anet_client_core::events::set_handler(Box::new(IosEventHandlerProxy(handler.clone())));
        handler
    });
    *handler.0.write().unwrap() = Some(callbacks);
}

fn clear_event_handler(context: usize) {
    if let Some(handler) = IOS_EVENT_HANDLER.get() {
        let mut current = handler.0.write().unwrap();
        if current
            .as_ref()
            .is_some_and(|callback| callback.context == context)
        {
            *current = None;
        }
    }
}

impl EventHandler for IosEventHandler {
    fn on_event(&self, event: AnetEvent) {
        let Some(callbacks) = self.0.read().unwrap().clone() else {
            return;
        };
        match event {
            AnetEvent::ClientStateChanged { state, message, .. } => {
                let code = match state {
                    ClientState::Disconnected => EVENT_DISCONNECTED,
                    ClientState::Connecting => EVENT_CONNECTING,
                    ClientState::Connected => EVENT_CONNECTED,
                    ClientState::Reconnecting => EVENT_RECONNECTING,
                    ClientState::Stopping => EVENT_STOPPING,
                    ClientState::Stopped => EVENT_STOPPED,
                    ClientState::Failed => EVENT_FAILED,
                };
                callbacks.emit_event(code, &message);
            }
            AnetEvent::Status(message) => callbacks.emit_event(EVENT_STATUS, &message),
            AnetEvent::Warn(message) => callbacks.emit_event(EVENT_WARNING, &message),
            AnetEvent::Error(message) => callbacks.emit_event(EVENT_ERROR, &message),
            AnetEvent::AccountInfo(info) => {
                if let Ok(payload) = serde_json::to_string(&info) {
                    callbacks.emit_event(EVENT_ACCOUNT, &payload);
                }
            }
            _ => {}
        }
    }
}

impl EventHandler for IosEventHandlerProxy {
    fn on_event(&self, event: AnetEvent) {
        self.0.on_event(event);
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Ipv4Route {
    address: String,
    prefix: u8,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkSettingsRequest {
    request_id: u64,
    reset: bool,
    remote_address: String,
    address: String,
    netmask: String,
    mtu: u16,
    dns_servers: Vec<String>,
    included_routes: Vec<Ipv4Route>,
    excluded_routes: Vec<Ipv4Route>,
}

#[derive(Clone, Default)]
struct NetworkSettingsState {
    remote_address: Option<String>,
    address: Option<String>,
    netmask: Option<String>,
    mtu: u16,
    dns_servers: Vec<String>,
    included_routes: Vec<Ipv4Route>,
    excluded_routes: Vec<Ipv4Route>,
}

struct NetworkSettingsBridge {
    callbacks: Arc<CallbackContext>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
}

impl NetworkSettingsBridge {
    fn new(callbacks: Arc<CallbackContext>) -> Self {
        Self {
            callbacks,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    async fn apply(&self, state: &NetworkSettingsState, reset: bool) -> Result<()> {
        let address = state
            .address
            .clone()
            .ok_or_else(|| anyhow!("Network settings requested before server authentication"))?;
        let netmask = state
            .netmask
            .clone()
            .ok_or_else(|| anyhow!("VPN netmask is missing"))?;
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = NetworkSettingsRequest {
            request_id,
            reset,
            remote_address: state
                .remote_address
                .clone()
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            address,
            netmask,
            mtu: state.mtu,
            dns_servers: state.dns_servers.clone(),
            included_routes: state.included_routes.clone(),
            excluded_routes: state.excluded_routes.clone(),
        };
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, sender);
        let payload = serde_json::to_string(&request)?;
        self.callbacks.emit_event(EVENT_APPLY_SETTINGS, &payload);

        let response = match timeout(SETTINGS_TIMEOUT, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(anyhow!("iOS tunnel settings request was cancelled")),
            Err(_) => {
                self.pending.lock().unwrap().remove(&request_id);
                return Err(anyhow!("Timed out waiting for iOS tunnel settings"));
            }
        };
        if response {
            Ok(())
        } else {
            Err(anyhow!(
                "iOS rejected the requested tunnel network settings"
            ))
        }
    }

    fn complete(&self, request_id: u64, succeeded: bool) -> bool {
        self.pending
            .lock()
            .unwrap()
            .remove(&request_id)
            .is_some_and(|sender| sender.send(succeeded).is_ok())
    }

    fn cancel_pending(&self) {
        self.pending.lock().unwrap().clear();
    }
}

struct IosTunFactory {
    inbound: Mutex<Option<mpsc::Receiver<Bytes>>>,
    callbacks: Arc<CallbackContext>,
    config: CoreConfig,
    settings: Arc<Mutex<NetworkSettingsState>>,
    bridge: Arc<NetworkSettingsBridge>,
}

#[async_trait]
impl TunFactory for IosTunFactory {
    async fn create_tun(
        &self,
        auth: &AuthResponse,
    ) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, String)> {
        auth.ip
            .parse::<Ipv4Addr>()
            .context("iOS Packet Tunnel currently requires an IPv4 server address")?;
        auth.netmask
            .parse::<Ipv4Addr>()
            .context("Invalid IPv4 netmask from ANet server")?;

        {
            let mut settings = self.settings.lock().unwrap();
            settings.address = Some(auth.ip.clone());
            settings.netmask = Some(auth.netmask.clone());
            settings.mtu = u16::try_from(auth.mtu).unwrap_or(1400).clamp(576, 9000);
            settings.dns_servers = self.config.main.dns_server_list.clone();
        }
        let settings = self.settings.lock().unwrap().clone();
        self.bridge.apply(&settings, false).await?;

        let inbound = self
            .inbound
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow!("iOS packet input channel was already consumed"))?;
        let (outbound, mut packets) = mpsc::channel::<Bytes>(256);
        let callbacks = self.callbacks.clone();
        tokio::spawn(async move {
            while let Some(packet) = packets.recv().await {
                callbacks.emit_packet(&packet);
            }
        });

        Ok((outbound, inbound, "anet-ios".to_string()))
    }
}

struct IosRouteManager {
    settings: Arc<Mutex<NetworkSettingsState>>,
    bridge: Arc<NetworkSettingsBridge>,
}

impl IosRouteManager {
    async fn apply_if_configured(&self) -> Result<()> {
        let settings = self.settings.lock().unwrap().clone();
        if settings.address.is_some() {
            self.bridge.apply(&settings, false).await?;
        }
        Ok(())
    }

    fn insert_route(routes: &mut Vec<Ipv4Route>, address: IpAddr, prefix: u8) {
        if let IpAddr::V4(address) = address {
            let route = Ipv4Route {
                address: address.to_string(),
                prefix: prefix.min(32),
            };
            if !routes
                .iter()
                .any(|item| item.address == route.address && item.prefix == route.prefix)
            {
                routes.push(route);
            }
        }
    }
}

#[async_trait]
impl RouteManager for IosRouteManager {
    async fn backup_routes(&self) -> Result<()> {
        Ok(())
    }

    async fn add_bypass_route(&self, target: IpAddr, prefix: u8) -> Result<()> {
        {
            let mut settings = self.settings.lock().unwrap();
            settings.remote_address = Some(target.to_string());
            Self::insert_route(&mut settings.excluded_routes, target, prefix);
        }
        self.apply_if_configured().await
    }

    async fn set_default_route(&self, _gateway: &str, _interface_name: &str) -> Result<()> {
        {
            let mut settings = self.settings.lock().unwrap();
            Self::insert_route(
                &mut settings.included_routes,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            );
        }
        self.apply_if_configured().await
    }

    async fn add_specific_route(
        &self,
        target: IpAddr,
        prefix: u8,
        _gateway: &str,
        _interface_name: &str,
    ) -> Result<()> {
        {
            let mut settings = self.settings.lock().unwrap();
            Self::insert_route(&mut settings.included_routes, target, prefix);
        }
        self.apply_if_configured().await
    }

    async fn restore_routes(&self) -> Result<()> {
        let snapshot = self.settings.lock().unwrap().clone();
        if snapshot.address.is_some() {
            self.bridge.apply(&snapshot, true).await?;
            let mut settings = self.settings.lock().unwrap();
            *settings = NetworkSettingsState::default();
        }
        Ok(())
    }
}

pub struct AnetIosClient {
    runtime: Runtime,
    client: Arc<AnetClient>,
    packet_sender: mpsc::Sender<Bytes>,
    bridge: Arc<NetworkSettingsBridge>,
    callbacks: Arc<CallbackContext>,
    start_task: Mutex<Option<JoinHandle<()>>>,
    started: AtomicBool,
    stopped: AtomicBool,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(message: impl AsRef<str>) {
    let text = message.as_ref().replace('\0', "�");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(text).unwrap_or_default();
    });
}

fn ffi_guard<T>(fallback: T, operation: impl FnOnce() -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            set_error(format!("{error:#}"));
            fallback
        }
        Err(_) => {
            set_error("Rust iOS FFI panicked");
            fallback
        }
    }
}

impl AnetIosClient {
    fn stop(&self) -> Result<()> {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.bridge.cancel_pending();
        self.runtime.block_on(self.client.stop())?;
        if let Some(mut task) = self.start_task.lock().unwrap().take() {
            let joined = self
                .runtime
                .block_on(async { timeout(Duration::from_secs(5), &mut task).await })
                .is_ok();
            if !joined {
                task.abort();
                let _ = self.runtime.block_on(task);
            }
        }
        clear_event_handler(self.callbacks.context);
        Ok(())
    }
}

/// `config_utf8` must point to `config_length` readable bytes for this call.
/// Callback context must remain valid until `anet_ios_client_free` returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_new(
    config_utf8: *const u8,
    config_length: usize,
    callbacks: AnetIosCallbacks,
) -> *mut AnetIosClient {
    ffi_guard(std::ptr::null_mut(), || {
        if config_utf8.is_null() || config_length == 0 || config_length > MAX_CONFIG_BYTES {
            return Err(anyhow!("Invalid ANet client profile buffer"));
        }
        if callbacks.on_event.is_none() || callbacks.on_packet.is_none() {
            return Err(anyhow!("iOS event and packet callbacks are required"));
        }
        if callbacks.context.is_null() {
            return Err(anyhow!("iOS callback context is null"));
        }
        // SAFETY: the caller promises a readable buffer of config_length bytes.
        let config_bytes = unsafe { slice::from_raw_parts(config_utf8, config_length) };
        let config_text =
            std::str::from_utf8(config_bytes).context("Client profile must be UTF-8")?;
        let mut config: CoreConfig =
            toml::from_str(config_text).context("Invalid ANet TOML profile")?;
        config.sanitize().context("Invalid ANet client profile")?;

        let callbacks = Arc::new(CallbackContext {
            context: callbacks.context as usize,
            on_event: callbacks.on_event,
            on_packet: callbacks.on_packet,
        });

        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("anet-ios-core")
            .build()
            .context("Could not create Tokio runtime")?;
        install_event_handler(callbacks.clone());

        let bridge = Arc::new(NetworkSettingsBridge::new(callbacks.clone()));
        let settings = Arc::new(Mutex::new(NetworkSettingsState::default()));
        let (packet_sender, packet_receiver) = mpsc::channel::<Bytes>(256);
        let tun_factory = Box::new(IosTunFactory {
            inbound: Mutex::new(Some(packet_receiver)),
            callbacks: callbacks.clone(),
            config: config.clone(),
            settings: settings.clone(),
            bridge: bridge.clone(),
        });
        let route_manager = Box::new(IosRouteManager {
            settings,
            bridge: bridge.clone(),
        });
        let client = Arc::new(AnetClient::new(config, tun_factory, route_manager));
        Ok(Box::into_raw(Box::new(AnetIosClient {
            runtime,
            client,
            packet_sender,
            bridge,
            callbacks,
            start_task: Mutex::new(None),
            started: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        })))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_start(client: *mut AnetIosClient) -> i32 {
    ffi_guard(-1, || {
        let client = unsafe { client.as_ref() }.ok_or_else(|| anyhow!("Client handle is null"))?;
        if client.stopped.load(Ordering::SeqCst) || client.started.swap(true, Ordering::SeqCst) {
            return Err(anyhow!("Client is stopped or already started"));
        }
        let core = client.client.clone();
        let callbacks = client.callbacks.clone();
        let task = client.runtime.spawn(async move {
            if let Err(error) = core.start().await {
                callbacks.emit_event(EVENT_FAILED, &format!("ANet core stopped: {error:#}"));
            }
        });
        *client.start_task.lock().unwrap() = Some(task);
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_send_packet(
    client: *mut AnetIosClient,
    packet: *const u8,
    packet_length: usize,
) -> i32 {
    ffi_guard(-1, || {
        let client = unsafe { client.as_ref() }.ok_or_else(|| anyhow!("Client handle is null"))?;
        if packet.is_null() || packet_length == 0 || packet_length > MAX_PACKET_BYTES {
            return Err(anyhow!("Invalid IP packet buffer"));
        }
        // SAFETY: the caller promises a readable packet buffer for this call.
        let packet = unsafe { slice::from_raw_parts(packet, packet_length) };
        match client
            .packet_sender
            .try_send(Bytes::copy_from_slice(packet))
        {
            Ok(()) => Ok(0),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(1),
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(2),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_complete_network_settings(
    client: *mut AnetIosClient,
    request_id: u64,
    succeeded: bool,
) -> i32 {
    ffi_guard(-1, || {
        let client = unsafe { client.as_ref() }.ok_or_else(|| anyhow!("Client handle is null"))?;
        if client.bridge.complete(request_id, succeeded) {
            Ok(0)
        } else {
            Err(anyhow!("Unknown or expired network settings request"))
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_reconnect(client: *mut AnetIosClient) -> i32 {
    ffi_guard(-1, || {
        let client = unsafe { client.as_ref() }.ok_or_else(|| anyhow!("Client handle is null"))?;
        if client.stopped.load(Ordering::SeqCst) {
            return Err(anyhow!("Client is stopped"));
        }
        client.client.trigger_reconnect();
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_stop(client: *mut AnetIosClient) -> i32 {
    ffi_guard(-1, || {
        let client = unsafe { client.as_ref() }.ok_or_else(|| anyhow!("Client handle is null"))?;
        client.stop()?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn anet_ios_client_free(client: *mut AnetIosClient) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            // SAFETY: the handle was created by `anet_ios_client_new` and is freed once.
            let owned = unsafe { Box::from_raw(client) };
            let _ = owned.stop();
        }
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn anet_ios_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}
