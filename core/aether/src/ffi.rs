use std::ffi::{c_char, CStr, CString};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use serde::Deserialize;
use tokio::sync::Notify;

use crate::{platform, EndpointDiscovery, IpScan, MasqueTransport, Protocol, ScanMode, StartOptions, TlsCurvePreset, TunnelAddresses};

static LAST_ERROR: LazyLock<Mutex<CString>> =
    LazyLock::new(|| Mutex::new(CString::new("").unwrap()));
static LAST_RESULT: LazyLock<Mutex<CString>> =
    LazyLock::new(|| Mutex::new(CString::new("").unwrap()));
static LAST_LOG: LazyLock<Mutex<CString>> =
    LazyLock::new(|| Mutex::new(CString::new("").unwrap()));
static LOGS: LazyLock<Mutex<VecDeque<String>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
static RUNNING: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static STOP_NOTIFY: OnceLock<Notify> = OnceLock::new();

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NativeStartOptions {
    config_path: String,
    protocol: String,
    listen: String,
    wireguard_config_path: Option<String>,
    masque_config_path: Option<String>,
    forced_peer: Option<String>,
    scan_mode: String,
    ip_scan: String,
    obfuscation_profile: Option<String>,
    retry_obfuscation_profiles: bool,
    endpoint_cache_path: Option<String>,
    endpoint_discovery: String,
    masque_transport: String,
    tls_curve_preset: String,
    wireguard_data_check: bool,
}

impl Default for NativeStartOptions {
    fn default() -> Self {
        Self {
            config_path: String::new(),
            protocol: "masque".into(),
            listen: "127.0.0.1:1819".into(),
            wireguard_config_path: None,
            masque_config_path: None,
            forced_peer: None,
            scan_mode: "balanced".into(),
            ip_scan: "v4".into(),
            obfuscation_profile: None,
            retry_obfuscation_profiles: true,
            endpoint_cache_path: None,
            endpoint_discovery: "cache".into(),
            masque_transport: "h3".into(),
            tls_curve_preset: "chrome".into(),
            wireguard_data_check: true,
        }
    }
}

impl TryFrom<NativeStartOptions> for StartOptions {
    type Error = String;

    fn try_from(value: NativeStartOptions) -> Result<Self, Self::Error> {
        if value.config_path.trim().is_empty() {
            return Err("config_path is required".into());
        }

        let mut options = StartOptions::new(Protocol::parse(&value.protocol), value.config_path);
        options.listen = parse_address("listen", &value.listen)?;
        options.wireguard_config_path = value.wireguard_config_path;
        options.masque_config_path = value.masque_config_path;
        options.forced_peer = value
            .forced_peer
            .map(|peer| parse_address("forced_peer", &peer))
            .transpose()?;
        options.scan_mode = ScanMode::parse(&value.scan_mode);
        options.ip_scan = IpScan::parse(&value.ip_scan);
        options.obfuscation_profile = value.obfuscation_profile;
        options.retry_obfuscation_profiles = value.retry_obfuscation_profiles;
        options.endpoint_cache_path = value.endpoint_cache_path.filter(|path| !path.trim().is_empty());
        options.endpoint_discovery = EndpointDiscovery::parse(&value.endpoint_discovery);
        options.masque_transport = MasqueTransport::parse(&value.masque_transport);
        options.tls_curve_preset = TlsCurvePreset::parse(&value.tls_curve_preset);
        options.wireguard_data_check = value.wireguard_data_check;
        Ok(options)
    }
}

fn parse_address(name: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}

fn set_last_error(error: impl ToString) {
    let clean = error.to_string().replace('\0', " ");
    *LAST_ERROR.lock().unwrap() = CString::new(clean).unwrap();
}

fn clear_logs() {
    LOGS.lock().unwrap().clear();
    *LAST_LOG.lock().unwrap() = CString::new("").unwrap();
}

pub(crate) fn record_log(message: impl ToString) {
    let text = message.to_string().replace('\0', " ");
    let snapshot = {
        let mut logs = LOGS.lock().unwrap();
        if logs.len() == 400 {
            logs.pop_front();
        }
        logs.push_back(text);
        logs.iter().cloned().collect::<Vec<_>>().join("\n")
    };
    *LAST_LOG.lock().unwrap() = CString::new(snapshot).unwrap();
}

fn set_last_result(result: impl ToString) {
    *LAST_RESULT.lock().unwrap() = CString::new(result.to_string()).unwrap();
}

unsafe fn options_from_json(json: *const c_char) -> Result<StartOptions, String> {
    if json.is_null() {
        return Err("configuration pointer is null".into());
    }

    // SAFETY: caller promises valid, NUL-terminated string for this call.
    let json = unsafe { CStr::from_ptr(json) }
        .to_str()
        .map_err(|error| format!("configuration is not UTF-8: {error}"))?;
    serde_json::from_str::<NativeStartOptions>(json)
        .map_err(|error| error.to_string())
        .and_then(StartOptions::try_from)
}

fn stop_notify() -> &'static Notify {
    STOP_NOTIFY.get_or_init(Notify::new)
}

async fn wait_for_stop() {
    loop {
        let notified = stop_notify().notified();
        if STOP_REQUESTED.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
        READY.store(false, Ordering::Release);
    }
}

/// Starts Aether on the calling thread from a UTF-8 JSON configuration.
///
/// Returns 0 when the tunnel exits normally, -1 for invalid input, -2 for a
/// runtime/tunnel error, and -3 if a panic was contained at the FFI boundary.
/// The Android caller must invoke this on a worker thread.
#[no_mangle]
pub unsafe extern "C" fn aether_start_json(json: *const c_char) -> i32 {
    unsafe { aether_start_json_inner(json, None) }
}

/// Starts Aether in Android TUN mode. The caller retains ownership of `tun_fd`.
#[no_mangle]
pub unsafe extern "C" fn aether_start_json_with_tun(json: *const c_char, tun_fd: i32) -> i32 {
    if tun_fd < 0 {
        set_last_error("TUN file descriptor is invalid");
        return -1;
    }
    unsafe { aether_start_json_inner(json, Some(tun_fd)) }
}

unsafe fn aether_start_json_inner(json: *const c_char, tun_fd: Option<i32>) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut options = match unsafe { options_from_json(json) } {
            Ok(options) => options,
            Err(error) => {
                set_last_error(error);
                return -1;
            }
        };
        options.tun_fd = tun_fd;

        if RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            set_last_error("Aether tunnel already running");
            return -2;
        }
        let _running = RunningGuard;
        STOP_REQUESTED.store(false, Ordering::Release);
        READY.store(false, Ordering::Release);
        clear_logs();
        record_log("Native tunnel started");

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                set_last_error(error);
                return -2;
            }
        };

        runtime.block_on(async {
            tokio::select! {
                result = crate::start(options) => match result {
                    Ok(()) => 0,
                    Err(error) => {
                        set_last_error(error);
                        -2
                    }
                },
                _ = wait_for_stop() => 0,
            }
        })
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in Aether native core");
            -3
        }
    }
}

/// Loads or provisions account identity and stores JSON addresses in last_result.
#[no_mangle]
pub unsafe extern "C" fn aether_prepare_json(json: *const c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let options = match unsafe { options_from_json(json) } {
            Ok(options) => options,
            Err(error) => {
                set_last_error(error);
                return -1;
            }
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                set_last_error(error);
                return -2;
            }
        };

        match runtime.block_on(crate::prepare(&options)) {
            Ok(TunnelAddresses { ipv4, ipv6 }) => {
                set_last_result(serde_json::json!({ "ipv4": ipv4, "ipv6": ipv6 }));
                0
            }
            Err(error) => {
                set_last_error(error);
                -2
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("panic in Aether native core");
            -3
        }
    }
}

/// Returns the most recent native error. Copy it before another native call.
#[no_mangle]
pub extern "C" fn aether_last_error() -> *const c_char {
    LAST_ERROR.lock().unwrap().as_ptr()
}

#[no_mangle]
pub extern "C" fn aether_last_result() -> *const c_char {
    LAST_RESULT.lock().unwrap().as_ptr()
}

#[no_mangle]
pub extern "C" fn aether_last_log() -> *const c_char {
    LAST_LOG.lock().unwrap().as_ptr()
}

#[no_mangle]
pub extern "C" fn aether_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn aether_set_socket_protector(protector: Option<platform::SocketProtector>) {
    platform::set_socket_protector(protector);
}

/// Requests shutdown of the active native tunnel. Returns 1 if running, else 0.
#[no_mangle]
pub extern "C" fn aether_stop() -> i32 {
    if !RUNNING.load(Ordering::Acquire) {
        return 0;
    }

    STOP_REQUESTED.store(true, Ordering::Release);
    stop_notify().notify_waiters();
    1
}

#[no_mangle]
pub extern "C" fn aether_is_running() -> i32 {
    i32::from(RUNNING.load(Ordering::Acquire))
}

#[no_mangle]
pub extern "C" fn aether_is_ready() -> i32 {
    i32::from(READY.load(Ordering::Acquire))
}

pub(crate) fn mark_ready() {
    READY.store(true, Ordering::Release);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_android_start_options() {
        let native: NativeStartOptions = serde_json::from_str(
            r#"{"config_path":"/data/user/0/app/files/aether.toml","protocol":"masque","masque_transport":"h2"}"#,
        )
        .unwrap();
        let options = StartOptions::try_from(native).unwrap();

        assert_eq!(options.protocol, Protocol::Masque);
        assert_eq!(options.masque_transport, MasqueTransport::H2);
        assert_eq!(options.listen, "127.0.0.1:1819".parse().unwrap());
        assert_eq!(options.scan_mode, ScanMode::Balanced);
        assert_eq!(options.tls_curve_preset, TlsCurvePreset::Chrome);
        assert!(options.wireguard_data_check);
    }

    #[test]
    fn parses_advanced_android_start_options() {
        let native: NativeStartOptions = serde_json::from_str(
            r#"{"config_path":"aether.toml","tls_curve_preset":"compatibility","wireguard_data_check":false}"#,
        )
        .unwrap();
        let options = StartOptions::try_from(native).unwrap();

        assert_eq!(options.tls_curve_preset, TlsCurvePreset::Compatibility);
        assert!(!options.wireguard_data_check);
    }

    #[test]
    fn rejects_missing_config_path() {
        let native: NativeStartOptions = serde_json::from_str("{}").unwrap();
        assert!(StartOptions::try_from(native).is_err());
    }
}
