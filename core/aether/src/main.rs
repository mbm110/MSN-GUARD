#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{AetherError, Result};
pub use crate::prober::{IpScan, ScanMode};
use crate::{
    account, aethernoize, config, consts, dns, lastconn, masque_h2, netstack, noize, prober, quic,
    socks, sysprofile, tls, tun, wg_prober, wireguard, zerotrust,
};

const TUNNEL_MTU: usize = 1280;
const INNER_MTU: usize = 1200;
const DEFAULT_CONFIG: &str = "aether.toml";
static INITIALIZED: std::sync::Once = std::sync::Once::new();

fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

#[derive(Debug, Clone)]
pub struct StartOptions {
    pub listen: SocketAddr,
    pub config_path: String,
    pub wireguard_config_path: Option<String>,
    pub masque_config_path: Option<String>,
    pub protocol: Protocol,
    pub forced_peer: Option<SocketAddr>,
    pub scan_mode: ScanMode,
    pub ip_scan: IpScan,
    pub obfuscation_profile: Option<String>,
    pub obfuscation_parameters: Option<String>,
    pub retry_obfuscation_profiles: bool,
    pub endpoint_cache_path: Option<String>,
    pub endpoint_discovery: EndpointDiscovery,
    pub masque_transport: MasqueTransport,
    pub tls_curve_preset: TlsCurvePreset,
    pub wireguard_data_check: bool,
    pub tun_fd: Option<i32>,
    pub log_level: Option<String>,
    pub perf_profile: Option<String>,
    pub h2_fragmentation: Option<bool>,
    pub dns_servers: Option<String>,
    pub route_block: Option<String>,
    pub route_direct: Option<String>,
    pub routes_file: Option<String>,
    pub team: Option<String>,
    pub access_client_id: Option<String>,
    pub access_client_secret: Option<String>,
    pub access_token: Option<String>,
    pub access_email: Option<String>,
    pub gateway: bool,
    pub upstream_proxy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueTransport {
    H3,
    H2,
}

impl MasqueTransport {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "h2" | "http2" | "http/2" => Self::H2,
            _ => Self::H3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointDiscovery {
    Cache,
    Fresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCurvePreset {
    Chrome,
    Compatibility,
}

impl TlsCurvePreset {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "compatibility" | "compatible" => Self::Compatibility,
            _ => Self::Chrome,
        }
    }
}

impl EndpointDiscovery {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "fresh" | "fresh_scan" => Self::Fresh,
            _ => Self::Cache,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelAddresses {
    pub ipv4: String,
    pub ipv6: String,
    pub gateway_proxy: String,
    pub organization: String,
}

fn address_host(raw: &str) -> String {
    raw.split('/')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_string()
}

impl StartOptions {
    pub fn new(protocol: Protocol, config_path: impl Into<String>) -> Self {
        Self {
            listen: "127.0.0.1:1819".parse().unwrap(),
            config_path: config_path.into(),
            wireguard_config_path: None,
            masque_config_path: None,
            protocol,
            forced_peer: None,
            scan_mode: ScanMode::Balanced,
            ip_scan: IpScan::V4,
            obfuscation_profile: None,
            obfuscation_parameters: None,
            retry_obfuscation_profiles: true,
            endpoint_cache_path: None,
            endpoint_discovery: EndpointDiscovery::Cache,
            masque_transport: MasqueTransport::H3,
            tls_curve_preset: TlsCurvePreset::Chrome,
            wireguard_data_check: true,
            tun_fd: None,
            log_level: None,
            perf_profile: None,
            h2_fragmentation: None,
            dns_servers: None,
            route_block: None,
            route_direct: None,
            routes_file: None,
            team: None,
            access_client_id: None,
            access_client_secret: None,
            access_token: None,
            access_email: None,
            gateway: false,
            upstream_proxy: None,
        }
    }

    fn masque_profile(&self) -> &str {
        self.obfuscation_profile.as_deref().unwrap_or("firewall")
    }

    fn wireguard_profile(&self) -> &str {
        self.obfuscation_profile.as_deref().unwrap_or("balanced")
    }
}

pub async fn run_cli() -> Result<()> {
    crate::cli::parse_and_apply()?;
    initialize();

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let listen: SocketAddr = std::env::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    let protocol =
        if std::env::var("AETHER_PEER").is_ok() || std::env::var("AETHER_WG_PEER").is_ok() {
            match std::env::var("AETHER_PROTOCOL") {
                Ok(v) => Protocol::parse(&v),
                Err(_) => Protocol::Masque,
            }
        } else {
            select_protocol(&base_config).await
        };

    let forced_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
        Protocol::Psiphon => None,
    }
    .map(|peer| {
        peer.parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {peer}")))
    })
    .transpose()?;

    let mut options = StartOptions::new(protocol, base_config);
    options.listen = listen;
    options.wireguard_config_path = std::env::var("AETHER_WG_CONFIG").ok();
    options.masque_config_path = std::env::var("AETHER_MASQUE_CONFIG").ok();
    options.forced_peer = forced_peer;
    options.scan_mode = select_scan_mode().await;
    options.ip_scan = select_ip_version().await;
    options.obfuscation_profile = std::env::var("AETHER_NOIZE").ok();
    options.obfuscation_parameters = std::env::var("AETHER_NOIZE_PARAMETERS").ok();
    options.retry_obfuscation_profiles = std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err();
    options.wireguard_data_check = std::env::var("AETHER_WG_NO_DATA_CHECK").is_err();
    options.log_level = std::env::var("AETHER_LOG_LEVEL").ok();
    options.perf_profile = std::env::var("AETHER_PERF_PROFILE").ok();
    options.h2_fragmentation = Some(std::env::var("AETHER_MASQUE_H2_FRAGMENT").is_ok());
    options.dns_servers = std::env::var("AETHER_DNS").ok();
    options.route_block = std::env::var("AETHER_ROUTE_BLOCK").ok();
    options.route_direct = std::env::var("AETHER_ROUTE_DIRECT").ok();
    options.routes_file = std::env::var("AETHER_ROUTES_FILE").ok();
    options.team = std::env::var("AETHER_TEAM").ok();
    options.access_client_id = std::env::var("AETHER_ACCESS_CLIENT_ID").ok();
    options.access_client_secret = std::env::var("AETHER_ACCESS_CLIENT_SECRET").ok();
    options.access_token = std::env::var("AETHER_ACCESS_TOKEN").ok();
    options.access_email = std::env::var("AETHER_ACCESS_EMAIL").ok();
    options.gateway = std::env::var("AETHER_GATEWAY").is_ok();

    select_masque_transport().await;
    options.masque_transport = if std::env::var("AETHER_MASQUE_HTTP2").is_ok() {
        MasqueTransport::H2
    } else {
        MasqueTransport::H3
    };
    start(options).await
}

pub async fn start(options: StartOptions) -> Result<()> {
    apply_runtime_options(&options);
    initialize();

    match options.protocol {
        Protocol::Masque => {
            masque_h2::set_preferred(options.masque_transport == MasqueTransport::H2);
            let config_path = masque_config_path(&options);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let ech = resolve_ech().await;
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, ech, options.listen, lastconn_path, &options).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&options);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let lastconn_path = lastconn_path(&config_path);
            run_wireguard(identity, options.listen, lastconn_path, &options).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&options);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            let lastconn_path = gool_lastconn_path(&primary_path);
            run_gool(primary, secondary, options.listen, lastconn_path, &options).await
        }
        Protocol::Psiphon => {
            let upstream = options.upstream_proxy.as_deref().unwrap_or("127.0.0.1:1080");
            log::info!("[+] Psiphon upstream SOCKS proxy: {upstream}");
            run_psiphon(upstream, options.listen, &options).await
        }
    }
}

fn apply_runtime_options(options: &StartOptions) {
    fn set_optional(key: &str, value: &Option<String>) {
        match value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    if let Some(ref level) = options.log_level {
        std::env::set_var("AETHER_LOG_LEVEL", level);
    } else {
        std::env::remove_var("AETHER_LOG_LEVEL");
    }
    if let Some(ref profile) = options.perf_profile {
        std::env::set_var("AETHER_PERF_PROFILE", profile);
    } else {
        std::env::remove_var("AETHER_PERF_PROFILE");
    }
    if options.h2_fragmentation == Some(true) {
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
    } else {
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
    }
    crate::ffi::set_log_path(Some(core_log_path(&options.config_path)));

    set_optional("AETHER_NOIZE_PARAMETERS", &options.obfuscation_parameters);

    set_optional("AETHER_DNS", &options.dns_servers);
    set_optional("AETHER_ROUTE_BLOCK", &options.route_block);
    set_optional("AETHER_ROUTE_DIRECT", &options.route_direct);
    set_optional("AETHER_ROUTES_FILE", &options.routes_file);
    set_optional("AETHER_TEAM", &options.team);
    set_optional("AETHER_ACCESS_CLIENT_ID", &options.access_client_id);
    set_optional("AETHER_ACCESS_CLIENT_SECRET", &options.access_client_secret);
    set_optional("AETHER_ACCESS_TOKEN", &options.access_token);
    set_optional("AETHER_ACCESS_EMAIL", &options.access_email);
    std::env::remove_var("AETHER_TEAM_ENDPOINT");
    if options.gateway {
        std::env::set_var("AETHER_GATEWAY", "1");
    } else {
        std::env::remove_var("AETHER_GATEWAY");
    }
    socks::clear_gateway_proxy();
    socks::reload_routes();
}

pub async fn prepare(options: &StartOptions) -> Result<TunnelAddresses> {
    apply_runtime_options(options);
    initialize();

    let identity = match options.protocol {
        Protocol::Masque => load_or_provision_masque(&masque_config_path(options)).await?,
        Protocol::WireGuard => load_or_provision_warp(&warp_config_path(options)).await?,
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(options);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            load_or_provision_warp(&secondary_path).await?
        }
        Protocol::Psiphon => {
            // Psiphon does not hand us a tunnel identity: the Go core owns the
            // tunnel and only exposes a local SOCKS port, which the Kotlin side
            // bridges into the TUN via tun2socks. These are fixed CGNAT-range
            // placeholders that satisfy VpnService.Builder's need for an address.
            //
            // gateway_proxy / organization are new in upstream v0.8.0 and belong
            // to Cloudflare Zero Trust. Psiphon has no equivalent, so they stay
            // empty: applyGatewayProxy() is gated on the config's "gateway" flag
            // and parseSocketAddress("") returns null, so an empty value is the
            // correct "not applicable" signal rather than a missing field.
            return Ok(TunnelAddresses {
                ipv4: "198.18.0.1".into(),
                ipv6: "fc00::1".into(),
                gateway_proxy: String::new(),
                organization: String::new(),
            });
        }
    };

    Ok(TunnelAddresses {
        ipv4: address_host(&identity.ipv4),
        ipv6: address_host(&identity.ipv6),
        gateway_proxy: identity.gateway_proxy,
        organization: identity.organization,
    })
}

pub fn initialize() {
    INITIALIZED.call_once(|| {
        let level = std::env::var("AETHER_LOG_LEVEL")
            .ok()
            .map(|value| value.trim().to_lowercase())
            .filter(|value| {
                matches!(
                    value.as_str(),
                    "error" | "warn" | "info" | "debug" | "trace"
                )
            })
            .unwrap_or_else(|| "info".to_string());
        let filter = format!("info,aether={level}");
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
            .format_timestamp_millis()
            .try_init();
        install_netstack_panic_guard();
    });
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config(profile: &str) -> noize::NoizeConfig {
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(profile)
}

fn aethernoize_config(profile: &str) -> aethernoize::AetherNoizeConfig {
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(profile)
}

fn team_scope() -> Option<String> {
    zerotrust::TeamSettings::from_env().map(|settings| settings.team)
}

fn enrolled_teams(base: &str) -> Vec<String> {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    let dir = if dir_end == 0 { "." } else { &base[..dir_end] };
    let stem = match base[dir_end..].rfind('.') {
        Some(rel) => &base[dir_end..dir_end + rel],
        None => &base[dir_end..],
    };
    let prefix = format!("{stem}-team-");

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut teams: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(team) = rest.strip_suffix(".toml") else {
            continue;
        };
        if team.is_empty() || team.ends_with("-secondary") || team.ends_with("-lastconn") {
            continue;
        }
        if !teams.iter().any(|known| known == team) {
            teams.push(team.to_string());
        }
    }
    teams.sort();
    teams
}

async fn enrol_zero_trust(base: &str) {
    let known = enrolled_teams(base);

    let prompt = match known.first() {
        Some(team) => format!(
            "\nZero Trust organization.\n  already enrolled: {}\nTeam name from \
             <team>.cloudflareaccess.com, or blank to reuse '{}': ",
            known.join(", "),
            team
        ),
        None => "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com \
                 (blank to cancel): "
            .to_string(),
    };

    let answer = prompt_line(&prompt).await.unwrap_or_default();
    let answer = answer.trim().to_string();

    let team = if answer.is_empty() {
        match known.first() {
            Some(team) => team.clone(),
            None => {
                log::info!("[*] Zero Trust skipped; staying on personal WARP");
                return;
            }
        }
    } else {
        match zerotrust::normalize_team(&answer) {
            Some(team) => team,
            None => {
                log::warn!("[-] '{answer}' is not a usable team name");
                return;
            }
        }
    };

    std::env::set_var("AETHER_TEAM", &team);

    if known.iter().any(|enrolled| *enrolled == team) {
        log::info!("[+] reusing the saved enrolment for team {team}; no sign-in needed");
        return;
    }

    let needs_method = match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            !(settings.token.is_some() || settings.has_service_token() || settings.email.is_some())
        }
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    if needs_method {
        let email = prompt_line("Email address for the one-time login code (blank to cancel): ")
            .await
            .unwrap_or_default();
        let email = email.trim().to_string();

        if email.is_empty() {
            log::warn!("[-] no email given; staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            return;
        }

        std::env::set_var("AETHER_ACCESS_EMAIL", &email);
    }

    let settings = match zerotrust::TeamSettings::from_env() {
        Some(settings) => settings,
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    match zerotrust::resolve_token(&settings).await {
        Ok(_) => log::info!("[+] signed in to team {team}; now pick the transport to use"),
        Err(error) => {
            log::error!("[-] Zero Trust sign-in failed: {error}");
            log::warn!("[-] staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            std::env::remove_var("AETHER_ACCESS_EMAIL");
        }
    }
}

async fn provision_account() -> Result<account::Identity> {
    match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            log::info!(
                "[*] enrolling this device into the Zero Trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, &settings)
                    .await?;
            Ok(account::refresh_profile(identity).await)
        }
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await,
    }
}

async fn adopt_team_profile(identity: account::Identity) -> account::Identity {
    if team_scope().is_none() {
        return identity;
    }

    let identity = account::refresh_profile(identity).await;

    if !identity.gateway_proxy.is_empty() {
        if std::env::var("AETHER_GATEWAY").is_ok() {
            socks::set_gateway_proxy(&identity.gateway_proxy);
        } else {
            log::debug!(
                "[zerotrust] the organization offers a gateway proxy at {}; pass --gateway to route http through it",
                identity.gateway_proxy
            );
        }
    }

    if !identity.assigned_endpoint.is_empty() && std::env::var("AETHER_PEER").is_err() {
        let port = if std::env::var("AETHER_PROTOCOL")
            .map(|value| value == "wg" || value == "gool")
            .unwrap_or(false)
        {
            2408
        } else {
            443
        };
        let peer = format!("{}:{port}", identity.assigned_endpoint);
        if peer.parse::<SocketAddr>().is_ok() {
            log::info!("[+] the organization assigned endpoint {peer}; trying it before scanning");
            std::env::set_var("AETHER_TEAM_ENDPOINT", &peer);
        }
    }

    identity
}

fn warp_config_path(options: &StartOptions) -> String {
    if let Some(p) = options.wireguard_config_path.clone() {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(&options.config_path, &format!("team-{team}")),
        None => options.config_path.clone(),
    }
}

fn masque_config_path(options: &StartOptions) -> String {
    if let Some(p) = options.masque_config_path.clone() {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(&options.config_path, &format!("team-{team}")),
        None => derive_sibling_path(&options.config_path, "masque"),
    }
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

/// Whether a refused identity may be replaced by registering a fresh one.
///
/// On by default. `AETHER_REPROVISION=0` keeps the dead identity instead, which
/// is what you want when debugging: the failure stays reproducible rather than
/// being silently repaired on the next start.
fn keep_saved_identity() -> bool {
    !matches!(
        std::env::var("AETHER_REPROVISION").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        // NOTE on coverage: `adopt_team_profile` only calls the account API when a
        // Zero Trust team is configured, so on a personal WARP account a deleted
        // device is not detected here — there is no other request on the connect
        // path to learn it from. MASQUE has one (the key enrolment), WireGuard does
        // not. Adding an unconditional /reg call would put a network round trip on
        // every single connect, so this stays as-is deliberately; the MASQUE path
        // and any team account do get the check.
        let identity = adopt_team_profile(identity).await;
        if !identity.refused {
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        if !keep_saved_identity() {
            return Ok(identity);
        }
        // Falling through re-registers. A refused identity cannot be repaired:
        // it would hand back a tunnel that handshakes and carries nothing.
        log::warn!("[*] registering a fresh wireguard account to replace the refused identity");
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        let refused = if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            if !identity.refused {
                config::save(config_path, &identity)?;
                return Ok(identity);
            }
            identity
        } else {
            log::info!("[+] masque identity needs a certificate; enrolling masque key");
            // This is the enrolment call, and on a personal (non-team) account it
            // is the one place a refusal actually surfaces: `adopt_team_profile`
            // only refreshes the profile when a Zero Trust team is configured, so
            // without this branch a device deleted upstream would keep trying to
            // enrol a key against an account that no longer exists.
            match account::ensure_masque_enrolled(&identity).await {
                Ok(enrollment) => {
                    let identity = apply_masque_enrollment(identity, enrollment);
                    config::save(config_path, &identity)?;
                    return Ok(identity);
                }
                Err(AetherError::IdentityRefused(reason)) => {
                    log::warn!("[-] the saved masque identity was refused: {reason}");
                    crate::ffi::record_log(
                        "The saved MASQUE registration was rejected; registering a fresh one",
                    );
                    account::Identity {
                        refused: true,
                        ..identity
                    }
                }
                Err(error) => return Err(error),
            }
        };

        if !keep_saved_identity() {
            return Ok(refused);
        }
        log::warn!("[*] registering a fresh masque account to replace the refused identity");
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = provision_account().await?;
    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    let identity = apply_masque_enrollment(identity, enrollment);
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

/// Fold an enrollment result into the identity.
///
/// Keeps the gateway the enrollment response named. Registration is
/// `tunnel_type: wireguard` and returns a WireGuard endpoint — in the field log
/// `104.16.192.82`, a website-CDN address with no connect-ip listener — and that
/// stale value was the only "account" peer the MASQUE dialler ever had. The
/// enrollment response is the first point where the API names a real MASQUE
/// gateway, so prefer it and fall back to the old value when absent.
fn apply_masque_enrollment(
    identity: account::Identity,
    enrollment: account::MasqueEnrollment,
) -> account::Identity {
    let assigned_endpoint = if enrollment.assigned_endpoint.is_empty() {
        identity.assigned_endpoint.clone()
    } else {
        enrollment.assigned_endpoint.clone()
    };

    account::Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        assigned_endpoint,
        ..identity
    }
}

async fn select_peer(
    identity: &account::Identity,
    protocol: Protocol,
    options: &StartOptions,
) -> Result<SocketAddr> {
    if let Some(peer) = options.forced_peer {
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            crate::ffi::record_log("Finding a verified MASQUE gateway");
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(options.masque_profile()),
                tls_curve_preset: options.tls_curve_preset,
                ports: prober::MASQUE_PORTS.to_vec(),
                ip: options.ip_scan,
                local_ipv4: parse_local_v4(&identity.ipv4),
            };

            if options.endpoint_discovery == EndpointDiscovery::Cache {
                let cached = cached_masque_gateways(options);
                if !cached.is_empty() {
                    crate::ffi::record_log(format!(
                        "Checking {} cached MASQUE gateway(s)",
                        cached.len()
                    ));
                    if let Some(best) = prober::verify_cached_gateways(&probe, cached).await {
                        cache_masque_gateway(options, best);
                        spawn_masque_cache_refresh(
                            probe.clone(),
                            options.endpoint_cache_path.clone(),
                        );
                        log::info!("[+] using cached MASQUE gateway {}:{}", best.ip, best.port);
                        return Ok(SocketAddr::new(best.ip, best.port));
                    }
                    crate::ffi::record_log(
                        "Cached gateways did not respond; starting a fresh scan",
                    );
                }
            }

            let best = match prober::hunt_best_gateway(&probe, options.scan_mode).await {
                Ok(best) => best,
                Err(error) if !masque_h2::enabled() => {
                    log::warn!(
                        "[-] HTTP/3 found no MASQUE gateway ({error}); retrying HTTP/2 with TLS fragmentation"
                    );
                    crate::ffi::record_log(
                        "HTTP/3 found no gateway; retrying HTTP/2 with TLS fragmentation",
                    );
                    enable_restricted_h2();
                    let mut h2_probe = probe.clone();
                    h2_probe.ports = masque_h2_ports(&probe.ports);
                    prober::hunt_best_gateway(&h2_probe, ScanMode::Balanced).await?
                }
                Err(error) => return Err(error),
            };
            cache_masque_gateway(options, best);
            if options.endpoint_discovery == EndpointDiscovery::Cache {
                spawn_masque_cache_refresh(probe.clone(), options.endpoint_cache_path.clone());
            }
            log::info!(
                "[+] selected MASQUE gateway {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            crate::ffi::record_log(format!(
                "Selected {}:{} ({:?})",
                best.ip, best.port, best.rtt
            ));
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            log::info!("[*] hunting for a working WireGuard endpoint (handshake + data-plane verification)");
            let private_key = identity.private_key_bytes()?;
            let peer_public = identity.peer_public_key_bytes()?;

            let probe = wg_prober::WgProbe {
                private_key: std::sync::Arc::new(private_key),
                peer_public_key: std::sync::Arc::new(peer_public),
                client_id: identity.client_id.clone(),
                local_ipv4: identity
                    .ipv4
                    .parse()
                    .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
                aethernoize: aethernoize_config(options.wireguard_profile()),
                data_check: options.wireguard_data_check,
                ports: wireguard::WG_PORTS.to_vec(),
                ip: options.ip_scan,
                excluded: HashSet::new(),
            };

            let best = wg_prober::hunt_best_wg_endpoint(
                &probe,
                wg_prober::WgScanMode::parse(options.scan_mode.label()),
            )
            .await?;
            log::info!(
                "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::Psiphon => {
            Err(AetherError::Other("psiphon gateway discovery is not applicable".into()))
        }
    }
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!(
                    "[+] fetched ECHConfigList automatically ({} bytes)",
                    raw.len()
                );
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

/// Where GOOL remembers its outer WARP endpoint.
///
/// Deliberately a different file from `lastconn_path`, even though both hold a
/// WireGuard endpoint discovered with the same identity. Plain WireGuard stores
/// the obfuscation profile that worked alongside the peer and varies it across
/// retries, while GOOL's outer tunnel is always raised with the fixed `balanced`
/// profile. Sharing one file would mean each protocol reading back a peer that
/// was validated under settings the other never used.
fn gool_lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "gool-lastconn")
}

fn core_log_path(config_path: &str) -> String {
    match Path::new(config_path).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join("aether-core.log").to_string_lossy().into_owned()
        }
        _ => "aether-core.log".to_string(),
    }
}

fn assigned_masque_peer(identity: &account::Identity) -> Option<SocketAddr> {
    let host = identity.assigned_endpoint.trim();
    if host.is_empty() {
        return None;
    }
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    format!("{host}:443").parse().ok()
}

fn masque_transport_label() -> &'static str {
    if masque_h2::enabled() {
        "HTTP/2"
    } else {
        "HTTP/3"
    }
}

fn enable_restricted_h2() {
    masque_h2::enable_fallback();
    std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
    if std::env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE").is_err() {
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT_SIZE", "8-24");
    }
    if std::env::var("AETHER_MASQUE_H2_FRAGMENT_DELAY").is_err() {
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT_DELAY", "5-15");
    }
    crate::ffi::record_log("HTTP/2 TLS ClientHello fragmentation enabled");
}

fn masque_h2_ports(base: &[u16]) -> Vec<u16> {
    let mut ports = base.to_vec();
    for extra in [2053_u16, 2083, 2087, 2096, 8880] {
        if !ports.contains(&extra) {
            ports.push(extra);
        }
    }
    ports
}

/// How many distinct gateways may reject the device certificate before we stop
/// dialling more of them.
///
/// A `4xx` on the connect-ip CONNECT is the edge saying *this client certificate
/// is not valid for MASQUE*. That is a property of the identity, not of the peer,
/// so once several unrelated gateways agree there is nothing left to discover by
/// working through the rest of the list.
const IDENTITY_REJECTED_LIMIT: u32 = 3;

/// The obfuscation profile GOOL's outer WARP tunnel is raised with.
///
/// Fixed, unlike plain WireGuard which retries across a list of profiles. Named
/// because three places have to agree on it: `establish_wg` when it raises the
/// tunnel, the cached-peer verify that decides whether to skip the scan, and the
/// value written into the cache file. If the verify used a different profile it
/// would be answering a question about a connection nobody is going to make.
const GOOL_OUTER_PROFILE: &str = "balanced";

/// How many MASQUE gateways the HTTP/3 pass may try.
///
/// HTTP/3 is the only transport that works: measured against every gateway in
/// `prober::MASQUE_SEEDS`, `162.159.198.2` and `162.159.198.1` answer
/// `:status 200` over HTTP/3, while HTTP/2 gets `RST_STREAM` from those same two
/// and a content-free `400` from everything else. So the budget belongs here,
/// not in the fallback. Dead addresses fail fast — no QUIC listener means no
/// handshake, not a timeout — so a larger list is cheap.
const MASQUE_H3_PROBE_LIMIT: usize = 12;

/// How many gateways the HTTP/2 fallback may try.
///
/// Kept small on purpose. No Cloudflare edge was observed serving connect-ip
/// over HTTP/2, so this pass exists only in case a network blocks UDP/443
/// outright and Cloudflare later enables extended CONNECT on TCP. Every attempt
/// costs a full 8-second verify timeout, and the ~2-minute stall in the field log
/// was this pass grinding through 30 peers that could never work.
const MASQUE_H2_PROBE_LIMIT: usize = 4;

/// MASQUE gateway candidates, in dial order. Used by both transports.
///
/// This used to walk `consts::CDN_ANYCAST_POOL` — 104.16-104.28 and
/// 172.64-172.67 — which is Cloudflare's *website* CDN. Those edges complete TCP
/// and TLS happily and then either answer the connect-ip CONNECT with `400` or
/// accept the stream and never reply. That is exactly the `status 400` /
/// `h2 verify timeout` mixture the Iranian field logs showed across 30
/// consecutive peers, not one of which can ever serve MASQUE.
///
/// The gateways that do serve connect-ip live in `prober::MASQUE_CIDRS_V4`
/// (162.159.192-198, 172.65.251, 188.114.96-99) and are seeded by
/// `prober::MASQUE_SEEDS`. Dial the seeds first, then the head of each MASQUE
/// /24 — `masque_cidrs_v4()` already moves the Zero Trust range to the front
/// when `AETHER_TEAM` is set.
fn masque_gateway_peers() -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    for seed in prober::MASQUE_SEEDS {
        if let Ok(ip) = seed.parse::<Ipv4Addr>() {
            let peer = SocketAddr::new(IpAddr::V4(ip), consts::QUIC_PORT);
            if seen.insert(peer) {
                out.push(peer);
            }
        }
    }

    for cidr in prober::masque_cidrs_v4() {
        let network = cidr.split('/').next().unwrap_or(cidr);
        let Ok(base) = network.parse::<Ipv4Addr>() else {
            continue;
        };
        let o = base.octets();
        for host in [1u8, 2] {
            let ip = Ipv4Addr::new(o[0], o[1], o[2], host);
            let peer = SocketAddr::new(IpAddr::V4(ip), consts::QUIC_PORT);
            if seen.insert(peer) {
                out.push(peer);
            }
        }
    }

    out
}

async fn quick_verify_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    options: &StartOptions,
) -> Result<()> {
    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(options.masque_profile()),
        tls_curve_preset: options.tls_curve_preset,
        timeout: std::time::Duration::from_secs(5),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::L4_CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: false,
            expected_pins: Vec::new(),
        };
        masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(8)).await?;
        return Ok(());
    }

    quic::verify_masque(&vp).await?;
    Ok(())
}

/// What a single gateway attempt told us.
///
/// The distinction matters because the three failures in the field logs mean
/// completely different things and only one of them is worth retrying elsewhere:
///
///   * `masque: h2 connect-ip status 400` — TCP and TLS succeeded and a real
///     Cloudflare edge answered, refusing the CONNECT. The device certificate is
///     not valid for MASQUE. Trying another gateway cannot fix that.
///   * `other: h2 verify timeout` / `tls: ... reset by peer` — this peer does not
///     serve connect-ip, or the path to it is blocked. Move on.
enum PeerOutcome {
    Accepted,
    /// The edge answered and rejected our identity (4xx on the CONNECT).
    IdentityRejected,
    /// Transport-level failure: timeout, reset, TLS error.
    Unreachable,
}

/// Turn an identity-rejection count into the user-facing failure.
fn identity_rejected_error(count: u32) -> AetherError {
    crate::ffi::record_log(format!(
        "{count} gateways rejected this device certificate for MASQUE; \
         the WARP registration needs refreshing"
    ));
    AetherError::Masque(
        "MASQUE identity rejected by every gateway that answered; \
         re-register the WARP device"
            .to_string(),
    )
}

/// Result of dialling a whole candidate list with one transport.
enum PassOutcome {
    /// A gateway accepted the connect-ip CONNECT.
    Connected(SocketAddr),
    /// Enough gateways answered and refused the device certificate that the
    /// identity, not the peer list, is the problem. Carries the running count.
    IdentityRejected(u32),
    /// Every candidate failed at the transport level. Worth trying another way.
    Exhausted,
}

async fn dial_masque_pass(
    identity: &account::Identity,
    candidates: &[(SocketAddr, &'static str)],
    options: &StartOptions,
) -> PassOutcome {
    dial_masque_pass_from(identity, candidates, options, 0).await
}

/// Dial each candidate in order, carrying an identity-rejection count in from a
/// previous pass.
///
/// The count carries across transports on purpose: a 4xx on the CONNECT means
/// the edge read our client certificate and refused it, which no change of
/// transport or peer can fix.
async fn dial_masque_pass_from(
    identity: &account::Identity,
    candidates: &[(SocketAddr, &'static str)],
    options: &StartOptions,
    mut identity_rejections: u32,
) -> PassOutcome {
    for (peer, source) in candidates {
        match try_masque_peer(identity, *peer, source, options).await {
            PeerOutcome::Accepted => return PassOutcome::Connected(*peer),
            PeerOutcome::IdentityRejected => {
                identity_rejections += 1;
                if identity_rejections >= IDENTITY_REJECTED_LIMIT {
                    return PassOutcome::IdentityRejected(identity_rejections);
                }
            }
            PeerOutcome::Unreachable => {}
        }
    }

    if identity_rejections > 0 {
        PassOutcome::IdentityRejected(identity_rejections)
    } else {
        PassOutcome::Exhausted
    }
}

async fn try_known_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    source: &str,
    options: &StartOptions,
) -> bool {
    matches!(
        try_masque_peer(identity, peer, source, options).await,
        PeerOutcome::Accepted
    )
}

async fn try_masque_peer(
    identity: &account::Identity,
    peer: SocketAddr,
    source: &str,
    options: &StartOptions,
) -> PeerOutcome {
    let label = masque_transport_label();
    crate::ffi::record_log(format!("Trying {source} {peer} via {label}"));
    match quick_verify_masque_peer(identity, peer, options).await {
        Ok(()) => {
            crate::ffi::record_log(format!("Accepted {peer} via {label}"));
            PeerOutcome::Accepted
        }
        Err(error) => {
            crate::ffi::record_log(format!("Rejected {peer} via {label}: {error}"));
            if is_identity_rejection(&error) {
                PeerOutcome::IdentityRejected
            } else {
                PeerOutcome::Unreachable
            }
        }
    }
}

/// True when the edge answered the CONNECT with an *authorization* verdict.
///
/// Deliberately narrow: `401` and `403` only.
///
/// `400` used to count, which produced a false diagnosis. Probing every gateway
/// from a clean host with a freshly enrolled certificate showed that no
/// Cloudflare edge serves connect-ip over HTTP/2 at all — the real gateways
/// answer `RST_STREAM`, and every other address answers `400` no matter what is
/// sent, including a request carrying no client certificate. So a `400` says
/// nothing about our identity; treating it as one is what produced
/// "re-register the WARP device" while the certificate was in fact fine.
///
/// A `403` is different: over HTTP/3 the gateway returns it after accepting our
/// certificate at the TLS layer, so it is a genuine verdict on the identity or
/// on the requested protocol.
fn is_identity_rejection(error: &AetherError) -> bool {
    let text = error.to_string();
    let Some(rest) = text.split("connect-ip status ").nth(1) else {
        return false;
    };
    rest.split_whitespace()
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| matches!(code, 401 | 403))
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

/// How long to wait for a dialled gateway to accept CONNECT-IP before giving up
/// on it and reconnecting.
///
/// Measured, not guessed. This peer has already answered a pre-flight verify
/// inside `quick_verify_masque_peer`, whose own budget is 5 seconds; in the field
/// logs the verify that precedes a healthy tunnel completes in about 2 seconds,
/// and the tunnel that follows it reports `:status 200` in about the same time.
/// So a gateway that has said yes once and then stays silent for more than ~10
/// seconds is not slow, it is stuck.
///
/// The old 30-second budget turned that stall into 30 seconds of dead air
/// followed by a reconnect that succeeded on the first try — 40 seconds to
/// connect instead of 8. Ten seconds keeps a genuinely slow-but-working edge
/// while making the retry, which is the thing that actually works, arrive
/// three times sooner.
fn masque_startup_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode: prober::ScanMode,
    ip: prober::IpScan,
    options: &StartOptions,
) -> Result<SocketAddr> {
    log::info!("[*] hunting for a working MASQUE gateway (CONNECT-IP verification)");
    let ports = if masque_h2::enabled() {
        masque_h2_ports(prober::MASQUE_PORTS)
    } else {
        prober::MASQUE_PORTS.to_vec()
    };
    crate::ffi::record_log(format!(
        "Scanning MASQUE gateways via {} ({})",
        masque_transport_label(),
        mode.label()
    ));
    let probe = prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: None,
        noize: noize_config(options.masque_profile()),
        tls_curve_preset: options.tls_curve_preset,
        ports,
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    let best = match prober::hunt_best_gateway(&probe, mode).await {
        Ok(best) => best,
        Err(error) if !masque_h2::enabled() => {
            log::warn!(
                "[-] HTTP/3 found no MASQUE gateway ({error}); retrying HTTP/2 with TLS fragmentation"
            );
            crate::ffi::record_log(format!(
                "HTTP/3 scan found no gateway ({error}); retrying HTTP/2 with TLS fragmentation"
            ));
            enable_restricted_h2();
            let mut h2_probe = probe.clone();
            h2_probe.ports = masque_h2_ports(&probe.ports);
            crate::ffi::record_log("Checking Cloudflare CDN anycast for HTTP/2");
            if let Some(best) = prober::verify_cached_gateways(
                &h2_probe,
                masque_gateway_peers(),
            )
            .await
            {
                crate::ffi::record_log(format!(
                    "Selected {}:{} ({:?})",
                    best.ip, best.port, best.rtt
                ));
                return Ok(SocketAddr::new(best.ip, best.port));
            }
            crate::ffi::record_log("Scanning MASQUE gateways via HTTP/2 (balanced)");
            prober::hunt_best_gateway(&h2_probe, ScanMode::Balanced).await?
        }
        Err(error) => return Err(error),
    };
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    crate::ffi::record_log(format!(
        "Selected {}:{} ({:?})",
        best.ip, best.port, best.rtt
    ));
    Ok(SocketAddr::new(best.ip, best.port))
}

async fn run_masque(
    identity: account::Identity,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    lastconn_path: String,
    options: &StartOptions,
) -> Result<()> {
    let forced = options.forced_peer.map(|p| p.to_string());

    let mut quick_peer: Option<SocketAddr> = None;
    let mut known: Vec<(SocketAddr, &'static str)> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            if seen.insert(assigned) {
                known.push((assigned, "organization"));
            }
        }
        // Last working gateway first, ahead of the account endpoint.
        //
        // Device evidence from the first successful MASQUE connection: the
        // account-assigned 162.159.198.2 answered `:status 200` when probed from
        // a clean host but timed out from the carrier, and 162.159.198.1 carried
        // the session. Dialling the account peer first therefore costs a full
        // verify timeout on every subsequent connect while the address already
        // known to work on *this* network waits behind it.
        //
        // A gateway that worked here a moment ago is better evidence than one the
        // API named, so it leads.
        if options.endpoint_discovery == EndpointDiscovery::Cache {
            if let Some(cached) = lastconn::load(&lastconn_path) {
                if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                    if want_quick_reconnect(&cached).await && seen.insert(peer) {
                        known.push((peer, "last working"));
                    }
                }
            }
        }
        if let Some(assigned) = assigned_masque_peer(&identity) {
            if seen.insert(assigned) {
                known.push((assigned, "account"));
            }
        }
        if options.endpoint_discovery == EndpointDiscovery::Cache {
            for gateway in cached_masque_gateways(options) {
                if seen.insert(gateway) {
                    known.push((gateway, "cached"));
                }
            }
        }

        crate::ffi::record_log(format!(
            "MASQUE start via {} with {} known gateway(s)",
            masque_transport_label(),
            known.len()
        ));

        // Pass 1 — HTTP/3, the transport that actually works.
        //
        // Measured: the gateway answers `:status 200` to an extended CONNECT with
        // `:protocol = cf-connect-ip` over HTTP/3, and `RST_STREAM` over HTTP/2.
        // Previously this pass only dialled `known`, which was one address — the
        // WireGuard endpoint from registration (`104.16.192.82`, a website-CDN
        // host with no connect-ip listener) — so HTTP/3 was written off after a
        // single doomed attempt and the run spent its time in a fallback that
        // cannot succeed.
        let mut h3_candidates = known.clone();
        let mut h3_seen = seen.clone();
        for peer in masque_gateway_peers()
            .into_iter()
            .take(MASQUE_H3_PROBE_LIMIT)
        {
            if h3_seen.insert(peer) {
                h3_candidates.push((peer, "masque gateway"));
            }
        }

        let mut identity_rejections = 0u32;
        match dial_masque_pass(&identity, &h3_candidates, options).await {
            PassOutcome::Connected(peer) => quick_peer = Some(peer),
            PassOutcome::IdentityRejected(count) if count >= IDENTITY_REJECTED_LIMIT => {
                return Err(identity_rejected_error(count));
            }
            PassOutcome::IdentityRejected(count) => identity_rejections = count,
            PassOutcome::Exhausted => {}
        }

        // Pass 2 — HTTP/2 with TLS fragmentation, for networks that block UDP/443.
        if quick_peer.is_none() && !masque_h2::enabled() {
            crate::ffi::record_log(
                "HTTP/3 did not accept a known gateway; switching to HTTP/2 with TLS fragmentation",
            );
            enable_restricted_h2();
            for peer in masque_gateway_peers()
                .into_iter()
                .take(MASQUE_H2_PROBE_LIMIT)
            {
                if seen.insert(peer) {
                    known.push((peer, "masque gateway"));
                }
            }

            // Identity rejections carry over from the HTTP/3 pass: a 401/403 on
            // the CONNECT is a property of the certificate, not of the transport.
            match dial_masque_pass_from(&identity, &known, options, identity_rejections).await {
                PassOutcome::Connected(peer) => quick_peer = Some(peer),
                PassOutcome::IdentityRejected(count) => {
                    return Err(identity_rejected_error(count));
                }
                PassOutcome::Exhausted => {}
            }
        }
    }

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if try_known_masque_peer(&identity, p, "last good", options).await {
                        Some(p)
                    } else {
                        log::warn!(
                            "[-] last known-good gateway {p} no longer responds; rescanning"
                        );
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(p) => p,
                None => match &forced {
                    Some(p) => match p.parse::<SocketAddr>() {
                        Ok(peer) => {
                            log::info!("[+] using forced peer {peer} (probe skipped)");
                            peer
                        }
                        Err(_) => return Err(AetherError::Other(format!("bad peer address {p}"))),
                    },
                    None => match hunt_masque_peer(
                        &identity,
                        options.scan_mode,
                        options.ip_scan,
                        options,
                    )
                    .await
                    {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!(
                                "[-] no usable MASQUE gateway found: {e}; rescanning shortly"
                            );
                            crate::ffi::record_log(format!(
                                "No usable MASQUE gateway ({e}); retrying shortly"
                            ));
                            if !masque_h2::enabled() {
                                enable_restricted_h2();
                            }
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            let profile = options.masque_profile().to_string();
            lastconn::save(&lastconn_path, &peer.to_string(), &profile);
        }

        last_good_peer = Some(peer);

        let reconnect_detail =
            match run_masque_tunnel(&identity, peer, ech.clone(), listen, options).await {
                Ok(()) => "MASQUE tunnel closed; reconnecting".to_string(),
                Err(e) => format!("MASQUE tunnel ended: {e}; reconnecting"),
            };
        log::warn!("[-] {reconnect_detail}");
        crate::ffi::record_log(&reconnect_detail);

        crate::ffi::emit_status("connecting", Some(reconnect_detail));

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    options: &StartOptions,
) -> Result<()> {
    let (chans, internals) = quic::channels();

    let cfg = quic::TunnelConfig {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech,
        noize: noize_config(options.masque_profile()),
        tls_curve_preset: options.tls_curve_preset,
        local_ipv4: parse_local_v4(&identity.ipv4),
        quiet: false,
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;

    let _ctrl = ctrl_tx;

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let mut http_task = None;
    let local_task = if let Some(fd) = options.tun_fd {
        tokio::spawn(async move { while addr_rx.recv().await.is_some() {} });
        log::info!("[+] Android TUN bridge active");
        tokio::spawn(tun::bridge(
            fd,
            parse_local_v4(&identity.ipv4),
            inbound_rx,
            outbound_tx,
        ))
    } else {
        let stack = netstack::spawn(
            &identity.ipv4,
            &identity.ipv6,
            TUNNEL_MTU,
            inbound_rx,
            outbound_tx,
        )?;
        let bridge_stack = stack.clone();
        tokio::spawn(async move {
            while let Some(a) = addr_rx.recv().await {
                let res = match a.ip {
                    IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                    IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
                };
                if let Err(e) = res {
                    log::warn!("[-] failed to sync edge address into netstack: {e}");
                }
            }
        });
        http_task = spawn_http_proxy(&stack);
        tokio::spawn(async move {
            log::info!("[+] socks5 server listening on {listen}");
            socks::serve(listen, stack).await
        })
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::L4_CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: false,
            expected_pins: Vec::new(),
        };
        log::info!("[+] MASQUE transport: HTTP/2 (TCP) to {}", h2cfg.peer);
        tokio::spawn(masque_h2::run(
            h2cfg,
            internals,
            Some(addr_tx),
            Some(ready_tx),
        ))
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {}", peer);
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };

    let startup_timeout = masque_startup_timeout();
    let tunnel_result = match tokio::time::timeout(startup_timeout, ready_rx).await {
        Ok(Ok(())) => tunnel_task.await,
        Ok(Err(_)) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => "tunnel exited before validation".to_string(),
                Ok(Err(e)) => format!("tunnel failed before validation: {e}"),
                Err(e) => format!("tunnel task join error: {e}"),
            };
            local_task.abort();
            if let Some(task) = &http_task {
                task.abort();
            }
            return Err(AetherError::Other(msg));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            local_task.abort();
            if let Some(task) = &http_task {
                task.abort();
            }
            return Err(AetherError::Other(format!(
                "tunnel startup timed out after {:?}",
                startup_timeout
            )));
        }
    };

    local_task.abort();
    if let Some(task) = &http_task {
        task.abort();
    }

    match tunnel_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
        Err(e) => Err(AetherError::Other(format!("tunnel task join error: {e}"))),
    }
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates(
    primary: &str,
    manual: Option<&str>,
    retry_fallbacks: bool,
) -> Result<Vec<(String, aethernoize::AetherNoizeConfig)>> {
    if let Some(raw) = manual {
        let config = aethernoize::with_manual(primary, raw).map_err(AetherError::Other)?;
        return Ok(vec![("manual".to_string(), config)]);
    }
    let primary = primary.to_string();
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if retry_fallbacks {
        for fallback in ["balanced", "aggressive", "light", "off"] {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(fallback)) {
                names.push(fallback.to_string());
            }
        }
    }

    Ok(names
        .into_iter()
        .map(|n| {
            let cfg = aethernoize::from_profile(&n);
            (n, cfg)
        })
        .collect())
}

async fn hunt_wg_peer_with_profile(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    profile: aethernoize::AetherNoizeConfig,
    data_check: bool,
    excluded: &HashSet<SocketAddr>,
) -> Result<SocketAddr> {
    let mode = wg_prober::WgScanMode::parse(mode_str);
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id,
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: profile,
        data_check,
        ports: wireguard::WG_PORTS.to_vec(),
        ip,
        excluded: excluded.clone(),
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    Ok(SocketAddr::new(best.ip, best.port))
}

async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
    data_check: bool,
    excluded: &HashSet<SocketAddr>,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let multi = candidates.len() > 1;
    for (name, profile) in candidates {
        log::info!(
            "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='{name}')"
        );
        match hunt_wg_peer_with_profile(
            identity,
            mode_str,
            ip,
            profile.clone(),
            data_check,
            excluded,
        )
        .await
        {
            Ok(peer) => {
                log::info!(
                    "[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'"
                );
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(e) => {
                if multi {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}; trying next profile");
                } else {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}");
                }
            }
        }
    }
    Err(AetherError::NoCleanEndpoint)
}

fn wg_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
    options: &StartOptions,
) -> Result<()> {
    let candidates = wg_profile_candidates(
        options.wireguard_profile(),
        options.obfuscation_parameters.as_deref(),
        options.retry_obfuscation_profiles,
    )?;

    let forced = options.forced_peer.map(|p| p.to_string());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            for (name, profile) in &candidates {
                match wireguard::verify_endpoint(
                    assigned,
                    private_key,
                    peer_public,
                    identity.client_id,
                    ipv4,
                    profile,
                    options.wireguard_data_check,
                    std::time::Duration::from_secs(8),
                    None,
                )
                .await
                {
                    Ok(rtt) => {
                        log::info!(
                            "[+] the assigned endpoint {assigned} works with profile '{name}' (rtt {rtt:?}); skipping the scan"
                        );
                        quick = Some((assigned, profile.clone(), name.clone()));
                        break;
                    }
                    Err(e) => {
                        log::debug!(
                            "[-] assigned endpoint {assigned} failed profile '{name}': {e}"
                        );
                    }
                }
            }
            if quick.is_none() {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not pass validation; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick.is_none() && options.obfuscation_parameters.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let profile = aethernoize::from_profile(&cached.profile);
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        &profile,
                        options.wireguard_data_check,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!(
                                "[+] cached endpoint {peer} still works (rtt {:?}); skipping scan",
                                rtt
                            );
                            quick = Some((peer, profile, cached.profile.clone()));
                        }
                        Err(e) => {
                            log::warn!(
                                "[-] cached endpoint {peer} no longer works ({e}); scanning fresh"
                            );
                        }
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str().await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    let mut consecutive_fails_on_peer: u32 = 0;
    let mut endpoint_cooldowns: HashMap<SocketAddr, Instant> = HashMap::new();
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        let now = Instant::now();
        endpoint_cooldowns.retain(|_, until| *until > now);
        if consecutive_fails_on_peer >= MAX_CONSECUTIVE_FAILS {
            if let Some((peer, _, _)) = last_good.take() {
                let cooldown = wg_endpoint_cooldown();
                endpoint_cooldowns.insert(peer, now + cooldown);
                log::warn!(
                    "[-] endpoint {peer} failed {consecutive_fails_on_peer} times in a row; excluding it for {:?}",
                    cooldown
                );
            }
            consecutive_fails_on_peer = 0;
        }

        let (peer, profile, profile_name) = if let Some(q) = quick.take() {
            q
        } else {
            let retried = match &last_good {
                Some((p, profile, _)) => {
                    log::info!(
                        "[*] retrying last known-good WireGuard endpoint {p} before rescanning"
                    );
                    match wireguard::verify_endpoint(
                        *p,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        profile,
                        options.wireguard_data_check,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(_) => Some(last_good.clone().unwrap()),
                        Err(e) => {
                            log::warn!("[-] last known-good endpoint {p} no longer responds ({e}); rescanning");
                            None
                        }
                    }
                }
                None => None,
            };

            match retried {
                Some(v) => v,
                None => {
                    if let Some(ref p) = forced {
                        let peer: SocketAddr = p
                            .parse()
                            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!(
                                "[*] testing forced peer {peer} with aethernoize profile '{name}'"
                            );
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public,
                                identity.client_id,
                                ipv4,
                                profile,
                                options.wireguard_data_check,
                                std::time::Duration::from_secs(10),
                                None,
                            )
                            .await
                            {
                                Ok(rtt) => {
                                    log::info!(
                                        "[+] profile '{}' passed handshake + data-plane (rtt {:?})",
                                        name,
                                        rtt
                                    );
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("[-] profile '{name}' failed on forced peer: {e}");
                                }
                            }
                        }
                        match chosen {
                            Some(v) => v,
                            None => return Err(AetherError::NoCleanEndpoint),
                        }
                    } else {
                        let excluded: HashSet<SocketAddr> =
                            endpoint_cooldowns.keys().copied().collect();
                        match hunt_wg_peer(
                            &identity,
                            &candidates,
                            &mode_str,
                            ip,
                            options.wireguard_data_check,
                            &excluded,
                        )
                        .await
                        {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("[-] no usable WireGuard endpoint found: {e}; rescanning shortly");
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            lastconn::save(&lastconn_path, &peer.to_string(), &profile_name);
        }

        let is_same_peer_as_before = last_good.as_ref().map(|(p, _, _)| *p) == Some(peer);
        if !is_same_peer_as_before {
            consecutive_fails_on_peer = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen, options).await {
            Ok(()) => {
                log::warn!("[-] WireGuard tunnel closed; reconnecting");
                consecutive_fails_on_peer += 1;
            }
            Err(e) => {
                log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting");
                consecutive_fails_on_peer += 1;
            }
        }

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
    options: &StartOptions,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before exposing socks5...");
    // verify_endpoint_keep_session, not verify_endpoint: the session that proved
    // the data plane is the one that goes on to carry traffic.
    //
    // This is the WireGuard fake-Connected bug at the transport layer. The old
    // code validated with verify_endpoint (which drops its socket), then built the
    // live tunnel with WgTunnel::new(), which binds a *fresh* UDP socket on a
    // fresh source port and performs a fresh handshake that nothing checks. On
    // Hamrah-e-Aval the first flow gets through and the second does not — the
    // carrier treats the new 5-tuple differently — so validation passed, the core
    // reported connected, and the live socket carried nothing. MASQUE and Psiphon
    // were unaffected because neither rebuilds its transport after validating,
    // which is exactly why only WireGuard showed the fake connect.
    //
    // run_gool already did it this way (see the WoW path); WireGuard was the
    // outlier. Reusing the proven session also skips a second handshake, so
    // connect is marginally faster.
    let (validation_rtt, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &aethernoize,
        options.wireguard_data_check,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|e| AetherError::Other(format!("tunnel failed validation: {e}")))?;

    let ipv6: std::net::Ipv6Addr = identity
        .ipv6
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv6".into()))?;

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    // The original concern behind splitting these — "reusing the verifier's socket
    // reported ready before the Android TUN had a working data path" — was a
    // mark_ready() ordering problem, not a socket problem, and mark_ready now
    // fires after the bridge is spawned (below).
    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(aethernoize),
        inbound_tx,
        ipv4,
    );
    let _ = ipv6;
    log::info!("[+] WireGuard endpoint validated in {validation_rtt:?}; live transport ready");

    let mut http_task = None;
    let local_task = if let Some(fd) = options.tun_fd {
        log::info!("[+] Android TUN bridge active");
        tokio::spawn(tun::bridge(fd, ipv4, inbound_rx, outbound_tx))
    } else {
        let stack = netstack::spawn(
            &identity.ipv4,
            &identity.ipv6,
            TUNNEL_MTU,
            inbound_rx,
            outbound_tx,
        )?;
        http_task = spawn_http_proxy(&stack);
        tokio::spawn(async move {
            log::info!("[+] socks5 server listening on {listen}");
            socks::serve(listen, stack).await
        })
    };

    // mark_ready() emits "connected" to the app, so it must not fire until a data
    // path actually exists. It used to fire straight after validation, above —
    // before the TUN bridge was spawned — so the validated throwaway session was
    // reported as the live tunnel. On Hamrah-e-Aval that is a lie: validation
    // succeeds on its own socket, then WgTunnel::new() opens a *different* UDP
    // socket from a different source port for the real transport, and the carrier
    // does not let that second flow through. The app got "connected" for a tunnel
    // whose live socket never carried anything.
    //
    // Announcing after the bridge exists does not prove payload crosses — nothing
    // at this layer can, which is why the app runs its own verification gate — but
    // it does stop the core claiming ready for a session that has no data path at
    // all.
    crate::ffi::mark_ready();

    let tunnel_result = tunnel.run(outbound_rx).await;
    if let Some(task) = &http_task {
        task.abort();
    }
    local_task.abort();
    let _ = local_task.await;

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
    }
}

type TunnelExit = tokio::task::JoinHandle<Result<()>>;

fn http_proxy_listen() -> Option<SocketAddr> {
    let raw = std::env::var("AETHER_HTTP_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            log::warn!("[-] ignoring an unparsable http proxy address: {trimmed}");
            None
        }
    }
}

fn spawn_http_proxy(stack: &netstack::StackHandle) -> Option<TunnelExit> {
    let listen = http_proxy_listen()?;
    let stack = stack.clone();
    Some(tokio::spawn(async move {
        log::info!("[+] http proxy listening on {listen}");
        socks::serve_http(listen, stack).await
    }))
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
    data_check: bool,
) -> Result<(netstack::StackHandle, TunnelExit)> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let profile = if obfuscate {
        aethernoize_config(GOOL_OUTER_PROFILE)
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &profile,
        data_check,
        wg_tunnel_validate_timeout(),
        Some(keepalive),
    )
    .await
    .map_err(|e| AetherError::Other(format!("[{label}] tunnel failed validation: {e}")))?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(profile),
        inbound_tx,
        ipv4,
    );
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let exit = tokio::spawn(async move {
        match tunnel.run(outbound_rx).await {
            Ok(()) => {
                log::warn!("[-] [{label}] wireguard tunnel closed");
                Ok(())
            }
            Err(e) => {
                log::warn!("[-] [{label}] wireguard tunnel exited: {e}");
                Err(AetherError::Other(format!("[{label}] {e}")))
            }
        }
    });

    Ok((stack, exit))
}

struct ForwarderGuard(Vec<tokio::task::AbortHandle>);

impl Drop for ForwarderGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, ForwarderGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match up_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    *up_peer.lock().await = Some(from);
                    if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    let guard = ForwarderGuard(vec![up_task.abort_handle(), down_task.abort_handle()]);

    Ok((local, guard))
}

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
    options: &StartOptions,
) -> Result<()> {
    let mut last_peer: Option<SocketAddr> = None;
    let mut consecutive_fails: u32 = 0;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    // The outer endpoint that worked last time this identity connected, from a
    // previous run of the process.
    //
    // `last_peer` below only remembers within one run, so on Android — where the
    // core starts from scratch on every connect — it is always `None` and every
    // connect paid for a full scan. In the field that scan was 27 seconds, and it
    // was 27 seconds on all five connects in one night's log because the cost is
    // our own scan budget, not the network. MASQUE and plain WireGuard already
    // cache their peer this way; GOOL was the only protocol that did not.
    let mut cached_peer = if options.forced_peer.is_none() {
        load_cached_gool_peer(&lastconn_path, &primary, options).await
    } else {
        None
    };

    loop {
        let peer = if consecutive_fails < MAX_CONSECUTIVE_FAILS {
            if let Some(p) = last_peer.or(cached_peer) {
                Some(p)
            } else {
                None
            }
        } else {
            if let Some(p) = last_peer {
                log::warn!(
                    "[-] outer endpoint {p} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                );
            }
            // A blacklisted peer must not come back via the cache on the next
            // iteration of this loop.
            cached_peer = None;
            None
        };

        let peer = match peer {
            Some(p) => p,
            None => {
                let p = match select_peer(&primary, Protocol::WireGuard, options).await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!(
                            "[-] no usable outer WARP endpoint found: {e}; rescanning shortly"
                        );
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                };
                consecutive_fails = 0;
                p
            }
        };

        log::info!("[+] using cloudflare edge {peer} (outer)");
        if options.forced_peer.is_none() {
            // Saved before the tunnel is raised, not after: the outer endpoint has
            // already passed a handshake and data-plane check by this point, and
            // the call below only returns when the whole GOOL session ends. Waiting
            // for that would mean never recording a peer that worked for hours.
            lastconn::save(&lastconn_path, &peer.to_string(), GOOL_OUTER_PROFILE);
        }
        last_peer = Some(peer);

        match run_warp_in_warp(primary.clone(), secondary.clone(), peer, listen, options).await {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] gool tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails += 1;

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

/// Read back the last known-good outer endpoint and check it still works.
///
/// Verified rather than trusted. A cached address that has since been blocked
/// would otherwise be handed straight to `run_warp_in_warp`, which fails, comes
/// back through the loop, and only then scans — turning the shortcut into a
/// delay. The verify shares the budget `run_wireguard` uses for the same job.
async fn load_cached_gool_peer(
    lastconn_path: &str,
    primary: &account::Identity,
    options: &StartOptions,
) -> Option<SocketAddr> {
    let cached = lastconn::load(lastconn_path)?;
    let peer = cached.peer.parse::<SocketAddr>().ok()?;

    if !want_quick_reconnect(&cached).await {
        return None;
    }

    let private_key = primary.private_key_bytes().ok()?;
    let peer_public = primary.peer_public_key_bytes().ok()?;
    let ipv4: std::net::Ipv4Addr = primary.ipv4.parse().ok()?;

    log::info!("[*] verifying cached outer WARP endpoint {peer} before reuse");
    crate::ffi::record_log(format!("Checking last working gateway {peer}"));

    // Must match how `run_warp_in_warp` actually raises the outer tunnel —
    // `establish_wg(.., obfuscate = true, ..)` with the fixed `balanced` profile.
    // Verifying under different obfuscation settings would prove nothing about
    // the connection we are about to make.
    let profile = aethernoize_config(GOOL_OUTER_PROFILE);

    match wireguard::verify_endpoint(
        peer,
        private_key,
        peer_public,
        primary.client_id,
        ipv4,
        &profile,
        options.wireguard_data_check,
        std::time::Duration::from_secs(6),
        None,
    )
    .await
    {
        Ok(rtt) => {
            log::info!("[+] cached outer endpoint {peer} still works (rtt {rtt:?}); skipping scan");
            crate::ffi::record_log(format!("Reusing gateway {peer} — scan skipped"));
            Some(peer)
        }
        Err(e) => {
            log::warn!("[-] cached outer endpoint {peer} no longer works ({e}); scanning fresh");
            crate::ffi::record_log("Last gateway is gone; scanning for a new one");
            None
        }
    }
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    listen: SocketAddr,
    options: &StartOptions,
) -> Result<()> {
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) = establish_wg(
        &primary,
        peer,
        TUNNEL_MTU,
        true,
        5,
        "outer",
        options.wireguard_data_check,
    )
    .await?;

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let mut http_task = None;
    let (mut inner_exit, mut local_task): (TunnelExit, TunnelExit) = if let Some(fd) =
        options.tun_fd
    {
        log::info!("[+] Android TUN bridge active for inner WARP tunnel");
        let secondary_private_key = secondary.private_key_bytes()?;
        let secondary_peer_public = secondary.peer_public_key_bytes()?;
        let secondary_ipv4: std::net::Ipv4Addr = secondary
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

        let profile = aethernoize::from_profile("off");
        log::info!(
            "[*] [inner] validating WireGuard tunnel with {forwarder} (handshake + data-plane)..."
        );
        let (_, session) = wireguard::verify_endpoint_keep_session(
            forwarder,
            secondary_private_key,
            secondary_peer_public,
            secondary.client_id,
            secondary_ipv4,
            &profile,
            options.wireguard_data_check,
            wg_tunnel_validate_timeout(),
            Some(20),
        )
        .await
        .map_err(|e| AetherError::Other(format!("[inner] tunnel failed validation: {e}")))?;
        log::info!("[+] [inner] wireguard tunnel validated (end-to-end data confirmed)");

        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(sysprofile::channel_capacity());

        let tunnel = wireguard::WgTunnel::from_established(
            session,
            std::sync::Arc::new(profile),
            inbound_tx,
            secondary_ipv4,
        );

        let inner_exit = tokio::spawn(async move {
            tunnel
                .run(outbound_rx)
                .await
                .map_err(|e| AetherError::Other(format!("[inner] {e}")))
        });
        let local_task =
            tokio::spawn(tun::bridge(fd, secondary_ipv4, inbound_rx, outbound_tx));
        (inner_exit, local_task)
    } else {
        let (inner_stack, inner_exit) = establish_wg(
            &secondary,
            forwarder,
            INNER_MTU,
            false,
            20,
            "inner",
            options.wireguard_data_check,
        )
        .await?;
        log::info!("[+] socks5 server listening on {listen}");
        http_task = spawn_http_proxy(&inner_stack);
        let local_task = tokio::spawn(async move { socks::serve(listen, inner_stack).await });
        (inner_exit, local_task)
    };

    crate::ffi::mark_ready();

    let outcome = tokio::select! {
        result = &mut outer_exit => join_outcome("outer wireguard tunnel", result),
        result = &mut inner_exit => join_outcome("inner wireguard tunnel", result),
        result = &mut local_task => join_outcome("local tunnel bridge", result),
    };

    if let Some(task) = &http_task {
        task.abort();
    }
    outer_exit.abort();
    inner_exit.abort();
    local_task.abort();

    let _ = outer_exit.await;
    let _ = inner_exit.await;
    let _ = local_task.await;

    drop(outer_stack);

    outcome
}

fn join_outcome(
    what: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!("{what} stopped"))),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => Err(AetherError::Other(format!("{what} was cancelled"))),
        Err(e) => Err(AetherError::Other(format!("{what} panicked: {e}"))),
    }
}

/// PSIPHON mode: bridge Android TUN → upstream SOCKS5 proxy (tun2socks).
async fn run_psiphon(
    upstream: &str,
    _listen: SocketAddr,
    options: &StartOptions,
) -> Result<()> {
    let upstream_addr: SocketAddr = upstream
        .parse()
        .map_err(|e| AetherError::Other(format!("invalid upstream proxy {upstream}: {e}")))?;

    let tun_fd = options.tun_fd
        .ok_or_else(|| AetherError::Other("psiphon mode requires a TUN fd".into()))?;

    log::info!("[+] PSIPHON tun2socks: TUN fd={tun_fd} → upstream SOCKS5 {upstream_addr}");
    crate::ffi::emit_status("connected", None);

    crate::socks_upstream::serve(upstream_addr, tun_fd).await
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

async fn select_scan_mode_str() -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let zero_trust = match team_scope() {
            Some(team) => format!("  [4] Zero Trust: signed in to {team}, pick another team\n"),
            None => "  [4] Zero Trust: sign in to an organization (WARP for teams)\n".to_string(),
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n{zero_trust}\
             Choose [1-4] (default 1): "
        ))
        .await;

        match answer.as_deref() {
            Some("2") => return Protocol::WireGuard,
            Some("3") => return Protocol::WarpInWarp,
            Some("4") => {
                enrol_zero_trust(base).await;
                continue;
            }
            _ => return Protocol::Masque,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
    Psiphon,
}

impl Protocol {
    pub fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            "psiphon" => Protocol::Psiphon,
            _ => Protocol::Masque,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
            Protocol::Psiphon => "Psiphon",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok() || std::env::var("AETHER_PEER").is_ok() {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

const MAX_CACHED_MASQUE_GATEWAYS: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedMasqueGateway {
    ip: String,
    port: u16,
    rtt_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MasqueGatewayCache {
    gateways: Vec<CachedMasqueGateway>,
}

fn cached_masque_gateways(options: &StartOptions) -> Vec<SocketAddr> {
    let Some(path) = options.endpoint_cache_path.as_deref() else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(cache) = serde_json::from_str::<MasqueGatewayCache>(&contents) else {
        return Vec::new();
    };
    cache
        .gateways
        .into_iter()
        .filter_map(|entry| {
            entry
                .ip
                .parse::<IpAddr>()
                .ok()
                .map(|ip| (ip, entry.port, entry.rtt_ms))
        })
        .filter(|(ip, _, _)| {
            (ip.is_ipv4() && options.ip_scan.want_v4())
                || (ip.is_ipv6() && options.ip_scan.want_v6())
        })
        .take(MAX_CACHED_MASQUE_GATEWAYS)
        .map(|(ip, port, _)| SocketAddr::new(ip, port))
        .collect()
}

fn cache_masque_gateway(options: &StartOptions, gateway: prober::ProbeResult) {
    let Some(path) = options.endpoint_cache_path.as_deref() else {
        return;
    };
    let mut cache = fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str::<MasqueGatewayCache>(&contents).ok())
        .unwrap_or_default();
    cache
        .gateways
        .retain(|entry| !(entry.ip == gateway.ip.to_string() && entry.port == gateway.port));
    cache.gateways.push(CachedMasqueGateway {
        ip: gateway.ip.to_string(),
        port: gateway.port,
        rtt_ms: gateway.rtt.as_millis().min(u128::from(u64::MAX)) as u64,
    });
    cache.gateways.sort_by_key(|entry| entry.rtt_ms);
    cache.gateways.truncate(MAX_CACHED_MASQUE_GATEWAYS);
    let Some(parent) = Path::new(path).parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_vec(&cache) {
        let temporary = format!("{path}.tmp");
        if fs::write(&temporary, json).is_ok() {
            let _ = fs::rename(temporary, path);
        }
    }
}

/// How many cached gateways are enough that topping the cache up is not worth
/// its cost.
///
/// The cache only has to hold a few alternates for the next connect to have
/// something to try before it falls back to a full scan. Past that, another
/// scan buys nothing.
const MASQUE_CACHE_WARM_ENOUGH: usize = 4;

/// Whether the gateway cache is thin enough to be worth a background top-up.
///
/// Split out from [`spawn_masque_cache_refresh`] so the decision is testable
/// without a tokio runtime.
fn masque_cache_needs_refresh(options: &StartOptions) -> bool {
    cached_masque_gateways(options).len() < MASQUE_CACHE_WARM_ENOUGH
}

/// Top the gateway cache up once in the background, then stop.
///
/// Once — not on a loop. This used to be `loop { hunt_best_gateway(Stealth);
/// sleep(15s) }`, which on a phone means a ~900-candidate QUIC scan with real
/// handshakes (up to a 180s budget) restarting every 15 seconds for the entire
/// life of the tunnel. The radio therefore never got an idle window, which is
/// the most expensive shape of background work on a phone: measured in the
/// field at 37% of battery for this app while a plain proxy client on the same
/// device stayed under 10%.
///
/// Stopping costs nothing on the data path. This cache is read only when
/// *choosing* which gateway to dial, never while a tunnel is running, so it
/// does not need re-deriving while connected — and the gateway actually in use
/// is already written to it by `cache_masque_gateway` on every connect. Its one
/// job is to give the next connect a warm list, and a single pass does that.
fn spawn_masque_cache_refresh(probe: prober::MasqueProbe, cache_path: Option<String>) {
    let Some(path) = cache_path else { return };
    // Mirror the probe's address family so counting and filtering agree.
    let options = StartOptions {
        endpoint_cache_path: Some(path),
        ip_scan: probe.ip,
        ..StartOptions::new(Protocol::Masque, String::new())
    };

    if !masque_cache_needs_refresh(&options) {
        log::debug!("[masque] gateway cache already warm; skipping background top-up");
        return;
    }

    tokio::spawn(async move {
        crate::ffi::record_log("Topping up the MASQUE gateway cache in the background");
        if let Ok(gateway) = prober::hunt_best_gateway(&probe, ScanMode::Stealth).await {
            cache_masque_gateway(&options, gateway);
            crate::ffi::record_log(format!("Cached gateway {}:{}", gateway.ip, gateway.port));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_options_have_app_safe_defaults() {
        let options = StartOptions::new(Protocol::Masque, "/data/user/0/app/files/aether.toml");

        assert_eq!(options.listen, "127.0.0.1:1819".parse().unwrap());
        assert_eq!(options.scan_mode, ScanMode::Balanced);
        assert_eq!(options.ip_scan, IpScan::V4);
        assert_eq!(options.masque_profile(), "firewall");
        assert!(options.forced_peer.is_none());
        assert_eq!(options.endpoint_discovery, EndpointDiscovery::Cache);
    }

    #[test]
    fn cached_masque_gateways_are_persisted_and_filtered_by_ip_family() {
        let path = std::env::temp_dir().join(format!("aether-cache-{}.json", std::process::id()));
        let mut options = StartOptions::new(Protocol::Masque, "aether.toml");
        options.endpoint_cache_path = Some(path.to_string_lossy().into_owned());

        cache_masque_gateway(
            &options,
            prober::ProbeResult {
                ip: "162.159.198.1".parse().unwrap(),
                port: 443,
                rtt: Duration::from_millis(20),
            },
        );
        cache_masque_gateway(
            &options,
            prober::ProbeResult {
                ip: "2606:4700:d0::a29f:c602".parse().unwrap(),
                port: 443,
                rtt: Duration::from_millis(10),
            },
        );

        assert_eq!(
            cached_masque_gateways(&options),
            vec!["162.159.198.1:443".parse().unwrap()]
        );
        options.ip_scan = IpScan::Both;
        assert_eq!(cached_masque_gateways(&options).len(), 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn prepare_addresses_drop_cidr_suffixes() {
        assert_eq!(address_host("172.16.0.2/32"), "172.16.0.2");
        assert_eq!(address_host("2606:4700:110:8877::2/128"), "2606:4700:110:8877::2");
        assert_eq!(address_host(""), "");
    }

    /// GOOL's endpoint cache is a separate file from plain WireGuard's.
    ///
    /// Both store an endpoint found with the same WARP identity, but WireGuard
    /// records the obfuscation profile that worked and varies it across retries,
    /// while GOOL's outer tunnel is always `balanced`. One shared file would let
    /// each protocol reuse a peer the other validated under settings it never uses.
    #[test]
    fn gool_keeps_its_own_endpoint_cache() {
        let config = "/data/user/0/app/files/aether.toml";

        assert_eq!(
            gool_lastconn_path(config),
            "/data/user/0/app/files/aether-gool-lastconn.toml"
        );
        assert_ne!(gool_lastconn_path(config), lastconn_path(config));
    }

    /// The cache file must not be mistaken for an enrolled Zero Trust team.
    ///
    /// `enrolled_teams` lists every `<stem>-team-*.toml` sibling and filters out
    /// bookkeeping files by suffix. A new sibling that slipped past that filter
    /// would show up in the team picker as a team named after the cache.
    #[test]
    fn the_gool_cache_is_not_read_back_as_a_team() {
        let team_config = "/data/user/0/app/files/aether-team-acme.toml";
        let cache = gool_lastconn_path(team_config);

        let name = cache.rsplit('/').next().unwrap();
        let team = name
            .strip_prefix("aether-team-")
            .and_then(|rest| rest.strip_suffix(".toml"))
            .expect("cache sits beside the team config");

        assert!(team.ends_with("-lastconn"), "got {team}");
    }

    /// GOOL's outer tunnel stays obfuscated.
    ///
    /// The cached-peer verify and `establish_wg` both resolve this constant, so a
    /// value naming no real profile would not desynchronise them — `from_profile`
    /// falls through to `balanced` for anything unrecognised. What it *would* do
    /// is silently disable obfuscation if it were ever set to `off` or `none`,
    /// which on an Iranian carrier is the difference between a tunnel and a
    /// blocked handshake. That is the case worth pinning.
    #[test]
    fn the_gool_outer_tunnel_stays_obfuscated() {
        assert!(aethernoize::from_profile(GOOL_OUTER_PROFILE).is_enabled());
        assert_ne!(GOOL_OUTER_PROFILE, "off");
        assert_ne!(GOOL_OUTER_PROFILE, "none");
    }

    /// The background cache top-up runs once, not forever.
    ///
    /// The refresh used to loop with a 15s sleep for the life of the tunnel,
    /// each pass a full Stealth scan (~900 QUIC handshake candidates, 180s
    /// budget), so the radio never got an idle window — the field report was 37%
    /// of battery. Guarding on a warm cache is what makes the top-up bounded:
    /// once the cache holds a few alternates there is nothing left to fetch, and
    /// the connect that just succeeded has already written its own gateway in.
    #[test]
    fn a_warm_gateway_cache_needs_no_background_scan() {
        let path = std::env::temp_dir().join(format!("aether-warm-{}.json", std::process::id()));
        let mut options = StartOptions::new(Protocol::Masque, "aether.toml");
        options.endpoint_cache_path = Some(path.to_string_lossy().into_owned());
        let _ = fs::remove_file(&path);

        // Empty cache: the next connect would have nothing to try, so scan.
        assert!(masque_cache_needs_refresh(&options));

        for host in 1..=MASQUE_CACHE_WARM_ENOUGH {
            cache_masque_gateway(
                &options,
                prober::ProbeResult {
                    ip: format!("162.159.198.{host}").parse().unwrap(),
                    port: 443,
                    rtt: Duration::from_millis(20),
                },
            );
        }

        assert!(
            !masque_cache_needs_refresh(&options),
            "a cache holding {MASQUE_CACHE_WARM_ENOUGH} gateways must not trigger another scan"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn assigned_masque_peer_accepts_host_or_socket() {
        let mut identity = account::Identity {
            device_id: "device".into(),
            access_token: "token".into(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            cert_issued_at: 0,
            ipv4: "172.16.0.2".into(),
            ipv6: String::new(),
            wg_private_key: [0u8; 32],
            wg_peer_public_key: [0u8; 32],
            client_id: [0u8; 3],
            organization: String::new(),
            gateway_proxy: String::new(),
            assigned_endpoint: "104.16.192.82".into(),
            refused: false,
        };
        assert_eq!(
            assigned_masque_peer(&identity),
            Some("104.16.192.82:443".parse().unwrap())
        );
        identity.assigned_endpoint = "162.159.198.139:8443".into();
        assert_eq!(
            assigned_masque_peer(&identity),
            Some("162.159.198.139:8443".parse().unwrap())
        );
        identity.assigned_endpoint.clear();
        assert_eq!(assigned_masque_peer(&identity), None);
    }

    #[test]
    fn http2_fallback_ports_keep_443_first() {
        let ports = masque_h2_ports(prober::MASQUE_PORTS);
        assert_eq!(ports.first(), Some(&443));
        assert!(ports.contains(&2053));
        assert!(ports.contains(&8880));
    }

    #[test]
    fn http2_anycast_peers_only_target_real_masque_gateways() {
        let peers = masque_gateway_peers();

        // 162.159.198.2 leads: it is the only address measured answering
        // :status 200 to connect-ip, and the one the account API assigns once a
        // MASQUE key is enrolled.
        assert_eq!(peers.first(), Some(&"162.159.198.2:443".parse().unwrap()));
        assert_eq!(peers.get(1), Some(&"162.159.198.1:443".parse().unwrap()));

        // Every /24 in the MASQUE list contributes its .1 and .2.
        assert!(peers.contains(&"162.159.192.1:443".parse().unwrap()));
        assert!(peers.contains(&"188.114.96.2:443".parse().unwrap()));
        assert!(peers.contains(&"172.65.251.1:443".parse().unwrap()));

        // The website CDN ranges must never be dialled for connect-ip: those
        // edges answer 400 or hang, which is what wasted two minutes per attempt
        // in the field logs.
        for peer in &peers {
            let text = peer.to_string();
            assert!(
                !text.starts_with("104."),
                "website CDN peer {text} must not be a MASQUE candidate"
            );
            assert!(
                !text.starts_with("172.64.")
                    && !text.starts_with("172.66.")
                    && !text.starts_with("172.67."),
                "website CDN peer {text} must not be a MASQUE candidate"
            );
        }
    }

    /// The gateway the enrollment response names must win over the stale
    /// WireGuard endpoint from registration.
    #[test]
    fn masque_enrollment_adopts_the_gateway_it_returns() {
        let identity = account::Identity {
            device_id: "device".into(),
            access_token: "token".into(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            cert_issued_at: 0,
            ipv4: "172.16.0.2".into(),
            ipv6: String::new(),
            wg_private_key: [0u8; 32],
            wg_peer_public_key: [0u8; 32],
            client_id: [0u8; 3],
            organization: String::new(),
            gateway_proxy: String::new(),
            // What /reg hands back: a WireGuard endpoint on the website CDN.
            assigned_endpoint: "104.16.192.82".into(),
            refused: false,
        };

        let enrolled = apply_masque_enrollment(
            identity.clone(),
            account::MasqueEnrollment {
                cert_pem: b"cert".to_vec(),
                key_pem: b"key".to_vec(),
                issued_at: 42,
                renewed: true,
                assigned_endpoint: "162.159.198.2".into(),
            },
        );
        assert_eq!(enrolled.assigned_endpoint, "162.159.198.2");
        assert_eq!(enrolled.cert_issued_at, 42);
        assert_eq!(
            assigned_masque_peer(&enrolled),
            Some("162.159.198.2:443".parse().unwrap())
        );

        // No endpoint in the response: keep whatever we already had.
        let unchanged = apply_masque_enrollment(
            identity,
            account::MasqueEnrollment {
                cert_pem: b"cert".to_vec(),
                key_pem: b"key".to_vec(),
                issued_at: 7,
                renewed: false,
                assigned_endpoint: String::new(),
            },
        );
        assert_eq!(unchanged.assigned_endpoint, "104.16.192.82");
    }

    /// A 400 must not be read as an identity verdict: every non-MASQUE Cloudflare
    /// edge answers 400 to connect-ip over HTTP/2 even with no client certificate,
    /// so counting it produced a bogus "re-register the WARP device".
    #[test]
    fn only_401_and_403_count_as_identity_rejections() {
        assert!(is_identity_rejection(&AetherError::Other(
            "connect-ip status 403".to_string()
        )));
        assert!(is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 401".to_string()
        )));

        assert!(!is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 400".to_string()
        )));
        assert!(!is_identity_rejection(&AetherError::Other(
            "connect-ip status 404".to_string()
        )));
        assert!(!is_identity_rejection(&AetherError::Other(
            "closed before data-plane confirmation".to_string()
        )));
    }

    /// The HTTP/2 request must carry the pseudo-header set extended CONNECT needs.
    #[test]
    fn h2_connect_request_is_an_extended_connect() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: "162.159.198.2:443".parse().unwrap(),
            sni: consts::CONNECT_SNI.to_string(),
            authority: "cloudflareaccess.com".to_string(),
            path: "/".to_string(),
            cert_pem: b"cert".to_vec(),
            key_pem: b"key".to_vec(),
            local_ipv4: "172.16.0.2".parse().unwrap(),
            quiet: true,
            pin_endpoint: false,
            expected_pins: Vec::new(),
        };

        let request = masque_h2::connect_request_for_test(&cfg).expect("request builds");
        assert_eq!(request.method(), http::Method::CONNECT);

        // Without this extension the h2 crate drops :protocol, :scheme and :path.
        let protocol = request
            .extensions()
            .get::<h2::ext::Protocol>()
            .expect(":protocol must be set for extended CONNECT");
        assert_eq!(protocol.as_str(), consts::CF_CONNECT_PROTOCOL);

        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().authority().map(|a| a.as_str()), Some("cloudflareaccess.com"));
        assert_eq!(request.uri().path(), "/");
        assert_eq!(
            request.headers().get("capsule-protocol").map(|v| v.as_bytes()),
            Some(&b"?1"[..])
        );
    }

    #[test]
    fn identity_rejection_is_distinguished_from_transport_failure() {
        // 400 is NOT an identity verdict, and this is the whole point of the
        // function: every non-gateway Cloudflare address answers 400 regardless
        // of what is sent, including requests with no client certificate at all.
        // Counting it as an identity rejection is what produced spurious
        // "re-register the WARP device" advice while the certificate was fine.
        // This assertion had it backwards and never ran — the test profile did
        // not compile, so nothing caught the contradiction with is_identity_rejection.
        assert!(!is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 400".to_string()
        )));
        assert!(is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 403".to_string()
        )));
        // 401 is the other genuine verdict on the identity.
        assert!(is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 401".to_string()
        )));
        // 5xx is the edge failing, not our certificate.
        assert!(!is_identity_rejection(&AetherError::Masque(
            "h2 connect-ip status 502".to_string()
        )));
        assert!(!is_identity_rejection(&AetherError::Other(
            "h2 verify timeout".to_string()
        )));
        assert!(!is_identity_rejection(&AetherError::Tls(
            "h2 tls handshake: Connection reset by peer".to_string()
        )));
        // The HTTP/3 path words it without the "h2" prefix; a real verdict there
        // must still count, otherwise a 403 over QUIC looks like a transport
        // failure and the run keeps dialling peers that all refuse the same
        // certificate.
        assert!(is_identity_rejection(&AetherError::Other(
            "connect-ip status 403".to_string()
        )));
    }

    #[test]
    // Same property as the test above, over the L4 CONNECT SNI and the default
    // authority/path rather than the cloudflareaccess.com pair. Renamed because
    // two tests shared one name, which is a hard compile error in the test
    // profile — the whole crate's tests could not build.
    fn h2_connect_request_over_l4_sni_is_an_extended_connect() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: "162.159.196.1:443".parse().unwrap(),
            sni: consts::L4_CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            local_ipv4: "172.16.0.2".parse().unwrap(),
            quiet: true,
            pin_endpoint: false,
            expected_pins: Vec::new(),
        };

        let request = masque_h2::connect_request_for_test(&cfg).expect("request builds");

        // Without :protocol the h2 crate drops :scheme and :path, which is what
        // made every gateway answer 400.
        assert_eq!(
            request
                .extensions()
                .get::<h2::ext::Protocol>()
                .map(|p| p.as_str()),
            Some(consts::CF_CONNECT_PROTOCOL)
        );
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().host(), Some(quic::default_authority()));
        assert_eq!(request.uri().path(), "/");
        assert_eq!(
            request.headers().get("capsule-protocol").map(|v| v.as_bytes()),
            Some(b"?1".as_ref())
        );
    }
}
