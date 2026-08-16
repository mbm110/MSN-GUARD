mod account;
mod aethernoize;
mod apifront;
mod cli;
mod config;
mod consts;
mod dns;
pub mod error;
mod exitip;
pub(crate) mod ffi;
mod fragment;
mod lastconn;
mod masque;
mod masque_h2;
mod netstack;
mod noize;
pub mod platform;
mod prober;
mod quic;
mod routing;
mod socks;
pub(crate) mod socks_upstream;
mod sysprofile;
mod tls;
mod tun;
mod tunnelping;
mod wg_prober;
mod wireguard;
mod zerotrust;

#[path = "main.rs"]
mod app;

pub use app::{
    initialize, prepare, run_cli, start, EndpointDiscovery, IpScan, MasqueTransport, Protocol,
    ScanMode, StartOptions, TlsCurvePreset, TunnelAddresses,
};
pub use platform::{set_socket_protector, SocketProtector};
