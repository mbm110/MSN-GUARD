pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

pub const ECH_PUBLIC_NAME: &str = "cloudflare-ech.com";

pub const DEFAULT_MODEL: &str = "PC";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";

pub const UA_REGISTER: &str = "WARP for Android";
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

pub const ALPN_H3: &[u8] = b"h3";

pub const CF_CONNECT_PROTOCOL: &str = "cf-connect-ip";

pub const H3_DATAGRAM_00: u64 = 0x276;

pub const CONNECT_IP_CONTEXT_ID: u64 = 0;

pub const CDN_ANYCAST_POOL: &[&str] = &[
    "104.16.0.0",
    "104.17.0.0",
    "104.18.0.0",
    "104.19.0.0",
    "104.20.0.0",
    "104.21.0.0",
    "104.22.0.0",
    "104.24.0.0",
    "104.25.0.0",
    "104.26.0.0",
    "104.27.0.0",
    "104.28.0.0",
    "172.64.0.0",
    "172.65.0.0",
    "172.66.0.0",
    "172.67.0.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0",
];

pub const QUIC_PORT: u16 = 443;
