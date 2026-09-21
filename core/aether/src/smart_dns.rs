use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::{AetherError, Result};

/// Gemini domains that must route through anti-sanction DNS
const GEMINI_DOMAINS: &[&str] = &[
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "alkalinetransmit-pa.googleapis.com",
    "bard.google.com",
    "proactivity-pa.googleapis.com",
];

/// Anti-sanction DNS servers (Plain UDP, port 53)
const ANTI_SANCTION_DNS: &[&str] = &[
    "10.202.10.202",   // 403.online
    "10.202.10.102",   // 403.online
    "78.157.42.100",   // Electro
    "78.157.42.101",   // Electro
    "178.22.122.100",  // Shecan
    "185.51.200.2",    // Shecan
];

/// Default fast DNS (Cloudflare/Google) for non-Gemini traffic
const DEFAULT_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "9.9.9.9",
];

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_CONCURRENT_QUERIES: usize = 32;

/// The synthetic DNS address advertised to Android — RethinkDNS's trick: instead
/// of listening on a port the OS cannot reach, advertise a fake resolver IP and
/// intercept every packet bound for it in the TUN bridge. This makes the split
/// engine the authoritative resolver for the device without a userspace server.
pub const FAKE_DNS_V4: &str = "10.111.222.53";

/// Cached DNS response
#[derive(Clone)]
struct CachedResponse {
    data: Vec<u8>,
    expires: Instant,
}

/// Resolver transport: plain UDP, DNS-over-TLS, or DNS-over-HTTPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsTransport {
    Plain,
    Dot,
    Doh,
}

/// A single resolver endpoint with its transport.
#[derive(Clone, Debug)]
pub struct DnsEndpoint {
    /// Plain: "1.2.3.4". DoT: "dns.example.com". DoH: the full URL.
    pub address: String,
    pub transport: DnsTransport,
    /// TLS SNI / authority for DoT and DoH.
    pub name: Option<String>,
}

impl DnsEndpoint {
    /// Parse a user-supplied DNS entry. Accepts:
    ///   1.2.3.4                            -> plain UDP
    ///   1.2.3.4:53                         -> plain UDP with explicit port
    ///   tls://dns.example.com              -> DoT on :853
    ///   https://dns.example.com/dns-query  -> DoH
    ///   doh:dns.example.com                -> DoH at /dns-query
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let lower = raw.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("https://").or_else(|| lower.strip_prefix("doh://")) {
            let host = host_of(rest);
            return Some(DnsEndpoint {
                address: format!("https://{rest}"),
                transport: DnsTransport::Doh,
                name: Some(host.to_string()),
            });
        }
        if let Some(rest) = lower.strip_prefix("tls://").or_else(|| lower.strip_prefix("dot://")) {
            let (host, _port) = split_host_port(rest, 853);
            return Some(DnsEndpoint {
                address: host.to_string(),
                transport: DnsTransport::Dot,
                name: Some(host.to_string()),
            });
        }
        if let Some(rest) = lower.strip_prefix("doh:") {
            let (host, _port) = split_host_port(rest, 443);
            return Some(DnsEndpoint {
                address: format!("https://{host}/dns-query"),
                transport: DnsTransport::Doh,
                name: Some(host.to_string()),
            });
        }
        if let Some(rest) = lower.strip_prefix("dot:") {
            let (host, _port) = split_host_port(rest, 853);
            return Some(DnsEndpoint {
                address: host.to_string(),
                transport: DnsTransport::Dot,
                name: Some(host.to_string()),
            });
        }
        // Plain UDP, with or without a port. Reject anything URL-ish.
        let (host, _port) = split_host_port(raw, u16::from(DNS_PORT));
        if host.contains("://") || host.contains('/') || host.is_empty() {
            return None;
        }
        Some(DnsEndpoint {
            address: host.to_string(),
            transport: DnsTransport::Plain,
            name: None,
        })
    }

    /// Port the user wrote into `address`, if any.
    fn explicit_port(&self) -> Option<u16> {
        match self.transport {
            DnsTransport::Plain | DnsTransport::Dot => host_port(&self.address),
            DnsTransport::Doh => url_port(&self.address),
        }
    }
}

/// Split "host" / "host:port", defaulting the port when absent.
fn split_host_port(raw: &str, default_port: u16) -> (&str, u16) {
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
            return (host, port.unwrap_or(default_port));
        }
    }
    match raw.matches(':').count() {
        0 => (raw, default_port),
        1 => {
            let (h, p) = raw.rsplit_once(':').unwrap();
            (h, p.parse().unwrap_or(default_port))
        }
        _ => (raw, default_port), // bare v6, no port
    }
}

/// Port of a bare host:port string, if a port is present.
fn host_port(raw: &str) -> Option<u16> {
    if raw.starts_with('[') {
        return raw
            .find(']')
            .and_then(|end| raw[end + 1..].strip_prefix(':'))
            .and_then(|p| p.parse().ok());
    }
    if raw.matches(':').count() == 1 {
        return raw.rsplit_once(':').and_then(|(_, p)| p.parse().ok());
    }
    None
}

/// Port inside an https:// URL, if present.
fn url_port(raw: &str) -> Option<u16> {
    let after_scheme = raw.strip_prefix("https://").or_else(|| raw.strip_prefix("http://"))?;
    let end = after_scheme
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    host_port(&after_scheme[..end])
}

/// The authority of a URL-ish string, minus path/query and user:pass@.
fn host_of(urlish: &str) -> &str {
    let end = urlish
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(urlish.len());
    let authority = &urlish[..end];
    authority.rsplit('@').next().unwrap_or(authority)
}

/// Smart DNS Split Engine
///
/// Clone is cheap: every field is an Arc, so cloning the engine shares the same
/// sockets and the same resolver lists rather than duplicating them. The clone
/// is what lets process_query() take the engine out of the global RwLock and
/// hold it across an .await without keeping the lock locked.
#[derive(Clone)]
pub struct SmartDnsSplit {
    /// In-memory cache for responses (RAM only)
    cache: Arc<RwLock<HashMap<Vec<u8>, CachedResponse>>>,
    /// Limits concurrent queries
    semaphore: Arc<Semaphore>,
    /// Anti-sanction DNS sockets (pre-connected, plain UDP)
    anti_sanction_sockets: Arc<Vec<Arc<UdpSocket>>>,
    /// Default DNS sockets (pre-connected, plain UDP)
    default_sockets: Arc<Vec<Arc<UdpSocket>>>,
    /// DoT/DoH endpoints. When non-empty, the encrypted path is preferred.
    encrypted_resolvers: Arc<RwLock<Vec<DnsEndpoint>>>,
    /// The user's own resolvers (any transport), set from `smart_dns_servers`.
    /// The engine prefers these for Gemini lookups — the whole point of the
    /// Custom DNS setting.
    user_resolvers: Arc<RwLock<Vec<DnsEndpoint>>>,
}

impl SmartDnsSplit {
    /// Create a new Smart DNS Split engine.
    pub async fn new() -> Result<Self> {
        let mut anti_sanction_sockets = Vec::new();
        let mut default_sockets = Vec::new();

        for server in ANTI_SANCTION_DNS {
            let addr: SocketAddr = format!("{server}:{DNS_PORT}").parse()
                .map_err(|e| AetherError::Other(format!("Invalid anti-sanction DNS {server}: {e}")))?;
            let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await
                .map_err(AetherError::Io)?;
            sock.connect(addr).await.map_err(AetherError::Io)?;
            // Per-socket protect, RethinkDNS pattern #5. The anti-sanction
            // resolvers are Iranian private-space addresses (10.202.10.x,
            // 78.157.42.x). They are only routable from the carrier network, so
            // their queries must ride OUTSIDE the tunnel. Sending them through
            // the VPN exit — which is what removing protect() did in 8b4e76a —
            // makes them unroutable and every Gemini lookup fails. Public
            // resolvers below take the tunnel instead, because plain 53 is
            // hijacked or poisoned on the carrier.
            #[cfg(target_os = "android")]
            {
                if let Err(e) = crate::platform::protect_socket(&sock) {
                    log::warn!("[smart-dns] protect({server}) failed: {e}");
                }
            }
            anti_sanction_sockets.push(Arc::new(sock));
        }

        for server in DEFAULT_DNS {
            let addr: SocketAddr = format!("{server}:{DNS_PORT}").parse()
                .map_err(|e| AetherError::Other(format!("Invalid default DNS {server}: {e}")))?;
            let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await
                .map_err(AetherError::Io)?;
            sock.connect(addr).await.map_err(AetherError::Io)?;
            // Public resolvers must ride the tunnel: on Iranian carriers plain 53
            // to 1.1.1.1 is hijacked and poisoned. Not protected on purpose.
            default_sockets.push(Arc::new(sock));
        }

        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
            anti_sanction_sockets: anti_sanction_sockets.into(),
            default_sockets: default_sockets.into(),
            encrypted_resolvers: Arc::new(RwLock::new(Vec::new())),
            user_resolvers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Replace the DoT/DoH resolver set. Picked up live, no reconnect needed.
    pub fn set_encrypted_resolvers(&self, endpoints: Vec<DnsEndpoint>) {
        let mut guard = self.encrypted_resolvers.write();
        guard.clear();
        guard.extend(endpoints);
        log::info!("[smart-dns] encrypted resolvers updated: {} endpoint(s)", guard.len());
    }

    pub fn has_encrypted(&self) -> bool {
        !self.encrypted_resolvers.read().is_empty()
    }

    /// Check if a domain is a Gemini domain (exact or subdomain match)
    fn is_gemini_domain(name: &str) -> bool {
        let name = name.to_lowercase();
        GEMINI_DOMAINS.iter().any(|d| name == *d || name.ends_with(&format!(".{d}")))
    }

    /// Build a DNS query packet
    fn build_query(name: &str, qtype: u16) -> (Vec<u8>, u16) {
        let id = rand::random::<u16>();
        let mut q = Vec::with_capacity(32 + name.len());
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
        q.extend_from_slice(&[0x00, 0x01]); // 1 question
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in name.split('.') {
            if label.is_empty() { continue; }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0x00);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // class IN
        (q, id)
    }

    /// Check if response matches our query
    fn response_matches(resp: &[u8], expected_id: u16, expected_name: &str, expected_qtype: u16) -> bool {
        if resp.len() < 12 { return false; }
        if u16::from_be_bytes([resp[0], resp[1]]) != expected_id { return false; }
        if resp[2] & 0x80 == 0 { return false; } // not a response
        if u16::from_be_bytes([resp[4], resp[5]]) != 1 { return false; } // not 1 question

        let mut pos = 12;
        for label in expected_name.split('.') {
            if label.is_empty() { continue; }
            let len = match resp.get(pos) { Some(v) => *v as usize, None => return false };
            if len != label.len() { return false; }
            pos += 1;
            let end = match pos.checked_add(len) { Some(v) if v <= resp.len() => v, _ => return false };
            if !resp[pos..end].eq_ignore_ascii_case(label.as_bytes()) { return false; }
            pos = end;
        }
        if pos + 5 > resp.len() { return false; }
        let qtype = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
        qtype == expected_qtype
    }

    /// Query multiple plain-UDP servers in parallel; first answer wins.
    async fn parallel_query(&self, sockets: Arc<Vec<Arc<UdpSocket>>>, query: Vec<u8>, expected_id: u16, name: String, qtype: u16) -> Result<Vec<u8>> {
        let permit = self.semaphore.acquire().await.map_err(|_| AetherError::Other("semaphore closed".into()))?;

        let mut handles = Vec::new();
        let query = Arc::new(query);
        let name = Arc::new(name);
        for sock in sockets.iter().cloned() {
            let query = query.clone();
            let name = name.clone();
            handles.push(tokio::spawn(async move {
                let deadline = Instant::now() + QUERY_TIMEOUT;
                sock.send(&query).await.ok()?;
                let mut buf = [0u8; 4096];
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() { return None; }
                    let n = timeout(remaining, sock.recv(&mut buf)).await.ok()?.ok()?;
                    let resp = &buf[..n];
                    if Self::response_matches(resp, expected_id, &name, qtype) {
                        return Some(resp.to_vec());
                    }
                }
            }));
        }

        let mut result = None;
        for handle in handles {
            if let Ok(Some(resp)) = handle.await {
                result = Some(resp);
                break;
            }
        }
        drop(permit);

        result.ok_or_else(|| AetherError::Other("All DNS queries failed".into()))
    }

    /// Query the user's own plain-UDP endpoints in parallel.
    /// Sockets are opened on the spot — the user's list can change at runtime —
    /// and each socket is protected (kept outside the tunnel) when its target is
    /// a private address, since private IPs are unroutable through the tunnel.
    async fn query_endpoints(&self, endpoints: &[DnsEndpoint], query: Vec<u8>, expected_id: u16, name: String, qtype: u16) -> Result<Vec<u8>> {
        let mut socks: Vec<Arc<UdpSocket>> = Vec::with_capacity(endpoints.len());
        for ep in endpoints {
            let addr = format!("{}:53", ep.address);
            let bind_addr = if ep.address.parse::<std::net::IpAddr>().map(|i| i.is_ipv4()).unwrap_or(true) { "0.0.0.0:0" } else { "[::]:0" };
            match UdpSocket::bind(bind_addr).await {
                Ok(sock) => {
                    let sock = Arc::new(sock);
                    // Only private resolvers (e.g. the Iranian 10.202.10.x /
                    // 78.157.42.x ranges) must be kept outside the tunnel — they
                    // are unroutable through it. Public resolvers must stay
                    // inside, otherwise the local network blocks them outright.
                    let is_private = ep.address
                        .parse::<std::net::IpAddr>()
                        .map(|ip| match ip {
                            std::net::IpAddr::V4(v4) => v4.is_private(),
                            std::net::IpAddr::V6(v6) => {
                                let seg = v6.segments();
                                (seg[0] & 0xfe00) == 0xfc00 // unique-local fd00::/8
                            }
                        })
                        .unwrap_or(false);
                    if is_private {
                        crate::platform::protect_socket(&sock);
                    }
                    if let Err(e) = sock.connect(addr).await {
                        log::warn!("[smart-dns] user resolver {} unreachable: {e}", ep.address);
                        continue;
                    }
                    socks.push(sock);
                }
                Err(e) => log::warn!("[smart-dns] bind for {} failed: {e}", ep.address),
            }
        }
        if socks.is_empty() {
            return Err(AetherError::Other("no user resolver socket could be opened".into()));
        }
        log::info!("[smart-dns] querying {} user resolver(s) for {name} (type {qtype})", socks.len());
        self.parallel_query(Arc::new(socks), query, expected_id, name, qtype).await
    }

    /// Resolve a hostname to IP addresses using the engine's OWN protected
    /// plain-UDP sockets — never the tunnel, never the system resolver.
    ///
    /// This exists because encrypted_query() must not look up its own server's
    /// hostname through the system: on Android the app's unprotected sockets
    /// route into the TUN, so that lookup would re-enter process_query() and
    /// recurse forever (the log shows 201 queries seen and zero answers, and
    /// neither the success nor the failure line — the future never completed).
    /// Resolving via the protected sockets breaks that loop.
    async fn resolve_host_out_of_band(&self, host: &str) -> Result<Vec<std::net::IpAddr>> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(vec![ip]);
        }
        let mut out = Vec::new();
        // A and AAAA, in that order; IPv4 first because the tunnel path is
        // v4-heavy and the carrier blocks nothing here — these sockets are
        // outside the tunnel by construction.
        //
        // The anti-sanction resolvers (10.202.10.x / Shecan / Electro) are only
        // reachable from inside Iran. Abroad they time out, and resolving the
        // DoH server's own hostname would then fail for a reason that has
        // nothing to do with the DoH server. Fall through to the public
        // defaults, which work everywhere.
        for qtype in [1u16, 28u16] {
            let (query, new_id) = Self::build_query(host, qtype);
            let resp = match self
                .parallel_query(self.anti_sanction_sockets.clone(), query.clone(), new_id, host.to_string(), qtype)
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    log::info!("[smart-dns] anti-sanction resolvers failed for {host}; trying public defaults");
                    self.parallel_query(self.default_sockets.clone(), query, new_id, host.to_string(), qtype).await?
                }
            };
            out.extend(Self::parse_answers(&resp, qtype));
        }
        if out.is_empty() {
            return Err(AetherError::Other(format!("no address for {host}")));
        }
        Ok(out)
    }

    /// Pull A/AAAA records out of a DNS response.
    fn parse_answers(resp: &[u8], qtype: u16) -> Vec<std::net::IpAddr> {
        if resp.len() < 12 { return vec![]; }
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
        // Skip the question section.
        let mut pos = 12;
        while pos < resp.len() {
            let len = resp[pos];
            if len == 0 { pos += 1; break; }
            if len & 0xC0 == 0xC0 { pos += 2; break; }
            pos += 1 + len as usize;
        }
        pos += 4; // qtype + qclass
        let mut out = Vec::new();
        for _ in 0..ancount {
            if pos >= resp.len() { break; }
            // Name: possibly a pointer back into the question.
            if resp[pos] & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                while pos < resp.len() && resp[pos] != 0 { pos += 1 + resp[pos] as usize; }
                pos += 1;
            }
            if pos + 10 > resp.len() { break; }
            let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
            let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > resp.len() { break; }
            if rtype == qtype {
                match (rtype, rdlen) {
                    (1, 4) => out.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]))),
                    (28, 16) => {
                        let mut s = [0u8; 16];
                        s.copy_from_slice(&resp[pos..pos + 16]);
                        out.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(s)));
                    }
                    _ => {}
                }
            }
            pos += rdlen;
        }
        out
    }

    /// Resolve over DoT/DoH. Preferred over plain UDP when configured — it is the
    /// only path that survives a network which hijacks port 53.
    async fn encrypted_query(&self, domain: &str, qtype: u16) -> Result<Vec<u8>> {
        let endpoints = self.encrypted_resolvers.read().clone();
        if endpoints.is_empty() {
            return Err(AetherError::Other("no encrypted resolvers".into()));
        }
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let name = Name::from_utf8(domain)
            .map_err(|e| AetherError::Other(format!("invalid name {domain}: {e}")))?;
        let mut message = Message::new();
        message.set_id(rand::random::<u16>());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(Query::query(name, RecordType::from(qtype)));
        let query_bytes = message.to_vec()
            .map_err(|e| AetherError::Other(format!("encode query: {e}")))?;

        let mut last_err = String::new();
        for ep in &endpoints {
            let attempt = match ep.transport {
                DnsTransport::Dot => self.dot_query(ep, &query_bytes).await,
                DnsTransport::Doh => self.doh_query(ep, &query_bytes).await,
                DnsTransport::Plain => continue,
            };
            match attempt {
                Ok(resp) => {
                    // A well-formed reply is enough; the resolver already framed it.
                    if hickory_proto::op::Message::from_vec(&resp).is_err() {
                        last_err = format!("bad response from {}", ep.address);
                        continue;
                    }
                    log::info!("[smart-dns] {} answered over {:?} for {}", ep.address, ep.transport, domain);
                    return Ok(resp);
                }
                Err(e) => last_err = format!("{}: {e}", ep.address),
            }
        }
        Err(AetherError::Other(format!("all encrypted resolvers failed: {last_err}")))
    }

    async fn dot_query(&self, ep: &DnsEndpoint, query: &[u8]) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port = ep.explicit_port().unwrap_or(853);
        // Resolve out of band (see doh_query): tokio's TcpStream::connect would
        // resolve the hostname via the system resolver, which on Android rides
        // the TUN and re-enters process_query() for this same hostname.
        let addrs = self.resolve_host_out_of_band(&ep.address).await?;
        let addr = addrs.into_iter().next()
            .ok_or_else(|| AetherError::Other(format!("dot: no address for {}", ep.address)))?;
        let mut stream = tokio::net::TcpStream::connect((addr, port))
            .await
            .map_err(AetherError::Io)?;
        // Two-byte length prefix, per RFC 1035 §4.2.2.
        let len = u16::try_from(query.len())
            .map_err(|_| AetherError::Other("DoT query too long".to_string()))?;
        stream.write_all(&len.to_be_bytes()).await.map_err(AetherError::Io)?;
        stream.write_all(query).await.map_err(AetherError::Io)?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.map_err(AetherError::Io)?;
        let resp_len = usize::from(u16::from_be_bytes(len_buf));
        let mut buf = vec![0u8; resp_len];
        stream.read_exact(&mut buf).await.map_err(AetherError::Io)?;
        Ok(buf)
    }

    async fn doh_query(&self, ep: &DnsEndpoint, query: &[u8]) -> Result<Vec<u8>> {
        // DoH as an HTTP POST with application/dns-message. reqwest already
        // speaks rustls, so no second TLS stack enters the binary.
        let url = if ep.address.starts_with("https://") {
            ep.address.clone()
        } else {
            format!("https://{}/dns-query", ep.address)
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|e| AetherError::Other(format!("doh url {url}: {e}")))?;
        let host = parsed.host_str()
            .ok_or_else(|| AetherError::Other(format!("doh url {url} has no host")))?;

        // Resolve the DoH server's own hostname OUT OF BAND. reqwest would
        // otherwise use the system resolver, which on Android routes into the
        // TUN and re-enters process_query() for this very hostname — the
        // recursion is why a configured DoH server produced zero answers in the
        // field. ClientBuilder::resolve() overrides only the address lookup; it
        // leaves the URL, the SNI and the Host header on the real hostname, so
        // Cloudflare Workers still route correctly.
        let addrs = self.resolve_host_out_of_band(host).await?;
        let ip = addrs.into_iter().next()
            .ok_or_else(|| AetherError::Other(format!("doh: no address for {host}")))?;
        // ClientBuilder::resolve() takes a SocketAddr, not an IpAddr. The port
        // is the one from the URL (443 unless the user overrode it).
        let port = parsed.port_or_known_default()
            .ok_or_else(|| AetherError::Other(format!("doh url {url} has no port")))?;
        let sock_addr = std::net::SocketAddr::new(ip, port);

        let client = reqwest::Client::builder()
            .timeout(QUERY_TIMEOUT)
            .resolve(host, sock_addr)
            .build()
            .map_err(|e| AetherError::Other(format!("doh client: {e}")))?;
        let resp = client
            .post(&url)
            .header("content-type", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
            .map_err(|e| AetherError::Other(format!("doh send: {e}")))?;
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AetherError::Other(format!("doh body: {e}")))
    }

    /// Process a DNS query from the TUN.
    /// Returns (response_data, is_gemini); None lets the query take the tunnel's
    /// normal path untouched.
    pub async fn process_query(&self, packet: &[u8], ihl: usize) -> Option<(Vec<u8>, bool)> {
        if packet.len() < ihl + 8 { return None; }
        let udp = &packet[ihl..];
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        if dst_port != DNS_PORT || udp.len() <= 8 { return None; }

        let payload = &udp[8..];
        if payload.len() < 12 { return None; }

        let mut pos = 12;
        let mut labels = Vec::new();
        loop {
            if pos >= payload.len() { return None; }
            let len = payload[pos];
            if len == 0 { pos += 1; break; }
            if len & 0xC0 == 0xC0 { return None; } // compression not expected in a query
            pos += 1;
            if pos + len as usize > payload.len() { return None; }
            labels.push(String::from_utf8_lossy(&payload[pos..pos + len as usize]).to_string());
            pos += len as usize;
        }
        if pos + 4 > payload.len() { return None; }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);

        let domain = labels.join(".");
        let is_gemini = Self::is_gemini_domain(&domain);
        let has_encrypted = self.has_encrypted();

        // Diagnostic: without this the engine looks dead when it is merely
        // receiving nothing. The field log showed init + ready but zero
        // per-query lines, which was indistinguishable from "queries never
        // arrive at the TUN" and "queries arrive but the parser rejects them".
        log::info!(
            "[smart-dns] qtype={qtype} name={domain} gemini={is_gemini} encrypted={has_encrypted} len={}",
            payload.len()
        );

        // v2.0.5: the old AI Mode gate is gone, but the engine still must not
        // answer a query it has no reason to. tun::bridge only CALLS
        // process_query when has_encrypted() is true, so reaching here means the
        // user configured DoT/DoH. The two branches below preserve that: the
        // encrypted path is preferred, and if it fails the plain fallbacks only
        // run when the engine was actually answering this query for the user.
        // A query that is neither Gemini nor has an encrypted resolver behind it
        // returns None and takes the tunnel's own normal path.
        if !has_encrypted && !is_gemini {
            return None;
        }

        let mut cache_key = Vec::new();
        cache_key.extend_from_slice(&[0, 0]); // placeholder for the transaction ID
        cache_key.extend_from_slice(&payload[2..]);

        {
            let cached = {
                let cache = self.cache.read();
                cache.get(&cache_key).and_then(|c| {
                    if c.expires > Instant::now() { Some(c.data.clone()) } else { None }
                })
            };
            if let Some(mut resp) = cached {
                if resp.len() >= 2 && payload.len() >= 2 {
                    resp[0] = payload[0];
                    resp[1] = payload[1];
                }
                return Some((resp, true));
            }
        }

        // Prefer DoT/DoH when configured — plain 53 is hijacked on many networks.
        if self.has_encrypted() {
            match self.encrypted_query(&domain, qtype).await {
                Ok(resp) => {
                    let mut to_cache = resp.clone();
                    if to_cache.len() >= 2 && payload.len() >= 2 {
                        to_cache[0] = payload[0];
                        to_cache[1] = payload[1];
                    }
                    {
                        let mut cache = self.cache.write();
                        if cache.len() > 1024 { cache.clear(); }
                        cache.insert(cache_key, CachedResponse {
                            data: to_cache,
                            expires: Instant::now() + CACHE_TTL,
                        });
                    }
                    return Some((resp, true));
                }
                Err(e) => log::warn!("[smart-dns] encrypted query for {domain} failed ({e}); falling back to UDP"),
            }
        }

        let (query, new_id) = Self::build_query(&domain, qtype);

        // Prefer the user's own resolvers when configured — that is the entire
        // point of the Custom DNS setting. Fall back to the built-in
        // anti-sanction list, then to the public defaults.
        let user = self.user_resolvers.read().clone();
        let plain_user: Vec<_> = user
            .iter()
            .filter(|e| e.transport == DnsTransport::Plain)
            .cloned()
            .collect();
        if !plain_user.is_empty() {
            match self.query_endpoints(&plain_user, query.clone(), new_id, domain.clone(), qtype).await {
                Ok(resp) => {
                    let mut to_cache = resp.clone();
                    if to_cache.len() >= 2 && payload.len() >= 2 {
                        to_cache[0] = payload[0];
                        to_cache[1] = payload[1];
                    }
                    {
                        let mut cache = self.cache.write();
                        if cache.len() > 1024 { cache.clear(); }
                        cache.insert(cache_key.clone(), CachedResponse {
                            data: to_cache,
                            expires: Instant::now() + CACHE_TTL,
                        });
                    }
                    return Some((resp, true));
                }
                Err(e) => log::warn!("[smart-dns] user resolvers failed for {domain} ({e}); falling back"),
            }
        }

        let query2 = query.clone();

        let (response, used_anti_sanction) = match self
            .parallel_query(self.anti_sanction_sockets.clone(), query.clone(), new_id, domain.clone(), qtype)
            .await
        {
            Ok(resp) => (resp, true),
            Err(_) => {
                match self
                    .parallel_query(self.default_sockets.clone(), query, new_id, domain, qtype)
                    .await
                {
                    Ok(resp) => (resp, false),
                    Err(_) => return Some((Self::build_error_response(&query2, new_id), true)),
                }
            }
        };

        {
            let mut cache = self.cache.write();
            if cache.len() > 1024 { cache.clear(); }
            cache.insert(cache_key, CachedResponse {
                data: response.clone(),
                expires: Instant::now() + CACHE_TTL,
            });
        }

        Some((response, used_anti_sanction))
    }

    /// Build a minimal DNS error response (SERVFAIL)
    fn build_error_response(query: &[u8], id: u16) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[0..2].copy_from_slice(&id.to_be_bytes());
        resp[2] = 0x81; // response + error
        resp[3] = 0x02; // SERVFAIL
        resp
    }
}

/// Global instance holder.
///
/// A RwLock, not a OnceCell: a OnceCell keeps the FIRST engine ever built, so a
/// user who connects MASQUE and then WireGuard would be stuck with the first
/// session's resolvers and its protect()-bound sockets. The Option inside keeps
/// the "not yet initialised" state the OnceCell expressed, and writing a new
/// engine drops the old one, which is what every transport switch needs.
static SMART_DNS: parking_lot::RwLock<Option<SmartDnsSplit>> = parking_lot::RwLock::new(None);

/// Initialize the global Smart DNS engine
pub async fn init_smart_dns() -> Result<()> {
    log::info!(
        "[smart-dns] standing up Smart DNS Split ({} anti-sanction UDP + DoT/DoH)",
        ANTI_SANCTION_DNS.len()
    );
    let engine = SmartDnsSplit::new().await?;
    *SMART_DNS.write() = Some(engine);
    log::info!("[smart-dns] engine ready: plain-UDP sockets up, DoT/DoH on demand");
    Ok(())
}

/// Run [f] with the current engine, if there is one. Holds the read lock for
/// the call, so the engine cannot be replaced underneath [f].
fn with_engine<R>(f: impl FnOnce(&SmartDnsSplit) -> R) -> Option<R> {
    SMART_DNS.read().as_ref().map(f)
}

/// Get whether the engine is up and has encrypted resolvers configured.
pub fn has_encrypted() -> bool {
    with_engine(|e| e.has_encrypted()).unwrap_or(false)
}

/// Hand a DNS packet to the engine. Returns the engine's answer, if it has one.
pub async fn process_query(packet: &[u8], ihl: usize) -> Option<(Vec<u8>, bool)> {
    // The engine's own fields are all Arc inside, so cloning the packet and
    // moving it into a 'static future is enough — no lock needs to be held
    // across the await.
    // .as_ref() first: cloning the guard itself does not compile (the guard
    // is !Clone), so dereference to the Option and clone the engine inside.
    let engine = SMART_DNS.read().as_ref().cloned()?;
    engine.process_query(packet, ihl).await
}

/// Replace the engine's resolver list at runtime. Called after
/// init_smart_dns() once the user's `smart_dns_servers` string has been parsed.
/// Plain-UDP entries are kept for the engine's own resolution path (Gemini
/// lookups) AND are already handed to Android by applyDns(); encrypted entries
/// are spoken by the core alone. Mirrors RethinkDNS's updateTun: reconfigure
/// without tearing the tunnel down.
pub fn set_resolvers(resolvers: Vec<DnsEndpoint>) {
    // Same as above: clone the Option's contents, never the guard.
    let engine = match SMART_DNS.read().as_ref().cloned() {
        Some(e) => e,
        None => {
            log::warn!("[smart-dns] set_resolvers called before init_smart_dns — ignored");
            return;
        }
    };
    // code paths. encrypted_resolvers is what encrypted_query() reads and
    // what has_encrypted() gates on — the "prefer DoT/DoH when configured"
    // branch above. Storing everything in user_resolvers alone leaves that
    // gate permanently false, so a user who filled the DoH field would
    // still be answered by plain UDP, silently.
    let encrypted: Vec<_> = resolvers
        .iter()
        .filter(|e| e.transport != DnsTransport::Plain)
        .cloned()
        .collect();
    {
        let mut enc = engine.encrypted_resolvers.write();
        enc.clear();
        enc.extend(encrypted);
    }
    let count = resolvers.len();
    let mut guard = engine.user_resolvers.write();
    guard.clear();
    guard.extend(resolvers);
    log::info!("[smart-dns] resolvers updated: {count} endpoint(s) from user list");
}
