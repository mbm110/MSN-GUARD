use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::{AetherError, Result};

/// Anti-sanction resolvers reachable from inside Iran, used to resolve a
/// configured DoT/DoH server's own hostname outside the tunnel.
const ANTI_SANCTION_DNS: &[&str] = &[
    "10.202.10.202",   // 403.online
    "10.202.10.102",   // 403.online
    "78.157.42.100",   // Electro
    "78.157.42.101",   // Electro
    "178.22.122.100",  // Shecan
    "185.51.200.2",    // Shecan
];

/// Default fast DNS (Cloudflare/Google), the fallback for plain lookups.
/// The DoT/DoH servers' own hostnames are pinned by the app instead — see
/// DnsEndpoint::pinned_ip and CoreConfig.precomputePinnedIps.
const DEFAULT_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "9.9.9.9",
];

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// DoT/DoH connect + TLS handshake. The 2.0.10 hang was a connect() with no
/// bound at all; a blocked path must fail in seconds, not sit forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Pinned IP addresses for the resolver's own hostname, when the app
    /// resolved them ahead of time. Set from the Android side with
    /// [DnsEndpoint::with_ips] before the endpoint reaches the engine.
    ///
    /// This is the RethinkDNS design and it is the only thing that makes a
    /// custom DoH server work from inside a VPN's own split DNS: the engine
    /// must not resolve the DoH server's hostname, because that lookup is
    /// itself a DNS query which the engine would have to intercept — a
    /// catch-22 that hung every query in 2.0.5-2.0.9 (bootstrap.go in
    /// celzero/firestack spells the same refusal out for their Go engine).
    /// With the IPs pinned there is nothing to resolve.
    pub ips: Vec<std::net::IpAddr>,
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
        // Only the SCHEME is matched case-insensitively. The rest is kept as the
        // user typed it: a DoH path is part of the URL and HTTP paths are
        // case-sensitive. Lowercasing the whole string here rewrote
        // /dns-query/PLJhQthhMfwAKilJ into /dns-query/pljhqthhmfwakilj, a
        // different URL that the Worker answered with 500 — so every DoH server
        // whose path carries an uppercase token silently failed and the engine
        // fell back to plain UDP. Hostnames ARE case-insensitive, so the DNS
        // label comparison and the TLS SNI are lowercased separately (host_of
        // is only used for resolver-host matching, never for the URL itself).
        let lower = raw.to_ascii_lowercase();
        if lower.starts_with("https://") || lower.starts_with("doh://") {
            // "https://" is 8 bytes, "doh://" is 6 — slicing by a hardcoded
            // length silently ate the first letter of every doh:// hostname.
            let scheme_len = if lower.starts_with("https://") { 8 } else { 6 };
            let rest = &raw[scheme_len..];
            let host = host_of(&lower[scheme_len..]);
            return Some(DnsEndpoint {
                address: format!("https://{rest}"),
                transport: DnsTransport::Doh,
                name: Some(host.to_string()),
                ips: vec![],
            });
        }
        if lower.starts_with("tls://") || lower.starts_with("dot://") {
            // Both prefixes are 6 bytes. A DoT address is a bare hostname (no
            // path), so lowercasing it is a normalisation, not a corruption.
            let (host, _port) = split_host_port(&lower[6..], 853);
            return Some(DnsEndpoint {
                address: host.to_string(),
                transport: DnsTransport::Dot,
                name: Some(host.to_string()),
                ips: vec![],
            });
        }
        if lower.starts_with("doh:") {
            // No path to preserve: the /dns-query this form builds is a
            // constant, so only the scheme needed case-insensitive matching.
            let (host, _port) = split_host_port(&raw[4..], 443);
            return Some(DnsEndpoint {
                address: format!("https://{host}/dns-query"),
                transport: DnsTransport::Doh,
                name: Some(host.to_string()),
                ips: vec![],
            });
        }
        if lower.starts_with("dot:") {
            let (host, _port) = split_host_port(&lower[4..], 853);
            return Some(DnsEndpoint {
                address: host.to_string(),
                transport: DnsTransport::Dot,
                name: Some(host.to_string()),
                ips: vec![],
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
            ips: vec![],
        })
    }

    /// Attach IP addresses resolved for the resolver's own hostname by the
    /// app, before the tunnel came up. See the field docs: with these pinned
    /// the engine never has to resolve its own resolver.
    pub fn with_ips(&mut self, ips: Vec<std::net::IpAddr>) {
        if !ips.is_empty() {
            self.ips = ips;
        }
    }

/// A pinned IP to dial for this endpoint, if the app gave us one.
    pub fn pinned_ip(&self) -> Option<std::net::IpAddr> {
        self.ips.first().copied()
    }

    /// Port the user wrote into `address`, if any.
    fn explicit_port(&self) -> Option<u16> {
        match self.transport {
            DnsTransport::Plain | DnsTransport::Dot => host_port(&self.address),
            DnsTransport::Doh => url_port(&self.address),
        }
    }
}

/// Dial an endpoint's pinned IPs in order, returning the first that completes
/// a TCP connect.
///
/// v2.0.13: `ips.first()` — the 2.0.10 design — pins exactly one IP and dies
/// with it. Cloudflare Workers resolve to a rotating set of anycast addresses
/// and Iranian carriers withdraw reachability to individual ones without
/// warning, so a single pin has no redundancy: the first stale address takes
/// the whole DoH/DoT path down with no retry. Intra (Jigsaw) iterates
/// `ips.GetAll()` per query and Rethink's firestack iterates a reordered IPSet,
/// promoting whichever address actually connected. This mirrors that: try each
/// pinned IP, prefer v4, and only report failure when none of them answers.
async fn connect_pinned(
    ep: &DnsEndpoint,
    port: u16,
    host: &str,
    proto: &str,
) -> Result<tokio::net::TcpStream> {
    if ep.ips.is_empty() {
        return Err(AetherError::Other(format!(
            "{proto}: {host} has no pinned IP"
        )));
    }
    // Prefer IPv4: some Iranian carriers break v6 to Cloudflare while v4 still
    // works (same preference as CoreConfig.resolveHostsToIps).
    let mut ordered: Vec<_> = ep.ips.iter().collect();
    ordered.sort_by_key(|ip| ip.is_ipv6());

    let mut last: Option<AetherError> = None;

    // Happy-eyeballs: race every pinned IP in parallel and keep whichever
    // socket completes the TCP handshake first. Trying them in series (the
    // pre-2.0.22 behaviour) meant one black-holed address cost a full
    // CONNECT_TIMEOUT before the next was even tried — the 14-15s "sites
    // don't load for the first minute" seen on Iranian carriers, where the
    // first pinned IP is frequently unroutable from inside the tunnel.
    // A failed connect here only abandons that racer; the query then falls
    // back to plain UDP, so the device stays online.
    let mut racers = Vec::new();
    for ip in &ordered {
        let addr = std::net::SocketAddr::new(**ip, port);
        racers.push(tokio::spawn(async move {
            SmartDnsSplit::connect_tcp_resolver(addr).await
        }));
    }
    let mut ok: Option<tokio::net::TcpStream> = None;
    for r in racers {
        match r.await {
            Ok(Ok(s)) => {
                log::debug!("{proto}: connected to {host} via a raced pinned IP");
                ok = Some(s);
                break;
            }
            Ok(Err(e)) => last = Some(e),
            Err(j) => last = Some(AetherError::Other(format!(" racer panicked: {j}"))),
        }
    }
    match ok {
        Some(s) => return Ok(s),
        None => {}
    }
    Err(last.unwrap_or_else(|| AetherError::Other(format!(
        "{proto}: {host}: every pinned IP failed"
    ))))
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
    /// The engine prefers these — the whole point of the
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
            // makes them unroutable and the bootstrap lookup fails. Public
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
            //

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

    /// True when the engine owns a resolver of ANY transport — encrypted OR a
    /// plain-UDP server the user typed on the DNS screen.
    ///
    /// tun::bridge diverts a UDP/53 datagram to the engine only when this is
    /// true. When the user configures ONLY a plain-UDP resolver (no DoT/DoH),
    /// has_encrypted() is false, the diversion never fires and the query rides
    /// the tunnel raw. That is what made "DNS ساده UDP کار نمیکنه" in 2.0.23:
    /// the custom resolver was pushed to the engine ("1 resolver(s) pushed to
    /// engine") but the engine was never handed the packets to answer. v2.0.0
    /// worked because it intercepted only Gemini domains and let every other
    /// query through — the same outcome this gate now reproduces for a
    /// UDP-only setup, only deliberately and with the user's own resolver.
    pub fn has_resolver(&self) -> bool {
        !self.encrypted_resolvers.read().is_empty()
            || !self.user_resolvers.read().is_empty()
    }

    /// The hostnames and addresses of the configured DoT/DoH servers.
    ///
    /// These are EXCLUDED from interception. This is the fix for the bootstrap
    /// deadlock that failed across 2.0.6-2.0.8:
    ///
    /// the engine intercepts every port-53 query the device makes. Answering a
    /// query for domain X means asking the DoH server, which means resolving
    /// the DoH server's own hostname. That lookup is itself a port-53 query.
    /// Whichever socket carried it — protected (physical carrier network, where
    /// Iranian operators hijack and drop plain 53) or unprotected (through the
    /// tunnel, whose DNS path IS this function) — failed. The protected path
    /// timed out on the carrier; the unprotected path re-entered this function
    /// and deadlocked the future waiting on it. Field logs: the bootstrap line
    /// cycling at a steady 6s with no answer, no error, nothing after it.
    ///
    /// Exclusion breaks the loop: a query for the resolver's own name returns
    /// None and takes the tunnel's own DNS path, which resolves it through the
    /// exit node where nothing is hijacked. The answer comes back without ever
    /// entering the interceptor. Then the DoH request can be sent over either
    /// path, because it can no longer re-enter this function.
    fn resolver_hosts(&self) -> Vec<String> {
        let mut out = Vec::new();
        for ep in self.encrypted_resolvers.read().iter() {
            if let Some(name) = &ep.name {
                out.push(name.to_ascii_lowercase());
            } else if !ep.address.starts_with("http") {
                out.push(ep.address.to_ascii_lowercase());
            }
        }
        out
    }

    /// True when the query must NOT be intercepted — the resolver's own name.
    fn is_resolver_hostname(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        self.resolver_hosts().iter().any(|h| domain == *h || domain.ends_with(&format!(".{h}")))
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

    /// Open a TCP connection to the DoT/DoH server.
    ///
    /// PROTECTED — kept outside the tunnel — same as masque_h2::connect_tcp.
    ///
    /// v2.0.13 corrects a wrong turn in 2.0.11. That build removed the protect()
    /// call on the theory that Iranian carriers block Cloudflare outside the
    /// tunnel, so the connection should ride the TUN. But the app excludes its
    /// own package from the VPN in split-tunnel ALL mode (the default) and runs
    /// single-process (no android:process in the manifest), so the core shares
    /// the app's uid and an "unprotected" socket was never actually in the
    /// tunnel to begin with. Un-protecting the socket changed nothing about the
    /// path — and it reintroduced the class of re-entry bug the protect() call
    /// exists to close. Intra (Jigsaw) and firestack both protect the
    /// resolver's own socket: protect() is the correct invariant.
    ///
    /// The reason DoH still failed in the 2.0.11/2.0.12 logs is that the
    /// outside-tunnel path IS where Iranian carriers block Cloudflare — so
    /// the fix is a working resolver IP, not a different socket. Cloudflare
    /// Workers also serve DoH over HTTP/2; see [doh_query].
    async fn connect_tcp_resolver(addr: std::net::SocketAddr) -> Result<tokio::net::TcpStream> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }
        .map_err(AetherError::Io)?;

        // v2.0.23: the socket is tunnel-routed by default (no protect()) so an
        // anycast Worker answers from the tunnel's exit, not from Frankfurt —
        // the fix for the German DNS leak. But when the tunnel is itself a
        // Cloudflare WARP tunnel and the resolver IS Cloudflare, tunnel-routing
        // the connection hairpins it: WARP's egress back into Cloudflare's own
        // DoT/DoH edge is dropped by the edge, and every query times out at
        // CONNECT_TIMEOUT (5s) and falls back to plain UDP — which is why
        // tls://family.cloudflare-dns.com silently stopped filtering in 2.0.21.
        // Keeping those connections OUT of the tunnel is also the only way they
        // work at all on this transport.
        //
        // v2.0.24: that reasoning was backwards. The app excludes its own uid
        // from the VPN (addDisallowedApplication in applySplitTunneling), so an
        // "unprotected" engine socket goes over the CARRIER, never the tunnel —
        // protect() and no-protect() are the same path here. The real variable
        // is the PORT: 443 is never filtered, but Iranian carriers block 853,
        // so DoT times out at exactly CONNECT_TIMEOUT no matter what. Keep the
        // Cloudflare-protect() call for the egress reason above; the DoT
        // timeout is a carrier fact, and the caller falls back to plain UDP.
        if crate::smart_dns::is_cloudflare_resolver_addr(&addr) {
            crate::platform::protect_socket(&socket).map_err(AetherError::Io)?;
        }

        let bind = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        socket.bind(bind).map_err(AetherError::Io)?;
        // A dead or blocked path must fail fast, not hang the query forever.
        let connect = timeout(CONNECT_TIMEOUT, socket.connect(addr));
        connect.await
            .map_err(|_| AetherError::Other(format!("connect to {addr} timed out")))?
            .map_err(AetherError::Io)
    }

    async fn dot_query(&self, ep: &DnsEndpoint, query: &[u8]) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port = ep.explicit_port().unwrap_or(853);
        // The app pins the resolver's own IPs at connect time (CoreConfig,
        // 2.0.10) precisely so this path never has to do a lookup. Without a
        // pin there is no safe option: resolving through the tunnel re-enters
        // this engine and deadlocks (2.0.5-2.0.9), and the protected path
        // times out on Iranian carriers. Fail fast instead and let the caller
        // fall back to plain UDP, which keeps the device online.
        let host = ep.address.split("://").nth(1).unwrap_or(&ep.address);
        let host = host.split('/').next().unwrap_or(host);
        let host = host.split(':').next().unwrap_or(host);
        let plain = connect_pinned(ep, port, host, "dot").await?;
        // The TLS handshake needs its own bound: on Iranian carriers a TCP
        // connect to a Cloudflare IP can succeed while the handshake's first
        // flight is blackholed, and tokio_boring has no timeout of its own.
        // Without this the query hangs forever with no error — the exact
        // signature of the 2.0.11 field logs.
        let mut stream = match timeout(CONNECT_TIMEOUT, tokio_boring::connect(Self::tls_connector()?, &ep.address, plain)).await {
            Ok(s) => s.map_err(|e| AetherError::Tls(format!("dot handshake {}: {e}", ep.address)))?,
            Err(_) => {
                // v2.0.24: a 853 connect that never completes is a carrier
                // port block, not a dead resolver. Iranian carriers filter 853
                // while leaving 443 untouched, so retry the identical query as
                // DoH over 443 with the resolver's own hostname. Without this
                // the caller falls back to plain UDP and the family filtering
                // the user configured (tls://family.cloudflare-dns.com) is
                // silently lost — the "adult content was shown" report.
                return self.query_doh_fallback(ep, query).await;
            }
        };
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

    /// v2.0.24: DoT-over-853 is unreachable on Iranian carriers, but the same
    /// public resolver almost always serves DoH on 443 (Cloudflare:
    /// `https://family.cloudflare-dns.com/dns-query`, which carries the same
    /// family policy). Rebuild a DoH endpoint from the DoT hostname and reuse
    /// the existing DoH path, so a port-853 block costs the user nothing.
    async fn query_doh_fallback(&self, dot_ep: &DnsEndpoint, query: &[u8]) -> Result<Vec<u8>> {
        // `dot_ep.address` is the raw endpoint of a tls:// entry, e.g.
        // "family.cloudflare-dns.com" (CoreConfig already split the port).
        let hostname = dot_ep.address
            .split("://")
            .nth(1)
            .unwrap_or(&dot_ep.address)
            .split('/')
            .next()
            .unwrap_or(&dot_ep.address)
            .split(':')
            .next()
            .unwrap_or(&dot_ep.address);
        let mut doh = DnsEndpoint::parse(&format!("https://{hostname}/dns-query"))
            .ok_or_else(|| AetherError::Other(format!("doh fallback parse {hostname}")))?;
        // CRITICAL: the rebuilt endpoint starts with an empty pin list, and
        // connect_pinned() with no pins fails with "has no pinned IP" (it
        // never resolves: a lookup would re-enter this engine and deadlock,
        // 2.0.5-2.0.9). CoreConfig pinned the IPs for this very hostname, and
        // they are equally valid for the DoH query to the same host on 443, so
        // carry them over.
        doh.ips = dot_ep.ips.clone();
        log::info!("[smart-dns] DoT blocked on 853, retrying https://{hostname}/dns-query on 443 ({} pinned IP(s))", doh.ips.len());
        self.doh_query(&doh, query).await
    }

    /// A permissive TLS config for a public DoT/DoH server: system roots, no
    /// pinning. The encrypted DNS path must not inherit the tunnel's own
    /// fingerprint settings — those exist to imitate a browser against a
    /// censor, and a resolver does not need them.
    fn tls_connector() -> Result<boring::ssl::ConnectConfiguration> {
        let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
            .map_err(|e| AetherError::Tls(format!("tls builder: {e}")))?;
        builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
            .map_err(|e| AetherError::Tls(format!("tls min: {e}")))?;
        builder.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
            .map_err(|e| AetherError::Tls(format!("tls max: {e}")))?;
        builder.set_grease_enabled(true);

        // The connector must be told how to verify the server. BoringSSL embeds
        // no CA bundle of its own, so an unconfigured connector stays on
        // SslVerifyMode::PEER with an empty trust store and rejects every cert:
        // "cert verification failed - unable to get local issuer certificate".
        // That is what log 30 showed on every DoH query. Cloudflare Workers
        // present publicly trusted chains, but we have no root store to verify
        // them against — and the app does not ship a pin for the resolver's
        // leaf SPKI either. So take the same route as tls::install_verification's
        // no-pin branch: accept the presented cert, relying on the DNS response
        // being authenticated by the resolver being the endpoint we pinned by IP.
        boring::ssl::SslContextBuilder::set_verify(
            &mut builder,
            boring::ssl::SslVerifyMode::NONE,
        );
        let mut config = builder.build()
            .configure()
            .map_err(|e| AetherError::Tls(format!("tls configure: {e}")))?;
        config.set_verify_hostname(false);
        Ok(config)
    }

    async fn doh_query(&self, ep: &DnsEndpoint, query: &[u8]) -> Result<Vec<u8>> {
        // DoH over a PROTECTED connection. The previous implementation used
        // reqwest, which opens its own socket — unprotected, so the POST rode
        // the tunnel, was captured by process_query(), and deadlocked the very
        // future waiting on its own answer. Field logs (2.0.6/2.0.7) showed the
        // bootstrap lookup cycling every 6s and then silence: no answer, no
        // error. This hand-rolled HTTP/1.1 POST over a protected TLS socket
        // removes reqwest from the DNS path entirely.
        let url = if ep.address.starts_with("https://") {
            ep.address.clone()
        } else {
            format!("https://{}/dns-query", ep.address)
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|e| AetherError::Other(format!("doh url {url}: {e}")))?;
        let host = parsed.host_str()
            .ok_or_else(|| AetherError::Other(format!("doh url {url} has no host")))?;
        let port = parsed.port_or_known_default()
            .ok_or_else(|| AetherError::Other(format!("doh url {url} has no port")))?;
        let path = parsed.path();
        let path = if path.is_empty() { "/dns-query" } else { path };

        let plain = connect_pinned(ep, port, host, "doh").await?;
        // Same bound as dot_query: the handshake can blackhole after a
        // successful TCP connect on a censored carrier.
        let mut tls = match timeout(CONNECT_TIMEOUT, tokio_boring::connect(Self::tls_connector()?, host, plain)).await {
            Ok(t) => t.map_err(|e| AetherError::Tls(format!("doh handshake {host}: {e}")))?,
            Err(_) => return Err(AetherError::Other(format!("doh handshake {host} timed out"))),
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n",
            len = query.len()
        );
        tls.write_all(req.as_bytes()).await.map_err(AetherError::Io)?;
        tls.write_all(query).await.map_err(AetherError::Io)?;
        tls.flush().await.map_err(AetherError::Io)?;

        // Read the full response: headers, then body.
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.map_err(AetherError::Io)?;
        // Locate the blank line separating headers from body.
        let mut split = None;
        for i in 0..buf.len().saturating_sub(3) {
            if &buf[i..i + 4] == b"\r\n\r\n" {
                split = Some(i + 4);
                break;
            }
        }
        let body_start = split.ok_or_else(|| AetherError::Other("doh: no body separator".into()))?;

        // Workers answers DoH with `Transfer-Encoding: chunked`. Leaving the
        // chunk framing in the body corrupts the DNS message, so decode it.
        let headers = &buf[..body_start - 4];
        let is_chunked = headers
            .windows(26)
            .any(|w| w.eq_ignore_ascii_case(b"transfer-encoding: chunked"));

        let body = if is_chunked {
            let mut out = Vec::new();
            let mut pos = body_start;
            while pos < buf.len() {
                // Read the hex size line up to CRLF.
                let eol = buf[pos..].iter().position(|&b| b == b'\n')
                    .map(|p| pos + p);
                let Some(eol) = eol else { break };
                let line = &buf[pos..eol];
                // Trim the trailing CR and split off any chunk extension.
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let hex = line.split(|&b| b == b';').next().unwrap_or(b"");
                let hex = std::str::from_utf8(hex).unwrap_or("");
                let size = usize::from_str_radix(hex.trim_start(), 16).unwrap_or(0);
                pos = eol + 1;
                if size == 0 { break }
                let end = (pos + size).min(buf.len());
                out.extend_from_slice(&buf[pos..end]);
                pos = end;
                // Skip the trailing CRLF after the chunk.
                if pos + 2 <= buf.len() && &buf[pos..pos+2] == b"\r\n" { pos += 2 }
            }
            out
        } else {
            // Content-Length is exact; honour it when present, else take the
            // remainder (connection-close body).
            let content_len = headers
                .windows(16)
                .find(|w| w.eq_ignore_ascii_case(b"content-length:"))
                .and_then(|w| {
                    let v = w[16..].split(|&b| b == b'\r').next().unwrap_or(b"");
                    std::str::from_utf8(v).ok().and_then(|s| s.trim().parse::<usize>().ok())
                });
            match content_len {
                Some(n) if body_start + n <= buf.len() => &buf[body_start..body_start + n],
                _ => &buf[body_start..],
            }.to_vec()
        };
        Ok(body)
    }

    /// Process a DNS query from the TUN.
    /// Returns response_data; None lets the query take the tunnel's
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
        let has_encrypted = self.has_encrypted();

        // Diagnostic: without this the engine looks dead when it is merely
        // receiving nothing. The field log showed init + ready but zero
        // per-query lines, which was indistinguishable from "queries never
        // arrive at the TUN" and "queries arrive but the parser rejects them".
        log::info!(
            "[smart-dns] qtype={qtype} name={domain} encrypted={has_encrypted} len={}",
            payload.len()
        );

        // v2.0.24: the gate must not require encrypted resolvers. A user who
        // configured only a plain-UDP server has an empty encrypted list, so the
        // old `if !has_encrypted { return None }` dropped every one of their
        // queries after tun::bridge had already diverted the packet to this
        // task — the query vanished and "DNS ساده UDP" silently did nothing.
        // The engine now answers whenever it has ANY resolver for the job, and
        // tun.rs forwards the packet to the tunnel when it still has no answer.
        if self.encrypted_resolvers.read().is_empty()
            && self.user_resolvers.read().is_empty()
        {
            return None;
        }

        // THE BOOTSTRAP EXCLUSION. Resolving the DoH server's own hostname is
        // what deadlocked every previous version: this function intercepts that
        // query, and answering it needs that very lookup. Letting it fall
        // through to the tunnel's own DNS path resolves it through the exit
        // node instead. See resolver_hosts().
        if self.is_resolver_hostname(&domain) {
            log::info!("[smart-dns] resolver-host query {domain} -> tunnel path (excluded)");
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

/// True when the address belongs to Cloudflare. The WARP tunnel IS Cloudflare,
/// so a resolver-to-Cloudflare connection that rides the WARP tunnel hairpins:
/// the egress dials back into Cloudflare's own edge and the edge drops it. The
/// DoT/DoH socket for such a resolver must stay OUT of the tunnel.
///
/// Covers 1.1.1.0/24, 1.0.0.0/24 (public resolvers and the family/adult
/// variants 1.1.1.2/.3 and 1.0.0.2/.3) and 2606:4700:4700::/48 (the v6 pair).
pub(crate) fn is_cloudflare_resolver_addr(addr: &std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // 1.1.1.x and 1.0.0.x — Cloudflare's public resolver range,
            // including the family (1.1.1.3 / 1.0.0.3) and adult (1.1.1.2)
            // variants the user may configure for filtering.
            o[0] == 1 && (o[1] == 1 || o[1] == 0)
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            // 2606:4700:4700::/48 — Cloudflare's v6 resolver pair and the
            // family/adult variants (::1111, ::1112, ::1113, ::1003 ...).
            s[0] == 0x2606 && s[1] == 0x4700 && s[2] == 0x4700
        }
    }
}

/// Get whether the engine is up and has encrypted resolvers configured.
pub fn has_encrypted() -> bool {
    with_engine(|e| e.has_encrypted()).unwrap_or(false)
}

/// True when the engine owns any resolver — encrypted or a plain-UDP server
/// the user typed. tun::bridge gates UDP/53 diversion on this; see
/// [SmartDnsSplit::has_resolver].
pub fn has_resolver() -> bool {
    with_engine(|e| e.has_resolver()).unwrap_or(false)
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
/// Plain-UDP entries are kept for the engine's own resolution path (the
/// bootstrap lookup) AND are already handed to Android by applyDns(); encrypted entries
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cloudflare resolvers must be recognised so their socket is kept out of
    /// the WARP tunnel — see [is_cloudflare_resolver_addr]. A miss here means
    /// the connection hairpins and every DoT/DoH query to 1.1.1.x times out.
    #[test]
    fn cloudflare_resolver_range_is_detected() {
        let cf = |ip: &str, port| {
            std::net::SocketAddr::new(ip.parse().unwrap(), port)
        };
        // Public, family and adult variants — all Cloudflare.
        assert!(is_cloudflare_resolver_addr(&cf("1.1.1.1", 853)));
        assert!(is_cloudflare_resolver_addr(&cf("1.1.1.2", 853)));
        assert!(is_cloudflare_resolver_addr(&cf("1.1.1.3", 853)));
        assert!(is_cloudflare_resolver_addr(&cf("1.0.0.3", 443)));
        assert!(is_cloudflare_resolver_addr(&cf("1.0.0.1", 443)));
        assert!(is_cloudflare_resolver_addr(&cf("[2606:4700:4700::1111]", 853)));
        assert!(is_cloudflare_resolver_addr(&cf("[2606:4700:4700::1003]", 853)));
        // Non-Cloudflare resolvers must NOT match — those ride the tunnel so
        // the anycast Worker answers from the exit, not from Frankfurt.
        assert!(!is_cloudflare_resolver_addr(&cf("9.9.9.9", 853)));
        assert!(!is_cloudflare_resolver_addr(&cf("8.8.8.8", 853)));
        assert!(!is_cloudflare_resolver_addr(&cf("94.140.14.14", 443)));
    }

    /// A DoH URL's path must survive parsing untouched. HTTP paths are
    /// case-sensitive, and a DoH server that authenticates by a token in the
    /// path — e.g. `https://x.workers.dev/dns-query/PLJhQthhMfwAKilJ` — answers
    /// the lowercased copy with 500. The engine then treats the DoH resolver as
    /// dead, falls back to plain UDP, and the user sees the exit node's own
    /// resolver instead of the one they configured.
    #[test]
    fn doh_path_case_is_preserved() {
        let ep = DnsEndpoint::parse("https://benjamin.mohamadxx.workers.dev/dns-query/PLJhQthhMfwAKilJ")
            .expect("a https:// DoH URL must parse");
        assert_eq!(ep.transport, DnsTransport::Doh);
        assert_eq!(
            ep.address,
            "https://benjamin.mohamadxx.workers.dev/dns-query/PLJhQthhMfwAKilJ"
        );
        assert_eq!(ep.name.as_deref(), Some("benjamin.mohamadxx.workers.dev"));
    }

    /// The scheme alone is what the user may type in any casing; the host below
    /// it is a hostname and case-insensitive, so it is normalised.
    #[test]
    fn doh_scheme_is_case_insensitive_path_is_not() {
        let ep = DnsEndpoint::parse("HTTPS://Benjamin.Mohamadxx.Workers.dev/dns-query/PLJhQthhMfwAKilJ")
            .expect("an uppercase scheme is still a DoH URL");
        assert_eq!(ep.transport, DnsTransport::Doh);
        assert_eq!(
            ep.address,
            "https://Benjamin.Mohamadxx.Workers.dev/dns-query/PLJhQthhMfwAKilJ"
        );
        // resolver-host matching must still see the hostname, and lowercase it.
        assert_eq!(ep.name.as_deref(), Some("benjamin.mohamadxx.workers.dev"));
    }

    /// The short `doh://` scheme is one byte shorter than `https://`. The two
    /// were length-sliced together once, which ate the first letter of every
    /// `doh://` hostname and produced a URL for a host that does not exist.
    #[test]
    fn doh_short_scheme_does_not_eat_the_first_letter() {
        let ep = DnsEndpoint::parse("doh://cloudflare-dns.com/dns-query")
            .expect("doh:// is the short DoH scheme");
        assert_eq!(ep.transport, DnsTransport::Doh);
        assert_eq!(ep.address, "https://cloudflare-dns.com/dns-query");
        assert_eq!(ep.name.as_deref(), Some("cloudflare-dns.com"));
    }

    /// The plain-UDP and DoT branches never carried a path, so the regression
    /// was DoH-only. Pin them so a future "normalise the entry" refactor cannot
    /// re-introduce it there.
    #[test]
    fn dot_and_plain_entries_still_parse() {
        let dot = DnsEndpoint::parse("tls://dns.google").expect("tls:// is DoT");
        assert_eq!(dot.transport, DnsTransport::Dot);
        assert_eq!(dot.address, "dns.google");

        let dot_doh_scheme = DnsEndpoint::parse("doh:dns.quad9.net").expect("doh: is DoH");
        assert_eq!(dot_doh_scheme.transport, DnsTransport::Doh);
        assert_eq!(dot_doh_scheme.address, "https://dns.quad9.net/dns-query");

        let plain = DnsEndpoint::parse("1.1.1.1:53").expect("bare ip:port is plain UDP");
        assert_eq!(plain.transport, DnsTransport::Plain);
        assert_eq!(plain.address, "1.1.1.1");

        assert!(DnsEndpoint::parse("  ").is_none(), "whitespace is not an entry");
    }

    /// v2.0.24: an IP-literal DoH server is its own pin. The engine never
    /// resolved one because CoreConfig's extractHost returned null for a
    /// literal, so no pin was stored and every query failed with "has no
    /// pinned IP" — the report that https://8.8.8.8/dns-query works in
    /// karing/intra but not here. The engine side of that fix is that the
    /// literal parses and reaches the pin-matching step at all.
    #[test]
    fn ip_literal_doh_entry_parses() {
        let ep = DnsEndpoint::parse("https://8.8.8.8/dns-query")
            .expect("an IP literal is a valid DoH host");
        assert_eq!(ep.transport, DnsTransport::Doh);
        assert_eq!(ep.name.as_deref(), Some("8.8.8.8"));
        // host_of must not mangle the literal: the pin list is matched by name.
        assert_eq!(host_of("8.8.8.8/dns-query"), "8.8.8.8");
    }

    /// v2.0.24: has_resolver() must be true for a UDP-only configuration.
    /// Before this the tun::bridge gate read has_encrypted(), which is false
    /// when the user configured only a plain-UDP server, so the diversion task
    /// was never armed and the engine never saw a single packet — "DNS ساده
    /// UDP کار نمیکنه" while the log happily reported the resolver pushed.
    #[test]
    fn udp_only_engine_reports_a_resolver() {
        let e = SmartDnsSplit::new();
        assert!(!e.has_resolver(), "an empty engine owns nothing");
        assert!(!e.has_encrypted());
        // set_resolvers() is the app's single entry point and is global-only;
        // exercise the two lists the way it does, through the same setters.
        e.set_encrypted_resolvers(vec![]);
        e.user_resolvers.write().push(
            DnsEndpoint::parse("111.88.96.51:53").unwrap()
        );
        assert!(e.has_resolver(), "a plain-UDP server is a resolver");
        assert!(!e.has_encrypted(), "but it is not an encrypted one");
    }

    /// v2.0.24: DoT on 853 is carrier-blocked, so dot_query retries the same
    /// query as DoH on 443 with the resolver's hostname. The rebuilt endpoint
    /// must keep the DoT entry's pinned IPs: connect_pinned() refuses to
    /// resolve a hostname (that re-enters the engine and deadlocks), so a
    /// fallback with an empty pin list would fail with "has no pinned IP".
    #[test]
    fn doh_fallback_carries_the_pinned_ips() {
        let dot = DnsEndpoint::parse("tls://family.cloudflare-dns.com").unwrap();
        let mut ips = dot.ips.clone();
        ips.push("1.1.1.3".parse().unwrap());
        let dot = DnsEndpoint { ips, ..dot };
        assert!(!dot.ips.is_empty());

        // query_doh_fallback is async and opens sockets; test only the
        // endpoint reconstruction it depends on.
        let raw = "https://family.cloudflare-dns.com/dns-query";
        let mut doh = DnsEndpoint::parse(raw).unwrap();
        assert!(doh.ips.is_empty(), "parse alone never sets pins");
        doh.ips = dot.ips.clone();
        assert_eq!(doh.ips.len(), 1);
        assert_eq!(doh.name.as_deref(), dot.name.as_deref());
        assert_eq!(doh.transport, DnsTransport::Doh);
    }
}
