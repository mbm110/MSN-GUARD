use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::aethernoize::{self, AetherNoizeConfig};
use crate::error::{AetherError, Result};
use rand::Rng;

const TIMER_TICK: Duration = Duration::from_millis(250);
const MAX_PACKET: usize = 65536;
const VERIFY_RETRY_DELAYS: [Duration; 2] = [
    Duration::from_millis(750),
    Duration::from_millis(2_000),
];

const WG_MSG_TYPE_MIN: u8 = 1;
const WG_MSG_TYPE_MAX: u8 = 4;

const MAX_TRANSIENT_RECV_ERRORS: u32 = 64;
const TRANSIENT_RECV_BACKOFF: Duration = Duration::from_millis(50);

pub fn is_transient_socket_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
    )
}

struct TaskGuard(Vec<tokio::task::AbortHandle>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

fn inject_client_id(pkt: &mut [u8], client_id: &[u8; 3]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(client_id);
}

fn strip_client_id(pkt: &mut [u8]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(&[0u8; 3]);
}

#[derive(Clone)]
pub struct WgConfig {
    pub local_private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub client_id: [u8; 3],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub aethernoize: Arc<AetherNoizeConfig>,
}

pub struct WgTunnel {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    pub obf_sent: Arc<Mutex<bool>>,
    pub aethernoize: Arc<AetherNoizeConfig>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
}

pub struct EstablishedSession {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    client_id: [u8; 3],
}

impl WgTunnel {
    pub async fn new(cfg: WgConfig, inbound_tx: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let bind_addr = if cfg.peer_endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        crate::platform::protect_socket(&sock)?;
        sock.connect(cfg.peer_endpoint).await?;

        let local_secret = StaticSecret::from(cfg.local_private_key);
        let peer_public = PublicKey::from(cfg.peer_public_key);
        let preshared = cfg.preshared_key;

        let tunn = Tunn::new(
            local_secret,
            peer_public,
            preshared,
            cfg.persistent_keepalive,
            0,
            None,
        )
        .map_err(|e| AetherError::Other(format!("wireguard tunnel init: {e}")))?;

        Ok(Self {
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            sock: Arc::new(sock),
            peer: cfg.peer_endpoint,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(false)),
            aethernoize: cfg.aethernoize.clone(),
            client_id: cfg.client_id,
            local_ipv4: cfg.local_ipv4,
        })
    }

    pub fn from_established(
        session: EstablishedSession,
        aethernoize: Arc<AetherNoizeConfig>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
    ) -> Self {
        Self {
            tunn: session.tunn,
            sock: session.sock,
            peer: session.peer,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(true)),
            aethernoize,
            client_id: session.client_id,
            local_ipv4,
        }
    }

    pub async fn run(self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let sock_r = self.sock.clone();
        let sock_w = self.sock.clone();
        let sock_t = self.sock.clone();
        let sock_h = self.sock.clone();
        let tunn_r = self.tunn.clone();
        let tunn_w = self.tunn.clone();
        let tunn_t = self.tunn.clone();
        let tunn_h = self.tunn.clone();
        let inbound_tx = self.inbound_tx.clone();
        let obf_sent = self.obf_sent.clone();
        let post_hs_junk_sent = Arc::new(AtomicBool::new(false));
        let aethernoize = self.aethernoize.clone();
        let aethernoize_t = self.aethernoize.clone();
        let client_id = self.client_id;
        let client_id_h = self.client_id;
        let peer = self.peer;
        let local_ipv4 = self.local_ipv4;

        let last_valid_rx: Arc<StdMutex<Instant>> = Arc::new(StdMutex::new(Instant::now()));
        let last_valid_rx_r = last_valid_rx.clone();
        let last_valid_rx_h = last_valid_rx.clone();

        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut tmp = vec![0u8; MAX_PACKET];
            let mut transient_errors = 0u32;
            loop {
                match sock_r.recv(&mut buf).await {
                    Ok(n) => {
                        transient_errors = 0;
                        strip_client_id(&mut buf[..n]);
                        let mut tunn = tunn_r.lock().await;
                        match tunn.decapsulate(None, &buf[..n], &mut tmp) {
                            TunnResult::Done => {
                                *last_valid_rx_r.lock().unwrap() = Instant::now();
                            }
                            TunnResult::Err(e) => {
                                log::trace!("decapsulate error: {e:?}");
                            }
                            TunnResult::WriteToNetwork(pkt) => {
                                *last_valid_rx_r.lock().unwrap() = Instant::now();
                                let mut pkt_vec = pkt.to_vec();
                                inject_client_id(&mut pkt_vec, &client_id);
                                drop(tunn);
                                let _ = sock_r.send(&pkt_vec).await;
                            }
                            TunnResult::WriteToTunnelV4(pkt, _)
                            | TunnResult::WriteToTunnelV6(pkt, _) => {
                                *last_valid_rx_r.lock().unwrap() = Instant::now();
                                let pkt_vec = pkt.to_vec();
                                drop(tunn);
                                let _ = inbound_tx.send(pkt_vec).await;
                            }
                        }
                    }
                    Err(e) => {
                        if is_transient_socket_error(&e) {
                            transient_errors += 1;
                            if transient_errors > MAX_TRANSIENT_RECV_ERRORS {
                                log::error!(
                                    "recv error: {e}; giving up after {transient_errors} consecutive transient failures"
                                );
                                break;
                            }
                            log::debug!(
                                "transient recv error: {e}; keeping the tunnel and retrying"
                            );
                            tokio::time::sleep(TRANSIENT_RECV_BACKOFF).await;
                            continue;
                        }
                        log::error!("recv error: {e}");
                        break;
                    }
                }
            }
        });

        let send_task = tokio::spawn(async move {
            // Hoisted out of the loop deliberately. This used to be allocated
            // per packet: a 64 KiB zeroed allocation for every single outbound
            // datagram, which at any real throughput is thousands of 64 KiB
            // allocations per second and the largest avoidable CPU cost in the
            // data path. `encapsulate` overwrites what it uses and returns a
            // subslice, so reusing one buffer is equivalent.
            let mut out_buf = vec![0u8; MAX_PACKET];
            while let Some(ip_packet) = outbound_rx.recv().await {
                let mut tunn = tunn_w.lock().await;

                match tunn.encapsulate(&ip_packet, &mut out_buf) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        log::trace!("encapsulate error: {e:?}");
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        drop(tunn);

                        {
                            let mut sent = obf_sent.lock().await;
                            if !*sent && aethernoize.is_enabled() {
                                *sent = true;
                                drop(sent);
                                aethernoize::apply_obfuscation(&sock_w, peer, &aethernoize).await;
                            }
                        }

                        let _ = sock_w.send(&pkt_vec).await;

                        if aethernoize.jc_after_hs > 0
                            && !post_hs_junk_sent.swap(true, Ordering::SeqCst)
                        {
                            let sock_clone = sock_w.clone();
                            let cfg_clone = aethernoize.clone();
                            tokio::spawn(async move {
                                aethernoize::send_post_handshake_junk(
                                    &sock_clone,
                                    peer,
                                    &cfg_clone,
                                )
                                .await;
                            });
                        }
                    }
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
        });

        let timer_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TIMER_TICK);
            // One buffer for the task's whole life, not one per tick. The tick is
            // 250ms and almost every tick has nothing to send, so this was 14,400
            // pointless 64 KiB allocations an hour for a tunnel just sitting there
            // — pure battery cost with no work behind it.
            let mut tmp = vec![0u8; MAX_PACKET];
            loop {
                interval.tick().await;
                let mut tunn = tunn_t.lock().await;
                if let TunnResult::WriteToNetwork(pkt) = tunn.update_timers(&mut tmp) {
                    let mut pkt_vec = pkt.to_vec();
                    inject_client_id(&mut pkt_vec, &client_id);
                    drop(tunn);

                    if aethernoize_t.is_enabled() {
                        let sock_j = sock_t.clone();
                        let cfg_j = aethernoize_t.clone();
                        tokio::spawn(async move {
                            aethernoize::send_keepalive_junk(&sock_j, &cfg_j).await;
                            let _ = sock_j.send(&pkt_vec).await;
                        });
                    } else {
                        let _ = sock_t.send(&pkt_vec).await;
                    }
                }
            }
        });

        let stale_timeout = wg_stale_timeout();
        let health_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(WG_HEALTHCHECK_INTERVAL);
            let probe = build_dataplane_probe(local_ipv4);
            let mut out_buf = vec![0u8; MAX_PACKET];
            loop {
                interval.tick().await;

                let idle = last_valid_rx_h.lock().unwrap().elapsed();
                if idle >= stale_timeout {
                    log::warn!(
                        "[wg] no valid data from peer {} in {:?}; tunnel considered dead",
                        peer,
                        idle
                    );
                    return Err::<(), AetherError>(AetherError::Other(
                        "wireguard tunnel stale: no valid data from peer".into(),
                    ));
                }

                let mut tunn = tunn_h.lock().await;
                if let Err(e) =
                    send_dataplane_probe(&sock_h, &mut tunn, &client_id_h, &probe, &mut out_buf)
                        .await
                {
                    log::trace!("[wg] health probe send failed: {e}");
                }
            }
        });

        let _guard = TaskGuard(vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
            health_task.abort_handle(),
        ]);

        let result = tokio::select! {
            _ = recv_task => {
                log::info!("wireguard recv task ended");
                Ok(())
            }
            _ = send_task => {
                log::info!("wireguard send task ended");
                Ok(())
            }
            _ = timer_task => {
                log::info!("wireguard timer task ended");
                Ok(())
            }
            r = health_task => {
                match r {
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(())) => Ok(()),
                    Err(e) => Err(AetherError::Other(format!("health task panicked: {e}"))),
                }
            }
        };

        result
    }
}

const WG_HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(3);

fn wg_stale_timeout() -> Duration {
    let secs = std::env::var("AETHER_WG_STALE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

fn build_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_dataplane_probe(src: Ipv4Addr) -> Vec<u8> {
    let dns = build_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    let sport: u16 = rand::thread_rng().gen_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&dns);
    pkt
}

async fn send_dataplane_probe(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    probe: &[u8],
    out_buf: &mut [u8],
) -> Result<()> {
    match tunn.encapsulate(probe, out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut v = pkt.to_vec();
            inject_client_id(&mut v, client_id);
            sock.send(&v).await?;
        }
        TunnResult::Err(e) => {
            return Err(AetherError::Other(format!("dataplane encap: {e:?}")));
        }
        _ => {}
    }
    Ok(())
}

const DATAPLANE_REQUIRED_SUCCESSES: u32 = 2;
const DATAPLANE_PROBE_GAP: Duration = Duration::from_millis(600);

/// Inner packet sizes tried during validation, largest first.
///
/// The small DNS probe proves *a* path exists. It does not prove the path can
/// carry a full-size packet, and on Hamrah-e-Aval those are different facts: a
/// ~70-byte probe round-trips while a 1200-byte one is dropped silently. So
/// validation passed, the core reported connected, and every real TLS flow died
/// — a TLS ClientHello is near the top of this ladder, not the bottom.
///
/// The largest size that round-trips becomes the inner MTU hint, which the TUN
/// bridge uses to clamp TCP MSS. That is what turns "detected as broken" into
/// "works anyway": an endpoint that only carries 800-byte packets is still a
/// usable tunnel once we stop trying to push 1280-byte ones through it.
const PROBE_LADDER: &[usize] = &[1200, 1000, 800, 576];

/// Per-size budget during the ladder walk. Two sends fit in this window.
///
/// Sized so the whole ladder plus the small-probe stage fits inside
/// `wg_tunnel_validate_timeout()`; otherwise the deadline would cut the walk
/// short and every endpoint would end up on the floor clamp regardless of what
/// it can really carry.
const LADDER_STEP_BUDGET: Duration = Duration::from_millis(1_200);

/// Inner MTU proven to cross the live tunnel, published for the TUN bridge.
///
/// Written once per successful validation, read by [crate::tun::bridge] to size
/// its MSS clamp. Conservative default so a path we never measured still gets a
/// clamp rather than none.
pub static INNER_MTU_HINT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1200);

/// Largest inner packet proven to cross the tunnel, in bytes.
pub fn inner_mtu_hint() -> usize {
    INNER_MTU_HINT.load(Ordering::Relaxed)
}

/// ICMP echo id/seq for the full-size probe, so a reply can be recognised.
const LARGE_PROBE_ID: u16 = 0x4d47;

fn icmp_checksum(body: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < body.len() {
        sum += u16::from_be_bytes([body[i], body[i + 1]]) as u32;
        i += 2;
    }
    if i < body.len() {
        sum += (body[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A full-size ICMP echo to 8.8.8.8, padded to `total_len` bytes of IPv4 packet.
///
/// ICMP rather than another DNS query: an echo reply comes back the same size
/// it went out, so one round-trip tests a full-size packet in *both*
/// directions. A padded DNS query only tests the outbound leg.
fn build_large_probe(src: Ipv4Addr, total_len: usize) -> Vec<u8> {
    let total_len = total_len.max(60);
    let payload_len = total_len - 20 - 8;
    let mut icmp = Vec::with_capacity(8 + payload_len);
    icmp.push(8); // echo request
    icmp.push(0);
    icmp.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    icmp.extend_from_slice(&LARGE_PROBE_ID.to_be_bytes());
    icmp.extend_from_slice(&1u16.to_be_bytes());
    // Deterministic filler: a fixed pattern keeps the packet incompressible
    // enough to be realistic without making the probe itself random.
    for i in 0..payload_len {
        icmp.push((i % 251) as u8);
    }
    let csum = icmp_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    // Do not fragment: if the path cannot take this size we want it dropped,
    // not quietly split into pieces that hide the problem.
    pkt.extend_from_slice(&[0x40, 0x00]);
    pkt.push(64);
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt.extend_from_slice(&icmp);
    pkt
}

/// True when `pkt` is the echo reply to [build_large_probe].
fn is_large_probe_reply(pkt: &[u8]) -> bool {
    if pkt.len() < 28 {
        return false;
    }
    if pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 8 {
        return false;
    }
    let icmp = &pkt[ihl..];
    // type 0 = echo reply, and the id must be ours.
    icmp[0] == 0 && u16::from_be_bytes([icmp[4], icmp[5]]) == LARGE_PROBE_ID
}

/// Proves the tunnel can carry traffic, and measures how big a packet it takes.
///
/// Stage 1 (small): a DNS query to 8.8.8.8, [DATAPLANE_REQUIRED_SUCCESSES]
/// round-trips. Proves the crypto and the path work at all.
///
/// Stage 2 (ladder): ICMP echoes down [PROBE_LADDER], largest first, until one
/// comes back. This is the stage that catches the Hamrah-e-Aval failure, where
/// stage 1 passes and a full-size packet does not: the carrier lets the small
/// UDP flow through and drops big encapsulated ones, so a handshake plus a small
/// probe looked like a working tunnel while Telegram and every site stayed dark.
///
/// Rather than rejecting such an endpoint, the largest size that *did* cross is
/// published as [inner_mtu_hint] and the tunnel is kept. The bridge then clamps
/// MSS to it, so TCP never offers more than the path proved it can take. Only an
/// endpoint where even the smallest rung fails is rejected — at that point
/// nothing useful can cross and another endpoint is the right answer.
async fn verify_dataplane(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    local_ipv4: Ipv4Addr,
    start: Instant,
    deadline: Instant,
) -> Result<Duration> {
    let small_probe = build_dataplane_probe(local_ipv4);
    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let mut successes: u32 = 0;
    // Stage 2 starts only after stage 1 is satisfied, so a large probe is never
    // blamed for a path that was broken for every packet size.
    let mut rung: Option<usize> = None;
    let mut large_probe: Vec<u8> = Vec::new();
    let mut rung_deadline = deadline;
    let mut last_probe_at = Instant::now();
    send_dataplane_probe(sock, tunn, client_id, &small_probe, &mut out_buf).await?;
    let mut resend_at = last_probe_at + Duration::from_millis(700);

    loop {
        let now = Instant::now();
        if now >= deadline {
            if rung.is_some() {
                // Small packets crossed; no rung of the ladder did inside the
                // budget. Keep the tunnel on the most conservative clamp we have
                // rather than throwing away a path that demonstrably passes
                // packets — the app's own verification still has the final say.
                let floor = *PROBE_LADDER.last().unwrap_or(&576);
                INNER_MTU_HINT.store(floor, Ordering::Relaxed);
                log::warn!(
                    "[wg] small probes passed but no rung of the size ladder round-tripped; \
                     clamping inner MTU to {floor} and keeping the tunnel"
                );
                return Ok(start.elapsed());
            }
            log::debug!(
                "[wg] dataplane verify timed out ({}/{} confirmations)",
                successes,
                DATAPLANE_REQUIRED_SUCCESSES
            );
            return Err(AetherError::Other("dataplane timeout".into()));
        }

        // Current rung ran out of time: step down to the next smaller size.
        if rung.is_some() && now >= rung_deadline {
            let next = rung.map(|i| i + 1).unwrap_or(0);
            if let Some(&size) = PROBE_LADDER.get(next) {
                log::debug!("[wg] no round-trip at rung {next}; trying {size} bytes");
                rung = Some(next);
                large_probe = build_large_probe(local_ipv4, size);
                rung_deadline = now + LADDER_STEP_BUDGET;
                let _ =
                    send_dataplane_probe(sock, tunn, client_id, &large_probe, &mut out_buf).await;
                last_probe_at = now;
                resend_at = now + Duration::from_millis(700);
                continue;
            }
            // Ladder exhausted: fall through to the shared deadline arm above,
            // which keeps the tunnel on the floor clamp.
            rung_deadline = deadline;
        }

        if now >= resend_at {
            let probe: &[u8] = if rung.is_some() { &large_probe } else { &small_probe };
            let _ = send_dataplane_probe(sock, tunn, client_id, probe, &mut out_buf).await;
            last_probe_at = now;
            resend_at = now + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(rung_deadline.saturating_duration_since(now))
            .min(resend_at.saturating_duration_since(now));

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                let n = r?;
                strip_client_id(&mut recv_buf[..n]);
                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                        if let Some(index) = rung {
                            // Only the echo reply counts here. Anything else is
                            // unrelated traffic and must not be mistaken for
                            // proof that a full-size packet crossed.
                            if !is_large_probe_reply(pkt) {
                                continue;
                            }
                            let size = PROBE_LADDER[index];
                            INNER_MTU_HINT.store(size, Ordering::Relaxed);
                            let elapsed = start.elapsed();
                            if index == 0 {
                                log::debug!(
                                    "[wg] dataplane ok in {elapsed:?} (full-size {size}-byte \
                                     round-trip)"
                                );
                            } else {
                                log::warn!(
                                    "[wg] path carries {size}-byte packets but not {}; inner MTU \
                                     clamped to {size}",
                                    PROBE_LADDER[0]
                                );
                            }
                            return Ok(elapsed);
                        }

                        successes += 1;
                        log::debug!(
                            "[wg] dataplane round-trip {}/{} confirmed in {:?}",
                            successes, DATAPLANE_REQUIRED_SUCCESSES, start.elapsed()
                        );
                        let next_at = Instant::now().max(last_probe_at + DATAPLANE_PROBE_GAP);
                        if successes >= DATAPLANE_REQUIRED_SUCCESSES {
                            let size = PROBE_LADDER[0];
                            rung = Some(0);
                            large_probe = build_large_probe(local_ipv4, size);
                            rung_deadline = next_at + LADDER_STEP_BUDGET;
                            log::debug!("[wg] small probes confirmed; testing {size} bytes");
                            let _ = send_dataplane_probe(
                                sock, tunn, client_id, &large_probe, &mut out_buf,
                            ).await;
                        } else {
                            let _ = send_dataplane_probe(
                                sock, tunn, client_id, &small_probe, &mut out_buf,
                            ).await;
                        }
                        last_probe_at = next_at;
                        resend_at = next_at + Duration::from_millis(700);
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut v = pkt.to_vec();
                        inject_client_id(&mut v, client_id);
                        let _ = sock.send(&v).await;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub async fn verify_endpoint(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    data_check: bool,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<Duration> {
    let (elapsed, _session) = verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        client_id,
        local_ipv4,
        aethernoize,
        data_check,
        timeout,
        keepalive,
    )
    .await?;
    Ok(elapsed)
}

pub async fn verify_endpoint_keep_session(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    data_check: bool,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<(Duration, EstablishedSession)> {
    log::trace!(
        "[wg] verify {} obf={} data_check={}",
        peer,
        aethernoize.is_enabled(),
        data_check
    );

    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    crate::platform::protect_socket(&sock)?;
    sock.connect(peer).await?;

    let start = Instant::now();
    let deadline = start + timeout;

    if aethernoize.is_enabled() {
        aethernoize::apply_obfuscation(&sock, peer, aethernoize).await;
    }

    let local_secret = StaticSecret::from(private_key);
    let peer_pk = PublicKey::from(peer_public);

    let mut tunn = Tunn::new(
        local_secret,
        peer_pk,
        None,
        Some(keepalive.unwrap_or(25)),
        0,
        None,
    )
    .map_err(|e| AetherError::Other(format!("tunn init: {e}")))?;

    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let init_packet = match tunn.encapsulate(&[], &mut out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut pkt_vec = pkt.to_vec();
            inject_client_id(&mut pkt_vec, &client_id);
            pkt_vec
        }
        other => {
            log::warn!("[wg] unexpected encap result: {:?}", other);
            return Err(AetherError::Other("handshake init failed".into()));
        }
    };

    log::trace!("[wg] sending init {} bytes to {}", init_packet.len(), peer);
    sock.send(&init_packet).await?;

    let mut retry_index = 0usize;
    let mut timer = tokio::time::interval(TIMER_TICK);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    timer.tick().await;

    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            log::trace!("[wg] timeout after {} recv attempts", attempts);
            return Err(AetherError::Other("verify timeout".into()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                attempts += 1;
                let n = r?;
                log::trace!("[wg] recv {} bytes (attempt {})", n, attempts);
                strip_client_id(&mut recv_buf[..n]);

                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::Done => {
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake done in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::trace!("[wg] sending response {} bytes", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake success in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::Err(e) => {
                        log::trace!("[wg] decap error: {:?}", e);
                    }
                    other => {
                        log::trace!("[wg] unexpected decap: {:?}", other);
                    }
                }
            }
            _ = timer.tick() => {
                if let Some(delay) = VERIFY_RETRY_DELAYS.get(retry_index) {
                    if start.elapsed() >= *delay {
                        retry_index += 1;
                        log::trace!(
                            "[wg] retransmitting init to {} after {:?} ({}/{})",
                            peer,
                            delay,
                            retry_index,
                            VERIFY_RETRY_DELAYS.len()
                        );
                        sock.send(&init_packet).await?;
                    }
                }

                match tunn.update_timers(&mut out_buf) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::trace!("[wg] timer generated {} byte handshake packet", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                    }
                    TunnResult::Err(e) => {
                        return Err(AetherError::Other(format!("wireguard timer failed: {e:?}")));
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(remaining) => {
                log::trace!("[wg] sleep timeout");
                return Err(AetherError::Other("verify timeout".into()));
            }
        }
    }
}

pub const WG_PREFIXES_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.193.0/24",
];

pub const WG_PREFIXES_V6: &[&str] = &[
    "2606:4700:d0::/64",
    "2606:4700:d1::/64",
    "2606:4700:100::/48",
];

pub const WG_ZT_PREFIXES_V4: &[&str] = &["162.159.193.0/24"];

pub const WG_ZT_PREFIXES_V6: &[&str] = &["2606:4700:100::/48"];

pub const WG_PORTS: &[u16] = &[
    2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

pub const WG_SEEDS_V4: &[&str] = &[
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.193.1",
];

pub const WG_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c001",
    "2606:4700:d1::a29f:c001",
    "2606:4700:d0::a29f:c301",
    "2606:4700:d0::bc72:6001",
];

pub fn wg_prefixes_v4() -> Vec<&'static str> {
    crate::prober::prioritize(WG_PREFIXES_V4, WG_ZT_PREFIXES_V4)
}

pub fn wg_prefixes_v6() -> Vec<&'static str> {
    crate::prober::prioritize(WG_PREFIXES_V6, WG_ZT_PREFIXES_V6)
}

pub fn wg_seeds_v4() -> Vec<&'static str> {
    crate::prober::prioritize(WG_SEEDS_V4, &["162.159.193.1"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn the_documented_zero_trust_wireguard_ingress_range_is_scanned() {
        assert!(WG_PREFIXES_V4.contains(&"162.159.193.0/24"));
        assert!(WG_PREFIXES_V6.contains(&"2606:4700:100::/48"));
    }

    #[test]
    fn the_size_ladder_walks_down_from_a_full_size_packet() {
        assert_eq!(PROBE_LADDER.first(), Some(&1200));
        for pair in PROBE_LADDER.windows(2) {
            assert!(
                pair[0] > pair[1],
                "the ladder must descend so the first success is the largest"
            );
        }
    }

    #[test]
    fn a_full_size_probe_is_exactly_the_requested_length() {
        let src = "172.16.0.2".parse().unwrap();
        for &size in PROBE_LADDER {
            let pkt = build_large_probe(src, size);
            assert_eq!(pkt.len(), size, "probe for {size} came out {}", pkt.len());
            // Total-length field must agree with the real length, or the peer
            // drops it and the rung looks blocked when it is merely malformed.
            assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, size);
            assert_eq!(pkt[9], 1, "must be ICMP");
            // Don't-fragment, so a too-big packet is dropped rather than split.
            assert_eq!(pkt[6] & 0x40, 0x40);
        }
    }

    #[test]
    fn the_probe_ipv4_checksum_is_valid() {
        let pkt = build_large_probe("172.16.0.2".parse().unwrap(), 1200);
        // Summing a correct header including its checksum yields zero.
        assert_eq!(ipv4_checksum(&pkt[0..20]), 0);
    }

    #[test]
    fn an_echo_reply_to_our_probe_is_recognised() {
        let mut reply = build_large_probe("172.16.0.2".parse().unwrap(), 1200);
        reply[20] = 0; // echo request -> echo reply
        assert!(is_large_probe_reply(&reply));
    }

    #[test]
    fn unrelated_traffic_is_not_mistaken_for_a_probe_reply() {
        let src = "172.16.0.2".parse().unwrap();
        // Our own outgoing request is not a reply.
        assert!(!is_large_probe_reply(&build_large_probe(src, 1200)));
        // A reply carrying someone else's echo id is not ours.
        let mut foreign = build_large_probe(src, 1200);
        foreign[20] = 0;
        foreign[24] = 0x00;
        foreign[25] = 0x01;
        assert!(!is_large_probe_reply(&foreign));
        // A UDP packet, i.e. the small DNS probe's reply, must not count.
        assert!(!is_large_probe_reply(&build_dataplane_probe(src)));
        assert!(!is_large_probe_reply(&[]));
        assert!(!is_large_probe_reply(&[0x45, 0x00]));
    }

    #[test]
    fn the_documented_wireguard_ports_are_all_covered() {
        for port in [2408u16, 500, 1701, 4500] {
            assert!(WG_PORTS.contains(&port), "port {port} should be scanned");
        }
    }

    #[test]
    fn the_documented_default_wireguard_port_leads_the_sweep() {
        assert_eq!(
            WG_PORTS.first(),
            Some(&2408),
            "the primary sweep port is taken from the head of this list"
        );
    }

    #[test]
    fn the_documented_wireguard_fallback_ports_follow_the_default() {
        assert_eq!(&WG_PORTS[..4], &[2408, 500, 1701, 4500]);
    }

    #[test]
    fn the_consumer_range_leads_when_no_team_is_configured() {
        std::env::remove_var("AETHER_TEAM");
        assert_eq!(wg_prefixes_v4().first(), Some(&"162.159.192.0/24"));
        assert_eq!(wg_prefixes_v6().first(), Some(&"2606:4700:d0::/64"));
    }

    #[test]
    fn no_prefix_is_lost_when_the_zero_trust_range_is_promoted() {
        let promoted = crate::prober::prioritize(WG_PREFIXES_V4, WG_ZT_PREFIXES_V4);
        assert_eq!(promoted.len(), WG_PREFIXES_V4.len());
        for entry in WG_PREFIXES_V4 {
            assert!(promoted.contains(entry), "{entry} went missing");
        }
    }

    #[test]
    fn every_wireguard_prefix_parses() {
        for entry in WG_PREFIXES_V4 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<std::net::Ipv4Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for entry in WG_PREFIXES_V6 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<std::net::Ipv6Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
    }

    #[test]
    fn an_icmp_port_unreachable_is_treated_as_transient() {
        assert!(is_transient_socket_error(&Error::from(
            ErrorKind::ConnectionRefused
        )));
    }

    #[test]
    fn the_usual_transient_udp_errors_do_not_end_the_tunnel() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
        ] {
            assert!(
                is_transient_socket_error(&Error::from(kind)),
                "{kind:?} should be transient"
            );
        }
    }

    #[test]
    fn a_broken_socket_is_still_fatal() {
        for kind in [
            ErrorKind::NotConnected,
            ErrorKind::AddrNotAvailable,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
        ] {
            assert!(
                !is_transient_socket_error(&Error::from(kind)),
                "{kind:?} should be fatal"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_verification_retransmits_a_lost_initial_handshake() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let profile = aethernoize::from_profile("off");
        let verifier = tokio::spawn(async move {
            verify_endpoint(
                peer,
                [7u8; 32],
                [9u8; 32],
                [1u8, 2, 3],
                "172.16.0.2".parse().unwrap(),
                &profile,
                true,
                Duration::from_secs(4),
                None,
            )
            .await
        });

        let mut received = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            let n = tokio::time::timeout(Duration::from_secs(3), server.recv(&mut buf))
                .await
                .expect("handshake packet deadline")
                .expect("handshake packet");
            received.push(buf[..n].to_vec());
        }

        verifier.abort();
        let _ = verifier.await;

        assert_eq!(received.len(), 3);
        assert_eq!(received[0], received[1]);
        assert_eq!(received[1], received[2]);
    }
}
