use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3;
use quiche::h3::NameValue;
use rand::{RngExt, Rng};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::masque::{self, CapsuleParser};
use crate::noize::{self, NoizeConfig};
use crate::tls::{self, TlsParams};
use crate::{consts, error::AetherError, error::Result};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const MIN_DATAGRAM_SIZE: usize = 1200;

/// QUIC v2, the RFC 9369 version number. Some carrier middleboxes let the
/// v1 flow through untouched once a v2-looking flow has been seen on the same
/// 5-tuple — the version-negotiation trick from upstream Aether v2.0.0.
const QUIC_V2_VERSION: u32 = 0x6b33_43cf;
const QUIC_V2_BAIT_WAIT: Duration = Duration::from_millis(600);
const QUIC_V2_BAIT_LEN: usize = 1200;

/// Upstream: the bait is on unless explicitly turned off. AETHER_QUIC_V2 is
/// the escape hatch for a network where the extra packet hurts.
pub(crate) fn quic_v2_bait_enabled() -> bool {
    !matches!(
        std::env::var("AETHER_QUIC_V2").as_deref(),
        Ok("0") | Ok("off") | Ok("false") | Ok("no")
    )
}

/// Two-byte QUIC varint, the 0x4000-prefixed short form.
fn quic_varint2(value: u64) -> [u8; 2] {
    (((value & 0x3fff) as u16) | 0x4000).to_be_bytes()
}

/// A single throwaway QUIC v2 long-header packet of the minimum legal size.
///
/// It is never handshake material: the DCID/SCID are random, so the edge cannot
/// associate it with our real v1 connection. What it does is make a
/// version-negotiation (or version-mismatch drop) happen on the 5-tuple before
/// the v1 Client Initial follows, which is enough for filters that key on
/// "first QUIC version seen" to treat the rest of the flow as v2 and pass it
/// where they would otherwise drop v1. Mirrors upstream Aether v2.0.0
/// (`build_version_bait`) byte for byte.
fn build_version_bait() -> Vec<u8> {
    let mut rng = rand::rng();
    let mut dcid = [0u8; 8];
    let mut scid = [0u8; 8];
    rng.fill_bytes(&mut dcid);
    rng.fill_bytes(&mut scid);

    let mut pkt = Vec::with_capacity(QUIC_V2_BAIT_LEN);
    // 0xc3: long header + fixed bit, type 3 (the type value QUIC v2 uses for
    // Initial). v1 Initial is 0xc0; using v1's type byte would be another way
    // to do this, but upstream ships 0xc3 and field-testing was on that byte.
    pkt.push(0xc3);
    pkt.extend_from_slice(&QUIC_V2_VERSION.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(&scid);
    // Zero-length token.
    pkt.push(0x00);

    // The length field must cover the rest of the packet so the total is
    // exactly the QUIC minimum datagram size — an undersized Initial is
    // malformed and would be dropped before any version negotiation happened.
    let remaining = QUIC_V2_BAIT_LEN - pkt.len() - 2;
    pkt.extend_from_slice(&quic_varint2(remaining as u64));
    let mut pn = [0u8; 4];
    rng.fill_bytes(&mut pn);
    pkt.extend_from_slice(&pn);
    pkt.resize(QUIC_V2_BAIT_LEN, 0);
    pkt
}

/// Fire the bait and briefly listen for the version-negotiation reply.
///
/// The reply, if any, is discarded: it goes to a random DCID the real
/// connection will never use, and the purpose is the side effect on the
/// filter, not the payload. Up to `tries` attempts with `wait` between them;
/// both stops at the first answer, because a server that answered is a server
/// that saw the packet, which is all the bait is for.
async fn send_version_bait(sock: &UdpSocket, target: SocketAddr, wait: Duration, tries: usize) {
    let bait = build_version_bait();
    let connected = sock.peer_addr().is_ok();
    let mut buf = [0u8; 2048];

    for _attempt in 0..tries.max(1) {
        let sent = if connected {
            sock.send(&bait).await
        } else {
            sock.send_to(&bait, target).await
        };
        if sent.is_err() {
            return;
        }

        let answered = tokio::time::timeout(wait, async {
            if connected {
                sock.recv(&mut buf).await
            } else {
                sock.recv_from(&mut buf).await.map(|(n, _)| n)
            }
        })
        .await;

        match answered {
            Ok(Ok(_n)) => {
                log::debug!(
                    "[quic] version-negotiation bait answered; the path is open for v1"
                );
                return;
            }
            Ok(Err(_)) => return,
            Err(_) => continue,
        }
    }
}

fn net_queue() -> usize {
    crate::sysprofile::channel_capacity()
}

async fn bind_udp_fast(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, None).map_err(AetherError::Io)?;
    sock.set_nonblocking(true).map_err(AetherError::Io)?;

    let buf_size = crate::sysprofile::udp_socket_buf_bytes();
    let _ = sock.set_recv_buffer_size(buf_size);
    let _ = sock.set_send_buffer_size(buf_size);

    sock.bind(&bind_addr.into()).map_err(AetherError::Io)?;
    // VPN/TUN mode routes 0.0.0.0/0 into the tunnel. Protect this socket so
    // MASQUE/QUIC handshakes leave on the real network instead of looping.
    crate::platform::protect_socket(&sock).map_err(AetherError::Io)?;
    UdpSocket::from_std(sock.into()).map_err(AetherError::Io)
}

#[derive(Debug, Clone)]
pub enum Control {
    Migrate,
    Close,
}

#[derive(Debug, Clone)]
pub struct AssignedAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
    pub tls_curve_preset: crate::TlsCurvePreset,
    pub local_ipv4: Ipv4Addr,
    pub quiet: bool,
    /// Whether this tunnel may call [crate::ffi::mark_ready] on its own
    /// validation. The single-hop MASQUE tunnel owns the whole session, so it
    /// announces itself. In masque-in-masque neither hop does: the outer hop's
    /// validation says nothing about the inner hop that actually owns the TUN,
    /// and a premature announce is what made v1.8.8 show "connected" while no
    /// data plane existed. The MIM orchestrator announces once BOTH hops are
    /// up — see [run_masque_in_masque].
    pub announce: bool,
    /// Cap on the QUIC datagram size this tunnel may emit. The plain MASQUE
    /// tunnel leaves this at [MAX_DATAGRAM_SIZE]; the MIM inner hop shrinks it
    /// so the inner datagram fits inside the outer tunnel's QUIC payload.
    pub max_datagram: usize,
    /// Fire the QUIC v2 version-negotiation bait before the v1 Client Initial.
    pub version_bait: bool,
}

impl TunnelConfig {
    /// The effective datagram cap, clamped to the QUIC-legal range.
    pub fn datagram_budget(&self) -> usize {
        self.max_datagram.clamp(MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE)
    }
}

fn validation_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

fn data_check_enabled_for(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("yes") | Some("on"))
}

fn data_check_enabled() -> bool {
    data_check_enabled_for(std::env::var("AETHER_MASQUE_DATA_CHECK").ok().as_deref())
}

const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;

/// How many packets one `select!` wake-up may move in a single direction.
///
/// The loop used to move exactly one packet per wake-up, then run the whole
/// tail — `poll_h3`, `drain_datagrams`, `flush` — for that one packet. At
/// 100 Mbps a 1350-byte path carries roughly 9 000 packets/second, so the tail
/// ran 9 000 times a second and `flush` allocated a fresh 1350-byte buffer each
/// time. Draining what is already queued before running the tail amortises it.
///
/// Bounded, not unbounded: an unbounded drain would let a fast download hold the
/// loop indefinitely and starve the timeout branch, which is how the connection
/// loses its loss-detection timers.
const PACKET_BATCH: usize = 32;

pub struct Channels {
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub ctrl_tx: mpsc::Sender<Control>,
}

pub fn channels() -> (Channels, Internals) {
    let (outbound_tx, outbound_rx) = mpsc::channel(net_queue());
    let (inbound_tx, inbound_rx) = mpsc::channel(net_queue());
    let (ctrl_tx, ctrl_rx) = mpsc::channel(16);

    (
        Channels {
            outbound_tx,
            inbound_rx,
            ctrl_tx,
        },
        Internals {
            outbound_rx,
            inbound_tx,
            ctrl_rx,
        },
    )
}

pub struct Internals {
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    ctrl_rx: mpsc::Receiver<Control>,
}

impl Internals {
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Control>,
    ) {
        (self.outbound_rx, self.inbound_tx, self.ctrl_rx)
    }
}

type NetPacket = (SocketAddr, SocketAddr, Vec<u8>);

fn bind_addr_for(peer: &SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    }
}

fn random_scid() -> [u8; 16] {
    let mut scid = [0u8; 16];
    rand::rng().fill_bytes(&mut scid);
    scid
}

#[derive(Default)]
struct ReaderGuard {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ReaderGuard {
    fn push(&mut self, h: tokio::task::JoinHandle<()>) {
        self.handles.push(h);
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

fn spawn_reader(
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    tx: mpsc::Sender<NetPacket>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    log::trace!("recv {n} bytes from {from}");
                    if tx.send((local, from, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    log::debug!("recv error: {e}");
                    break;
                }
            }
        }
    })
}

pub async fn run(
    cfg: TunnelConfig,
    mut internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let peer = cfg.peer;
    let quiet = cfg.quiet;
    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(cfg.local_ipv4);
    let mut ready_tx = ready_tx;
    let mut ready_fired = false;
    let mut validate_deadline: Option<Instant> = None;
    let mut validate_successes: u32 = 0;
    // Device packets discarded while the tunnel was still being accepted.
    let mut predelivery_drops: u64 = 0;

    let init_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let local = init_sock.local_addr()?;
    let init_sock = Arc::new(init_sock);

    // Upstream Aether v2.0.0: before the v1 Client Initial, send one throwaway
    // QUIC v2 long-header packet on the same socket. Filters that classify the
    // flow by the first QUIC version they see then treat the v1 handshake that
    // follows as v2 traffic and pass it — which revives MASQUE on networks
    // where the v1 fingerprint alone was being dropped. Two tries with a
    // short listen, then the real handshake proceeds either way.
    if cfg.version_bait && quic_v2_bait_enabled() {
        send_version_bait(&init_sock, peer, QUIC_V2_BAIT_WAIT, 2).await;
    }

    let (net_tx, mut net_rx) = mpsc::channel::<NetPacket>(net_queue());

    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    sockets.insert(local, init_sock.clone());
    let mut readers = ReaderGuard::default();
    readers.push(spawn_reader(init_sock, local, net_tx.clone()));

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &cfg.cert_pem,
        key_pem: &cfg.key_pem,
        curve_preset: cfg.tls_curve_preset,
        pin_endpoint: false,
        expected_pins: &[],
    })?;

    // The MIM inner hop shrinks this below MAX_DATAGRAM_SIZE so an inner QUIC
    // datagram fits inside the outer tunnel's payload; the plain tunnel leaves
    // it at the default and this is a no-op. quiche clamps at 1200 minimum.
    let datagram = cfg.datagram_budget();
    config.set_max_send_udp_payload_size(datagram);
    config.set_max_recv_udp_payload_size(datagram);

    let mut current_ech = cfg.ech_config_list.clone();

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;

    if let Some(ref ech) = current_ech {
        tls::inject_ech(&mut conn, ech)?;
        log::info!("ech config injected ({} bytes)", ech.len());
    }

    let h3_config = h3::Config::new()?;
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;
    let mut capsules = CapsuleParser::new();
    let mut established_ever = false;
    let mut ech_retried = false;

    if let Some(sock) = sockets.get(&local) {
        noize::pre_handshake(sock.as_ref(), peer, &cfg.noize).await;
    }

    let mut send_buf = vec![0u8; MAX_DATAGRAM_SIZE];
    flush(&mut conn, &sockets, &mut send_buf).await?;

    let mut out_buf = vec![0u8; 65535];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(20));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut probe_interval = tokio::time::interval(Duration::from_millis(700));
    probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut ctrl_open = true;
    let mut outbound_open = true;

    loop {
        if data_check && !ready_fired {
            if let Some(dl) = validate_deadline {
                if Instant::now() >= dl {
                    log::warn!(
                        "[-] masque data-plane validation timed out; edge {peer} accepts control but drops traffic"
                    );
                    let _ = conn.close(true, 0x00, b"validation-timeout");
                    return Err(AetherError::Masque(
                        "data-plane validation timeout (handshake ok, no traffic)".into(),
                    ));
                }
            }
        }

        let timeout = conn.timeout();

        // NOT `biased`. With biased polling tokio takes the first ready arm in
        // declaration order, and `net_rx` is never empty during a download — so
        // the arms below it (device traffic out, and `conn.on_timeout()`) were
        // never polled at all. Two things broke as a result:
        //
        //   * the device's own TCP ACKs could not leave the phone, so every
        //     download collapsed to a stall-and-recover crawl;
        //   * QUIC loss detection never ran, so a lost packet was only noticed
        //     when the peer happened to retransmit.
        //
        // Unbiased polling starts at a random arm each time, so every arm makes
        // progress. `PACKET_BATCH` is what keeps that efficient: each arm drains
        // a bounded burst per wake-up instead of one packet.
        tokio::select! {
            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    if let Err(e) = conn.send_ack_eliciting() {
                        log::debug!("keepalive ping failed: {e}");
                    }
                }
            }

            _ = probe_interval.tick(), if data_check && !ready_fired => {
                if let Some(sid) = req_stream {
                    match masque::encode_ip_datagram(sid, &probe_packet) {
                        Ok(framed) => {
                            if let Err(e) = conn.dgram_send(&framed) {
                                log::trace!("data-plane probe send: {e}");
                            }
                        }
                        Err(e) => log::trace!("data-plane probe encode: {e}"),
                    }
                }
            }

            Some((to_local, from, mut data)) = net_rx.recv() => {
                let mut hdr_buf = data.clone();
                if let Ok(hdr) = quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN) {
                    log::trace!("recv {} bytes type={:?} version=0x{:x} from {}", data.len(), hdr.ty, hdr.version, from);
                }
                let info = quiche::RecvInfo { from, to: to_local };
                if let Err(e) = conn.recv(&mut data, info) {
                    log::trace!("recv error: {e}");
                }

                // Drain whatever else the socket reader already has queued before
                // falling through to poll_h3/drain_datagrams/flush. Under load the
                // channel is never empty, so without this the expensive tail runs
                // once per received packet.
                for _ in 1..PACKET_BATCH {
                    match net_rx.try_recv() {
                        Ok((to_local, from, mut data)) => {
                            let info = quiche::RecvInfo { from, to: to_local };
                            if let Err(e) = conn.recv(&mut data, info) {
                                log::trace!("recv error: {e}");
                            }
                        }
                        Err(_) => break,
                    }
                }
            }

            ctrl = internals.ctrl_rx.recv(), if ctrl_open => {
                match ctrl {
                    Some(Control::Migrate) => {
                        if let Err(e) = do_migrate(&mut conn, peer, &mut sockets, &net_tx, &mut readers).await {
                            log::warn!("migration failed: {e}");
                        }
                    }
                    Some(Control::Close) => {
                        ctrl_open = false;
                        let _ = conn.close(true, 0x00, b"bye");
                    }
                    None => {
                        ctrl_open = false;
                        let _ = conn.close(true, 0x00, b"bye");
                    }
                }
            }

            pkt = internals.outbound_rx.recv(), if outbound_open => {
                match pkt {
                    Some(ip_packet) => {
                        // Only carry device traffic once the edge has accepted the
                        // CONNECT-IP request. Before that the packets are
                        // undeliverable *and* actively harmful:
                        //
                        // Android brings the TUN up before the tunnel exists, so by
                        // the time this connection is dialled the kernel already
                        // holds seconds of the whole device's traffic. The instant
                        // `req_stream` became Some, that entire backlog used to be
                        // encoded into QUIC DATAGRAMs on a brand-new connection
                        // whose congestion window is still at its initial value —
                        // starving the very CONNECT-IP request whose response we
                        // are waiting for. Field log: the same gateway answered a
                        // 2-second pre-flight verify, then the real tunnel sat for
                        // the full 30s startup timeout and only connected on the
                        // retry, when the backlog had already been drained.
                        //
                        // Keep draining the channel so the TUN reader never blocks;
                        // just do not hand the packets to QUIC yet.
                        match (req_stream, ready_fired) {
                            (Some(sid), true) => match masque::encode_ip_datagram(sid, &ip_packet) {
                                Ok(framed) => {
                                    if let Err(e) = conn.dgram_send(&framed) {
                                        log::trace!("dgram_send: {e}");
                                    }
                                }
                                Err(e) => log::trace!("encap: {e}"),
                            },
                            _ => predelivery_drops += 1,
                        }

                        // Same batching as the inbound arm: during an upload the
                        // TUN reader keeps this channel full, and one packet per
                        // wake-up is what made the upload direction slow.
                        if let (Some(sid), true) = (req_stream, ready_fired) {
                            for _ in 1..PACKET_BATCH {
                                match internals.outbound_rx.try_recv() {
                                    Ok(next) => match masque::encode_ip_datagram(sid, &next) {
                                        Ok(framed) => {
                                            if let Err(e) = conn.dgram_send(&framed) {
                                                log::trace!("dgram_send: {e}");
                                                break;
                                            }
                                        }
                                        Err(e) => log::trace!("encap: {e}"),
                                    },
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    None => {
                        outbound_open = false;
                        let _ = conn.close(true, 0x00, b"eof");
                    }
                }
            }

            _ = sleep_opt(timeout) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            established_ever = true;
            log_or_debug(
                quiet,
                format!(
                    "quic handshake established; alpn={}",
                    String::from_utf8_lossy(conn.application_proto())
                ),
            );
            let mut h3c = h3::Connection::with_transport(&mut conn, &h3_config)?;
            let headers = masque::connect_ip_request(&cfg.authority, &cfg.path);
            let sid = h3c.send_request(&mut conn, &headers, false)?;
            log_or_debug(quiet, format!("connect-ip request sent on stream {sid}"));
            req_stream = Some(sid);
            h3_conn = Some(h3c);

            if data_check {
                validate_deadline = Some(Instant::now() + validation_timeout());
                log_or_debug(
                    quiet,
                    "[*] validating masque data-plane before exposing socks5".to_string(),
                );
            }
        }

        let mut connect_ip_ok = false;
        if let (Some(h3c), Some(sid)) = (h3_conn.as_mut(), req_stream) {
            connect_ip_ok = poll_h3(&mut conn, h3c, sid, &mut capsules, &addr_tx, quiet)?;
        }
        if connect_ip_ok && !data_check && !ready_fired {
            ready_fired = true;
            if cfg.announce {
                crate::ffi::mark_ready();
            }
            if predelivery_drops > 0 {
                log_or_debug(
                    quiet,
                    format!(
                        "[*] dropped {predelivery_drops} device packet(s) queued before the edge accepted CONNECT-IP"
                    ),
                );
            }
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(());
            }
        }

        let got_data = drain_datagrams(&mut conn, req_stream, &internals.inbound_tx, &mut out_buf);

        if got_data && !ready_fired {
            validate_successes += 1;
            log::debug!(
                "[*] masque data-plane round-trip {}/{} confirmed",
                validate_successes,
                DATA_PROBE_REQUIRED_SUCCESSES
            );
            if validate_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                ready_fired = true;
                validate_deadline = None;
                if cfg.announce {
                    crate::ffi::mark_ready();
                }
                if predelivery_drops > 0 {
                    log_or_debug(
                        quiet,
                        format!(
                            "[*] dropped {predelivery_drops} device packet(s) queued before data-plane validation"
                        ),
                    );
                }
                if let Some(tx) = ready_tx.take() {
                    let _ = tx.send(());
                }
                log_or_debug(
                    quiet,
                    "[+] masque tunnel validated (end-to-end data confirmed); exposing socks5"
                        .to_string(),
                );
            }
        }

        flush(&mut conn, &sockets, &mut send_buf).await?;

        if conn.is_closed() {
            if !established_ever && !ech_retried && current_ech.is_some() {
                if let Some(retry) = tls::extract_ech_retry_configs(&mut conn) {
                    log::warn!(
                        "ech_required: retrying handshake with server retry_configs ({} bytes)",
                        retry.len()
                    );
                    ech_retried = true;
                    current_ech = Some(retry);

                    let scid_bytes = random_scid();
                    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
                    conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;
                    if let Some(ref ech) = current_ech {
                        tls::inject_ech(&mut conn, ech)?;
                    }

                    h3_conn = None;
                    req_stream = None;
                    capsules = CapsuleParser::new();
                    flush(&mut conn, &sockets, &mut send_buf).await?;
                    continue;
                }
            }

            log_or_debug(quiet, format!("connection closed: {:?}", conn.stats()));
            if let Some(e) = conn.peer_error() {
                log_or_debug(
                    quiet,
                    format!(
                        "peer closed: code=0x{:x} app={} reason={}",
                        e.error_code,
                        e.is_app,
                        String::from_utf8_lossy(&e.reason)
                    ),
                );
            }
            if let Some(e) = conn.local_error() {
                log_or_debug(
                    quiet,
                    format!(
                        "local closed: code=0x{:x} app={} reason={}",
                        e.error_code,
                        e.is_app,
                        String::from_utf8_lossy(&e.reason)
                    ),
                );
            }
            return Ok(());
        }
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn log_or_debug(quiet: bool, msg: String) {
    if quiet {
        log::debug!("{msg}");
    } else {
        log::info!("{msg}");
    }
}

fn poll_h3(
    conn: &mut quiche::Connection,
    h3c: &mut h3::Connection,
    req_stream: u64,
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    quiet: bool,
) -> Result<bool> {
    let mut body = vec![0u8; 65535];
    let mut connect_ip_ok = false;

    loop {
        match h3c.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                if stream_id != req_stream {
                    continue;
                }
                for h in &list {
                    if h.name() == b":status" {
                        log_or_debug(
                            quiet,
                            format!("connect-ip status: {}", String::from_utf8_lossy(h.value())),
                        );
                        if h.value() == b"200" {
                            connect_ip_ok = true;
                        } else {
                            return Err(AetherError::Other(format!(
                                "connect-ip status {}",
                                String::from_utf8_lossy(h.value())
                            )));
                        }
                    }
                }
            }

            Ok((stream_id, h3::Event::Data)) => {
                if stream_id != req_stream {
                    continue;
                }
                while let Ok(n) = h3c.recv_body(conn, stream_id, &mut body) {
                    if n == 0 {
                        break;
                    }
                    capsules.push(&body[..n]);
                }
                drain_capsules(capsules, addr_tx);
            }

            Ok((_stream_id, h3::Event::Finished)) => {}
            Ok((_stream_id, h3::Event::Reset(_))) => {}
            Ok(_) => {}

            Err(h3::Error::Done) => break,
            Err(e) => return Err(AetherError::H3(e)),
        }
    }

    Ok(connect_ip_ok)
}

fn drain_capsules(capsules: &mut CapsuleParser, addr_tx: &Option<mpsc::Sender<AssignedAddr>>) {
    loop {
        match capsules.next() {
            Ok(Some(masque::Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("edge assigned {}/{}", ip, a.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: a.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(masque::Capsule::RouteAdvertisement(routes))) => {
                log::info!("received {} route advertisements", routes.len());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                log::trace!("capsule parse: {e}");
                break;
            }
        }
    }
}

fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
    match version {
        4 if bytes.len() == 4 => Some(IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into())),
        6 if bytes.len() == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

fn drain_datagrams(
    conn: &mut quiche::Connection,
    req_stream: Option<u64>,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    buf: &mut [u8],
) -> bool {
    let sid = match req_stream {
        Some(s) => s,
        None => return false,
    };

    let mut delivered = false;
    loop {
        match conn.dgram_recv(buf) {
            Ok(n) => match masque::decode_ip_datagram(&buf[..n], sid) {
                Ok(Some(ip_packet)) => {
                    delivered = true;
                    match inbound_tx.try_send(ip_packet) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            log::trace!("inbound queue full, dropping datagram");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return delivered,
                    }
                }
                Ok(None) => {}
                Err(e) => log::trace!("decap: {e}"),
            },
            Err(quiche::Error::Done) => break,
            Err(e) => {
                log::trace!("dgram_recv: {e}");
                break;
            }
        }
    }
    delivered
}

/// Drain quiche's send queue onto the wire.
///
/// The scratch buffer is caller-owned on purpose. This runs once per loop
/// iteration — thousands of times a second on a fast tunnel — and allocating a
/// fresh 1350-byte `Vec` each call put a hot allocation directly in the data
/// path.
async fn flush(
    conn: &mut quiche::Connection,
    sockets: &HashMap<SocketAddr, Arc<UdpSocket>>,
    out: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                if let Some(sock) = sockets.get(&send_info.from) {
                    sock.send_to(&out[..write], send_info.to).await?;
                } else if let Some((_, sock)) = sockets.iter().next() {
                    sock.send_to(&out[..write], send_info.to).await?;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(AetherError::Quic(e)),
        }
    }

    Ok(())
}

async fn do_migrate(
    conn: &mut quiche::Connection,
    peer: SocketAddr,
    sockets: &mut HashMap<SocketAddr, Arc<UdpSocket>>,
    net_tx: &mpsc::Sender<NetPacket>,
    readers: &mut ReaderGuard,
) -> Result<()> {
    if conn.available_dcids() == 0 {
        return Err(AetherError::Other("no spare dcids for migration".into()));
    }

    let new_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let new_local = new_sock.local_addr()?;
    let new_sock = Arc::new(new_sock);

    sockets.insert(new_local, new_sock.clone());
    readers.push(spawn_reader(new_sock, new_local, net_tx.clone()));

    conn.probe_path(new_local, peer)?;
    let seq = conn.migrate_source(new_local)?;
    log::info!("migrated to local {new_local} (path seq {seq})");

    Ok(())
}

pub fn default_authority() -> &'static str {
    "cloudflareaccess.com"
}

pub fn default_path() -> &'static str {
    "/"
}

pub fn default_sni() -> &'static str {
    consts::CONNECT_SNI
}

#[derive(Clone)]
pub struct VerifyParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
    pub tls_curve_preset: crate::TlsCurvePreset,
    pub timeout: Duration,
    pub local_ipv4: Ipv4Addr,
}

pub async fn verify_masque(p: &VerifyParams) -> Result<Duration> {
    let bind: SocketAddr = if p.peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = bind_udp_fast(bind).await?;
    sock.connect(p.peer).await?;
    let local = sock.local_addr()?;

    // Same bait as the tunnel path (upstream fires it here too): a gateway
    // verify that never gets through the filter would rule out a peer the
    // real connection might have reached.
    if quic_v2_bait_enabled() {
        send_version_bait(&sock, p.peer, Duration::from_millis(500), 1).await;
    }

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &p.cert_pem,
        key_pem: &p.key_pem,
        curve_preset: p.tls_curve_preset,
        pin_endpoint: false,
        expected_pins: &[],
    })?;

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(&p.sni), &scid, local, p.peer, &mut config)?;

    if let Some(ref ech) = p.ech_config_list {
        let _ = tls::inject_ech(&mut conn, ech);
    }

    let h3_config = h3::Config::new()?;
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;

    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(p.local_ipv4);
    let mut connect_ip_ok = false;
    let mut last_probe = Instant::now();
    let mut dgram_buf = vec![0u8; 65535];
    let mut probe_successes: u32 = 0;

    let start = Instant::now();
    let deadline = start + p.timeout;

    noize::pre_handshake(&sock, p.peer, &p.noize).await;

    flush_connected(&mut conn, &sock).await?;

    let mut buf = vec![0u8; 65535];

    loop {
        if Instant::now() >= deadline {
            // Say where the timeout happened. A timeout during the handshake
            // means UDP/443 to this address is being dropped; a timeout after the
            // connect-ip request means the gateway completed TLS, read our
            // certificate and then never answered the CONNECT. The old flat
            // "verify timeout" could not tell those apart.
            return Err(AetherError::Other(format!(
                "verify timeout {}",
                verify_stage(&conn, req_stream.is_some())
            )));
        }

        let wait = match conn.timeout() {
            Some(t) => t.min(remaining(deadline)),
            None => remaining(deadline),
        };
        let wait = if connect_ip_ok {
            wait.min(Duration::from_millis(250))
        } else {
            wait
        };

        tokio::select! {
            r = sock.recv(&mut buf) => {
                match r {
                    Ok(n) => {
                        let mut hdr_buf = buf[..n].to_vec();
                        if let Ok(hdr) = quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN) {
                            log::trace!("verify recv {} bytes type={:?} version=0x{:x} from {}", n, hdr.ty, hdr.version, p.peer);
                        }
                        let info = quiche::RecvInfo { from: p.peer, to: local };
                        if let Err(e) = conn.recv(&mut buf[..n], info) {
                            log::trace!("verify recv error from {}: {e}", p.peer);
                        }
                    }
                    Err(e) => return Err(AetherError::Io(e)),
                }
            }
            _ = tokio::time::sleep(wait) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            let mut h3c = h3::Connection::with_transport(&mut conn, &h3_config)?;
            let headers = masque::connect_ip_request(&p.authority, &p.path);
            let sid = h3c.send_request(&mut conn, &headers, false)?;
            req_stream = Some(sid);
            h3_conn = Some(h3c);
        }

        if let (Some(h3c), Some(sid)) = (h3_conn.as_mut(), req_stream) {
            loop {
                match h3c.poll(&mut conn) {
                    Ok((stream_id, h3::Event::Headers { list, .. })) if stream_id == sid => {
                        for h in &list {
                            if h.name() == b":status" {
                                if h.value() == b"200" {
                                    if !data_check {
                                        // Hand the session back before leaving.
                                        // See `close_verify` for why this matters.
                                        close_verify(&mut conn, &sock).await;
                                        return Ok(start.elapsed());
                                    }
                                    connect_ip_ok = true;
                                    if let Some(sid) = req_stream {
                                        if let Ok(framed) =
                                            masque::encode_ip_datagram(sid, &probe_packet)
                                        {
                                            let _ = conn.dgram_send(&framed);
                                        }
                                    }
                                    last_probe = Instant::now();
                                } else {
                                    return Err(AetherError::Other(format!(
                                        "status {}",
                                        String::from_utf8_lossy(h.value())
                                    )));
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(h3::Error::Done) => break,
                    Err(e) => return Err(AetherError::H3(e)),
                }
            }
        }

        if connect_ip_ok {
            if last_probe.elapsed() >= Duration::from_millis(700) {
                if let Some(sid) = req_stream {
                    if let Ok(framed) = masque::encode_ip_datagram(sid, &probe_packet) {
                        let _ = conn.dgram_send(&framed);
                    }
                }
                last_probe = Instant::now();
            }

            if let Some(sid) = req_stream {
                loop {
                    match conn.dgram_recv(&mut dgram_buf) {
                        Ok(n) => {
                            if let Ok(Some(_)) = masque::decode_ip_datagram(&dgram_buf[..n], sid) {
                                probe_successes += 1;
                                if probe_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                    close_verify(&mut conn, &sock).await;
                                    return Ok(start.elapsed());
                                }
                                if let Ok(framed) = masque::encode_ip_datagram(sid, &probe_packet) {
                                    let _ = conn.dgram_send(&framed);
                                }
                                last_probe = Instant::now();
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(_) => break,
                    }
                }
            }
        }

        flush_connected(&mut conn, &sock).await?;

        if conn.is_closed() {
            return Err(AetherError::Other(verify_close_reason(
                &conn,
                req_stream.is_some(),
            )));
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Names the TLS alert carried inside a QUIC CRYPTO_ERROR code.
///
/// RFC 9001 §4.8 maps a TLS alert onto transport error code `0x100 + alert`, so
/// the alert number is the only part of a certificate rejection that reaches us.
/// Naming them is what makes the log actionable, because they diagnose
/// completely different problems: `certificate_expired` means the WARP device
/// registration needs refreshing, `unknown_ca` means the peer is not the gateway
/// we think it is, and `handshake_failure` usually means the ClientHello never
/// arrived intact.
fn tls_alert_name(alert: u64) -> Option<&'static str> {
    Some(match alert {
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => return None,
    })
}

/// Render a `CONNECTION_CLOSE` in terms of what it says about the failure.
fn describe_connection_error(err: &quiche::ConnectionError) -> String {
    let mut text = if err.is_app {
        format!("application error 0x{:x}", err.error_code)
    } else if (0x100..=0x1ff).contains(&err.error_code) {
        let alert = err.error_code - 0x100;
        match tls_alert_name(alert) {
            Some(name) => format!("TLS alert {alert} ({name})"),
            None => format!("TLS alert {alert}"),
        }
    } else {
        format!("transport error 0x{:x}", err.error_code)
    };

    let reason = String::from_utf8_lossy(&err.reason);
    let reason = reason.trim();
    if !reason.is_empty() {
        text.push_str(": ");
        text.push_str(reason);
    }
    text
}

/// The `verify_stage` marker meaning "QUIC and TLS both completed and the
/// connect-ip request was sent".
///
/// Public because `is_identity_rejection` in the dialler keys off it: on the QUIC
/// path an authorization refusal arrives as a `CONNECTION_CLOSE` carrying TLS
/// alert 49, with no `:status` to parse, and the *stage* is what separates that
/// from a certificate rejected during the handshake. Sharing the constant keeps
/// the two in step — a reworded message here would otherwise silently stop the
/// classifier from recognising a refused identity.
pub const CONNECT_STAGE_AFTER_REQUEST: &str = "after the connect-ip request, before any :status";

/// How far the verify attempt got before it stopped.
///
/// The stage is the diagnostically valuable half. "Never established" means the
/// QUIC handshake itself did not complete — UDP/443 to this address is being
/// dropped or mangled. "After the connect-ip request" means QUIC and TLS both
/// succeeded, the gateway read our client certificate, and it then refused or
/// abandoned the CONNECT — a completely different problem with a completely
/// different fix.
fn verify_stage(conn: &quiche::Connection, connect_sent: bool) -> &'static str {
    if !conn.is_established() {
        "during the QUIC handshake"
    } else if connect_sent {
        CONNECT_STAGE_AFTER_REQUEST
    } else {
        "after the handshake, before the connect-ip request"
    }
}

/// Why a verify connection closed, in a form worth putting in a field log.
///
/// Replaces the flat `closed before data-plane confirmation`, which collapsed
/// every one of these causes into one sentence and so could not distinguish a
/// rejected certificate from a blocked UDP path. Both appeared identically in the
/// Iranian logs across a hundred consecutive gateways, which made the logs
/// unusable for deciding what to fix.
fn verify_close_reason(conn: &quiche::Connection, connect_sent: bool) -> String {
    let stage = verify_stage(conn, connect_sent);

    let cause = if let Some(err) = conn.peer_error() {
        format!(
            "gateway sent CONNECTION_CLOSE ({})",
            describe_connection_error(err)
        )
    } else if let Some(err) = conn.local_error() {
        format!("closed locally ({})", describe_connection_error(err))
    } else if conn.is_timed_out() {
        "idle timeout, no CONNECTION_CLOSE".to_string()
    } else {
        "no CONNECTION_CLOSE frame".to_string()
    };

    format!("closed {stage}: {cause}")
}

/// End a verify connection politely instead of just dropping the socket.
///
/// `verify_masque` proves a gateway will serve CONNECT-IP, then the caller dials
/// the *same* gateway again for the real tunnel. Both connections present the
/// same client certificate, and CONNECT-IP assigns the client an IP address per
/// session — so an abandoned verify session is not free. Without a
/// CONNECTION_CLOSE the edge cannot know we are gone and keeps that session (and
/// its address assignment) alive until its own idle timeout, which is the same
/// order of magnitude as the dead air seen in the field log between a successful
/// verify and a tunnel that never received its `:status 200`.
///
/// Sending CONNECTION_CLOSE costs one datagram and removes that whole class of
/// failure. Errors are ignored on purpose: we are leaving either way, and the
/// verdict for the caller has already been decided.
async fn close_verify(conn: &mut quiche::Connection, sock: &UdpSocket) {
    let _ = conn.close(true, 0x00, b"verify-done");
    let _ = flush_connected(conn, sock).await;
}

async fn flush_connected(conn: &mut quiche::Connection, sock: &UdpSocket) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((write, _info)) => {
                sock.send(&out[..write]).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(AetherError::Quic(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod v2_bait_tests {
    use super::*;

    #[test]
    fn the_bait_is_a_v2_versioned_long_header_of_the_minimum_size() {
        let pkt = build_version_bait();
        assert_eq!(pkt.len(), QUIC_V2_BAIT_LEN);
        assert_eq!(pkt[0] & 0x80, 0x80, "long header form bit must be set");
        assert_eq!(pkt[0] & 0x40, 0x40, "fixed bit must be set");
        assert_eq!(
            u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]),
            QUIC_V2_VERSION,
            "the version field must be QUIC v2 so the filter treats the flow as v2"
        );
        assert_eq!(pkt[5], 8, "destination connection id length");
        assert_eq!(pkt[14], 8, "source connection id length");
    }

    #[test]
    fn two_baits_do_not_share_connection_ids() {
        let a = build_version_bait();
        let b = build_version_bait();
        assert_ne!(a[6..14], b[6..14], "each bait must use a fresh dcid");
    }

    #[test]
    fn the_bait_is_on_unless_it_is_turned_off() {
        // SAFETY: single-threaded test, and env mutation is the thing under test.
        std::env::remove_var("AETHER_QUIC_V2");
        assert!(quic_v2_bait_enabled());
    }

    #[tokio::test]
    async fn the_bait_triggers_a_version_negotiation_from_a_v1_only_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, QUIC_V2_BAIT_LEN);
            let dcid = buf[6..14].to_vec();
            let scid = buf[15..23].to_vec();
            let mut vn = vec![0xc0, 0x00, 0x00, 0x00, 0x00];
            vn.push(scid.len() as u8);
            vn.extend_from_slice(&scid);
            vn.push(dcid.len() as u8);
            vn.extend_from_slice(&dcid);
            vn.extend_from_slice(&1u32.to_be_bytes());
            server.send_to(&vn, from).await.unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        send_version_bait(&client, server_addr, Duration::from_secs(2), 1).await;
        responder.await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::{data_check_enabled_for, describe_connection_error, tls_alert_name};

    #[test]
    fn h3_data_validation_is_opt_in() {
        assert!(!data_check_enabled_for(None));
        assert!(data_check_enabled_for(Some("true")));
    }

    /// A CRYPTO_ERROR is decoded into the TLS alert it carries.
    ///
    /// This is the case the flat log message hid. `0x100 + 45` is
    /// `certificate_expired` — the gateway telling us the WARP registration is
    /// stale, which is a fix on our side and nothing to do with the network.
    #[test]
    fn a_crypto_error_names_the_tls_alert() {
        let err = quiche::ConnectionError {
            is_app: false,
            error_code: 0x100 + 45,
            reason: Vec::new(),
        };

        assert_eq!(
            describe_connection_error(&err),
            "TLS alert 45 (certificate_expired)"
        );
    }

    /// An unnamed alert still reports its number rather than being swallowed.
    #[test]
    fn an_unknown_tls_alert_still_reports_its_number() {
        let err = quiche::ConnectionError {
            is_app: false,
            error_code: 0x100 + 99,
            reason: Vec::new(),
        };

        assert_eq!(describe_connection_error(&err), "TLS alert 99");
    }

    /// A non-crypto transport error is reported as a transport code, not
    /// misdecoded as an alert.
    ///
    /// Guards the `0x100..=0x1ff` range check: `0x2` is PROTOCOL_VIOLATION and
    /// must not be rendered as "TLS alert".
    #[test]
    fn a_transport_error_is_not_mistaken_for_a_tls_alert() {
        let err = quiche::ConnectionError {
            is_app: false,
            error_code: 0x2,
            reason: Vec::new(),
        };

        assert_eq!(describe_connection_error(&err), "transport error 0x2");
    }

    /// An application close is labelled as such.
    ///
    /// HTTP/3 error codes live in this space, so mislabelling them as transport
    /// errors would point debugging at the wrong layer.
    #[test]
    fn an_application_error_is_labelled_as_application() {
        let err = quiche::ConnectionError {
            is_app: true,
            error_code: 0x101,
            reason: Vec::new(),
        };

        assert_eq!(describe_connection_error(&err), "application error 0x101");
    }

    /// The reason phrase from the CONNECTION_CLOSE is appended when present.
    ///
    /// Cloudflare puts human-readable text here; it is the most direct statement
    /// of why a gateway refused us and was previously discarded entirely.
    #[test]
    fn the_reason_phrase_is_included_when_the_gateway_sends_one() {
        let err = quiche::ConnectionError {
            is_app: false,
            error_code: 0x100 + 48,
            reason: b"bad client cert".to_vec(),
        };

        assert_eq!(
            describe_connection_error(&err),
            "TLS alert 48 (unknown_ca): bad client cert"
        );
    }

    /// An empty or whitespace-only reason must not leave a dangling separator.
    #[test]
    fn an_empty_reason_phrase_adds_nothing() {
        let err = quiche::ConnectionError {
            is_app: false,
            error_code: 0x100 + 40,
            reason: b"   ".to_vec(),
        };

        assert_eq!(
            describe_connection_error(&err),
            "TLS alert 40 (handshake_failure)"
        );
    }

    /// The alerts that change what we would do about a failure are all named.
    ///
    /// Each of these implies a different action: refresh the registration, stop
    /// trusting the peer, or look at whether the ClientHello survived the path.
    #[test]
    fn the_diagnostically_important_alerts_are_named() {
        assert_eq!(tls_alert_name(45), Some("certificate_expired"));
        assert_eq!(tls_alert_name(48), Some("unknown_ca"));
        assert_eq!(tls_alert_name(40), Some("handshake_failure"));
        assert_eq!(tls_alert_name(116), Some("certificate_required"));
        assert_eq!(tls_alert_name(49), Some("access_denied"));
        assert_eq!(tls_alert_name(200), None);
    }
}
