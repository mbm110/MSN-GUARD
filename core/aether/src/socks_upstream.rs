//! tun2socks bridge: reads raw IPv4 packets from a TUN fd,
//! parses TCP/UDP, and forwards through an upstream SOCKS5 proxy.
//! Includes proper TCP/UDP/IP checksums, bidirectional forwarding, DNS-over-TCP.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::error::{AetherError, Result};
use crate::ffi;

// ─── checksum helpers ───────────────────────────────────────────────

/// One's complement sum over a byte buffer (for IP/TCP/UDP checksums).
fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// IPv4 header checksum (over the 20-byte basic header).
fn ip_checksum(pkt: &[u8]) -> u16 {
    ones_complement_sum(&pkt[..20])
}

/// TCP checksum over IPv4 pseudo-header + TCP segment.
fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let tcp_len = tcp_segment.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0); // reserved
    pseudo.push(6); // protocol = TCP
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    ones_complement_sum(&pseudo)
}

/// UDP checksum over IPv4 pseudo-header + UDP segment.
fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let udp_len = udp_segment.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0); // reserved
    pseudo.push(17); // protocol = UDP
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    let cksum = ones_complement_sum(&pseudo);
    if cksum == 0 { 0xFFFF } else { cksum }
}

// ─── helpers ────────────────────────────────────────────────────────

fn ip_to_bytes(ip: Ipv4Addr) -> [u8; 4] { ip.octets() }
fn ip_from_bytes(b: &[u8]) -> Ipv4Addr { Ipv4Addr::new(b[0], b[1], b[2], b[3]) }

struct TcpConn {
    /// Send data from app → SOCKS5 (via channel, no lock contention)
    data_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Shared ACK value — updated by handle_tcp, read by tun_response_reader
    ack_shared: Arc<AtomicU32>,
    /// Our sequence number for packets sent to TUN
    seq_to_tun: u32,
    connecting: bool,
}

// ─── SOCKS5 handshake ──────────────────────────────────────────────

async fn socks5_handshake(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] {
        return Err(AetherError::Other(format!("SOCKS5 auth failure: {buf:?}")));
    }
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(AetherError::Other(format!("SOCKS5 CONNECT reply: {}", hdr[1])));
    }

    match hdr[3] {
        0x01 => { let mut a = [0u8; 4]; stream.read_exact(&mut a).await?; }
        0x03 => { let mut l = [0u8; 1]; stream.read_exact(&mut l).await?;
                   let mut buf = vec![0u8; l[0] as usize]; stream.read_exact(&mut buf).await?; }
        0x04 => { let mut buf = vec![0u8; 16]; stream.read_exact(&mut buf).await?; }
        _ => {}
    }
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    Ok(())
}

async fn connect_through_socks(upstream: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut last_err = None;
    for attempt in 0..3u8 {
        if attempt > 0 {
            ffi::record_log(format!(
                "[tun2socks] retry {attempt} for {target} after SOCKS5 failure"
            ));
            tokio::time::sleep(Duration::from_millis(300 * (1 << attempt))).await;
        }
        match tokio::time::timeout(
            Duration::from_secs(8),
            async {
                let mut stream = TcpStream::connect(upstream).await?;
                socks5_handshake(&mut stream).await?;
                socks5_connect(&mut stream, target).await?;
                Ok::<TcpStream, AetherError>(stream)
            },
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                last_err = Some(e.to_string());
                // reply:5 = general failure — retry makes sense
                if !e.to_string().contains("reply: 5") {
                    return Err(e);
                }
            }
            Err(_) => {
                last_err = Some("timeout".into());
            }
        }
    }
    Err(AetherError::Other(format!(
        "SOCKS5 connect failed after 3 attempts: {}",
        last_err.unwrap_or_default()
    )))
}

// ─── TCP flags ──────────────────────────────────────────────────────

fn tcp_flags(buf: &[u8], ihl: usize) -> (bool, bool, bool) {
    if buf.len() < ihl + 14 { return (false, false, false); }
    let flags = buf[ihl + 13];
    (flags & 0x02 != 0, flags & 0x10 != 0, flags & 0x01 != 0) // SYN, ACK, FIN
}

fn is_rst_flag(tcp: &[u8]) -> bool {
    tcp.len() > 13 && (tcp[13] & 0x04 != 0)
}

// ─── build & write TCP packet to TUN ────────────────────────────────

async fn send_tcp(
    tun: &tokio::io::unix::AsyncFd<std::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32,
    flags: u8, payload: &[u8],
) -> u64 {
    send_tcp_ex(tun, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, false).await
}

/// Extended send_tcp with MSS option support (needed for SYN-ACK).
async fn send_tcp_ex(
    tun: &tokio::io::unix::AsyncFd<std::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32,
    flags: u8, payload: &[u8],
    with_mss: bool,
) -> u64 {
    // TCP options: MSS (4 bytes) if requested
    let mss_opt_len = if with_mss { 4 } else { 0 };
    let tcp_hdr_len: usize = 20 + mss_opt_len;
    let tcp_len = tcp_hdr_len + payload.len();
    let ip_len = 20 + tcp_len;
    let mut pkt = vec![0u8; ip_len];

    // ── IP header ──
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0, 0]);
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6;  // TCP
    pkt[12..16].copy_from_slice(&ip_to_bytes(src_ip));
    pkt[16..20].copy_from_slice(&ip_to_bytes(dst_ip));
    let ip_cksum = ip_checksum(&pkt);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ── TCP header ──
    let o = 20;
    pkt[o..o+2].copy_from_slice(&src_port.to_be_bytes());
    pkt[o+2..o+4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[o+4..o+8].copy_from_slice(&seq.to_be_bytes());
    pkt[o+8..o+12].copy_from_slice(&ack.to_be_bytes());
    // Data offset = (20 + mss_opt_len) / 4
    pkt[o+12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[o+13] = flags;
    pkt[o+14..o+16].copy_from_slice(&65535u16.to_be_bytes()); // window
    // checksum filled below
    pkt[o+18..o+20].copy_from_slice(&0u16.to_be_bytes()); // urgent ptr

    // ── TCP options (MSS) ──
    if with_mss {
        let opt_off = o + 20;
        pkt[opt_off] = 0x02;     // Kind = MSS
        pkt[opt_off + 1] = 0x04; // Length = 4
        // MSS = 1280 - 20 (IP) - 20 (TCP) = 1240
        pkt[opt_off + 2..opt_off + 4].copy_from_slice(&1240u16.to_be_bytes());
    }

    if !payload.is_empty() {
        pkt[o + tcp_hdr_len..].copy_from_slice(payload);
    }
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[o+16..o+18].copy_from_slice(&tcp_cksum.to_be_bytes());

    // ── write to TUN ──
    let mut guard = match tun.ready(Interest::WRITABLE).await {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.try_io(|inner| {
        let fd = inner.as_raw_fd();
        let n = unsafe { libc::write(fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n >= 0 { Ok(n as usize) } else { Err(std::io::Error::last_os_error()) }
    }) {
        Ok(Ok(_)) => pkt.len() as u64,
        _ => 0,
    }
}

// ─── build & write UDP packet to TUN ────────────────────────────────

async fn send_udp(
    tun: &tokio::io::unix::AsyncFd<std::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    payload: &[u8],
) -> u64 {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut pkt = vec![0u8; ip_len];

    // ── IP header ──
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0, 0]); // ID
    pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol = UDP
    pkt[12..16].copy_from_slice(&ip_to_bytes(src_ip));
    pkt[16..20].copy_from_slice(&ip_to_bytes(dst_ip));
    let ip_cksum = ip_checksum(&pkt);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ── UDP header ──
    let o = 20;
    pkt[o..o+2].copy_from_slice(&src_port.to_be_bytes());
    pkt[o+2..o+4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[o+4..o+6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // checksum filled below
    pkt[o+8..].copy_from_slice(payload);
    let udp_cksum = udp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[o+6..o+8].copy_from_slice(&udp_cksum.to_be_bytes());

    // ── write to TUN ──
    let mut guard = match tun.ready(Interest::WRITABLE).await {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.try_io(|inner| {
        let fd = inner.as_raw_fd();
        let n = unsafe { libc::write(fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n >= 0 { Ok(n as usize) } else { Err(std::io::Error::last_os_error()) }
    }) {
        Ok(Ok(_)) => pkt.len() as u64,
        _ => 0,
    }
}

// ─── DNS forwarding (UDP:53 → TCP DNS through SOCKS5) ───────────────

async fn forward_dns_tcp(upstream: SocketAddr, dns_server: Ipv4Addr, query: &[u8]) -> Result<Vec<u8>> {
    let target = SocketAddr::new(IpAddr::V4(dns_server), 53);
    let mut stream = connect_through_socks(upstream, target).await?;
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn handle_udp(
    packet: &[u8], ihl: usize,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    tun: &tokio::io::unix::AsyncFd<std::fs::File>,
    upstream: SocketAddr,
) -> u64 {
    if packet.len() < ihl + 8 { return 0; }
    let udp = &packet[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = if udp.len() > 8 { &udp[8..] } else { &[] };

    if dst_port != 53 || payload.is_empty() { return 0; }
    ffi::record_log(format!("[tun2socks] DNS query {src_ip}:{src_port} -> {dst_ip}:53 ({}B)", payload.len()));

    match forward_dns_tcp(upstream, dst_ip, payload).await {
        Ok(response) => {
            ffi::record_log(format!("[tun2socks] DNS response OK ({}B)", response.len()));
            // Response goes from DNS server → app: src=dns_ip:53, dst=app_ip:src_port
            send_udp(tun, dst_ip, src_ip, 53, src_port, &response).await
        }
        Err(e) => {
            ffi::record_log(format!("[tun2socks] DNS FAILED: {e}"));
            0
        }
    }
}

// ─── TUN reader: reads responses from SOCKS and writes to TUN ──────

async fn tun_response_reader(
    mut read_half: ReadHalf<TcpStream>,
    tun: tokio::io::unix::AsyncFd<std::fs::File>,
    tun_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    tun_port: u16,
    remote_port: u16,
    mut seq_to_tun: u32,
    ack_shared: Arc<AtomicU32>,
    conns: Arc<Mutex<HashMap<u16, TcpConn>>>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        // 60s idle timeout (increased from 30s)
        match tokio::time::timeout(Duration::from_secs(60), read_half.read(&mut buf)).await {
            Err(_) => {
                ffi::record_log(format!(
                    "[tun2socks] idle timeout {remote_ip}:{remote_port} -> {tun_ip}:{tun_port}"
                ));
                let ack = ack_shared.load(Ordering::Relaxed);
                let _ = send_tcp(
                    &tun, remote_ip, tun_ip,
                    remote_port, tun_port,
                    seq_to_tun, ack,
                    0x11, &[], // FIN+ACK
                ).await;
                break;
            }
            Ok(Ok(0)) => {
                let ack = ack_shared.load(Ordering::Relaxed);
                let _ = send_tcp(
                    &tun, remote_ip, tun_ip,
                    remote_port, tun_port,
                    seq_to_tun, ack,
                    0x11, &[], // FIN+ACK
                ).await;
                break;
            }
            Ok(Ok(n)) => {
                // Read the LATEST ack from app (may have been updated by handle_tcp)
                let ack = ack_shared.load(Ordering::Relaxed);
                ffi::record_log(format!("[tun2socks] RECV {n}B from {remote_ip}:{remote_port} → {tun_ip}:{tun_port}"));
                let _ = send_tcp(
                    &tun, remote_ip, tun_ip,
                    remote_port, tun_port,
                    seq_to_tun, ack,
                    0x18, &buf[..n], // PSH+ACK
                ).await;
                seq_to_tun = seq_to_tun.wrapping_add(n as u32);
            }
            Ok(Err(_)) => {
                let ack = ack_shared.load(Ordering::Relaxed);
                let _ = send_tcp(
                    &tun, remote_ip, tun_ip,
                    remote_port, tun_port,
                    seq_to_tun, ack,
                    0x04, &[], // RST
                ).await;
                break;
            }
        }
    }
    conns.lock().await.remove(&tun_port);
}

/// Writer task: reads data from channel, writes to SOCKS5 write_half
async fn socks_writer_task(
    mut write_half: WriteHalf<TcpStream>,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(data) = data_rx.recv().await {
        if write_half.write_all(&data).await.is_err() {
            break;
        }
    }
}

// ─── TCP handler ────────────────────────────────────────────────────

async fn handle_tcp(
    packet: &[u8], ihl: usize,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    tun: &tokio::io::unix::AsyncFd<std::fs::File>,
    conns: &Arc<Mutex<HashMap<u16, TcpConn>>>,
    upstream: SocketAddr,
) -> u64 {
    if packet.len() < ihl + 20 { return 0; }
    let tcp = &packet[ihl..];
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    let (is_syn, is_ack, is_fin) = tcp_flags(packet, ihl);
    let payload_len = if tcp.len() > tcp_hdr_len { tcp.len() - tcp_hdr_len } else { 0 };
    let payload = &tcp[tcp_hdr_len..tcp.len()];

    // FIN / RST → cleanup
    if is_fin || is_rst_flag(tcp) {
        conns.lock().await.remove(&sport);
        return 0;
    }

    // SYN → connect through upstream SOCKS5 (ASYNC — don't block main loop!)
    if is_syn {
        // Skip private IPs — they can't be routed through SOCKS5
        if dst_ip.is_private() {
            let _ = send_tcp(
                tun, dst_ip, src_ip,
                dport, sport,
                0, seq_num.wrapping_add(1),
                0x14, &[], // RST+ACK
            ).await;
            return 64;
        }

        let dst = SocketAddr::new(IpAddr::V4(dst_ip), dport);

        // SYN retransmission check
        {
            let conns_guard = conns.lock().await;
            if let Some(conn) = conns_guard.get(&sport) {
                // Only resend SYN-ACK if already connected (not during connecting phase)
                if !conn.connecting {
                    let _ = send_tcp_ex(
                        tun, dst_ip, src_ip,
                        dport, sport,
                        conn.seq_to_tun, conn.ack_shared.load(Ordering::Relaxed),
                        0x12, &[], true,
                    ).await;
                }
                // During connecting: silently drop retransmitted SYN
                return 64;
            }
        }

        // Pre-generate ISN before creating connecting entry (fixes seq mismatch)
        let isn = rand_u32();
        let ack_shared = Arc::new(AtomicU32::new(seq_num.wrapping_add(1)));
        conns.lock().await.insert(sport, TcpConn {
            data_tx: None,
            ack_shared: Arc::clone(&ack_shared),
            seq_to_tun: isn,
            connecting: true,
        });

        ffi::record_log(format!("[tun2socks] TCP SYN {src_ip}:{sport} -> {dst}"));

        // Spawn async connect — main loop continues immediately
        let tun_fd_clone = unsafe { libc::dup(tun.as_raw_fd()) };
        let conns_clone = Arc::clone(&conns);
        tokio::spawn(async move {
            if tun_fd_clone < 0 { return; }
            let tun_file = unsafe { std::fs::File::from_raw_fd(tun_fd_clone) };
            let tun_async = match tokio::io::unix::AsyncFd::new(tun_file) {
                Ok(a) => a,
                Err(_) => return,
            };

            match connect_through_socks(upstream, dst).await {
                Ok(stream) => {
                    ffi::record_log(format!("[tun2socks] SOCKS5 CONNECT OK {dst}"));
                    // Use the pre-generated ISN (already stored in conn)
                    let seq_to_tun: u32 = isn;
                    let (read_half, write_half) = tokio::io::split(stream);

                    // Create channel for app→SOCKS5 data
                    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(128);

                    // Store connection state BEFORE sending SYN-ACK (fixes race condition)
                    conns_clone.lock().await.insert(sport, TcpConn {
                        data_tx: Some(data_tx),
                        ack_shared: Arc::clone(&ack_shared),
                        seq_to_tun,
                        connecting: false,
                    });

                    // Spawn response reader
                    let tun_reader_fd = unsafe { libc::dup(tun_async.as_raw_fd()) };
                    let ack_for_reader = Arc::clone(&ack_shared);
                    if tun_reader_fd >= 0 {
                        let tun_reader_file = unsafe { std::fs::File::from_raw_fd(tun_reader_fd) };
                        let tun_reader = tokio::io::unix::AsyncFd::new(tun_reader_file).unwrap();
                        let conns_reader = Arc::clone(&conns_clone);
                        tokio::spawn(async move {
                            tun_response_reader(
                                read_half, tun_reader,
                                src_ip, dst_ip,
                                sport, dport,
                                seq_to_tun.wrapping_add(1),
                                ack_for_reader,
                                conns_reader,
                            ).await;
                        });
                    }

                    // Spawn SOCKS writer task
                    tokio::spawn(socks_writer_task(write_half, data_rx));

                    // Send SYN-ACK with MSS (connection already stored above)
                    let ack_val = ack_shared.load(Ordering::Relaxed);
                    let _ = send_tcp_ex(
                        &tun_async, dst_ip, src_ip,
                        dport, sport,
                        seq_to_tun, ack_val,
                        0x12, &[], true,
                    ).await;
                }
                Err(e) => {
                    ffi::record_log(format!("[tun2socks] SOCKS5 CONNECT FAILED {dst}: {e}"));
                    let _ = send_tcp(
                        &tun_async, dst_ip, src_ip,
                        dport, sport,
                        0, seq_num.wrapping_add(1),
                        0x04, &[], // RST
                    ).await;
                    conns_clone.lock().await.remove(&sport);
                }
            }
        });
        return 64;
    }

    // Established connection with data → forward to SOCKS
    if is_ack && payload_len > 0 {
        // Quick lock, no await inside lock
        let data_tx_clone = {
            let conns_guard = conns.lock().await;
            let conn = match conns_guard.get(&sport) {
                Some(c) => c,
                None => return 0,
            };
            if conn.connecting {
                ffi::record_log(format!("[tun2socks] DATA while connecting {src_ip}:{sport} -> {dst_ip}:{dport} ({payload_len}B) — dropped"));
                return 0;
            }
            // Update ACK atomically (response reader will see it)
            conn.ack_shared.store(
                seq_num.wrapping_add(payload_len as u32),
                Ordering::Relaxed,
            );
            conn.data_tx.clone()
        };

        if let Some(tx) = data_tx_clone {
            ffi::record_log(format!("[tun2socks] DATA {src_ip}:{sport} -> {dst_ip}:{dport} ({payload_len}B) → SOCKS5"));
            if tx.try_send(payload.to_vec()).is_err() {
                ffi::record_log(format!("[tun2socks] DATA channel full for {sport}"));
            }
            // Send ACK to app
            let seq_ack;
            let ack_val;
            {
                let conns_guard = conns.lock().await;
                let conn = match conns_guard.get(&sport) {
                    Some(c) => c,
                    None => return payload_len as u64,
                };
                seq_ack = conn.seq_to_tun;
                ack_val = conn.ack_shared.load(Ordering::Relaxed);
            }
            let _ = send_tcp(
                tun, dst_ip, src_ip,
                dport, sport,
                seq_ack, ack_val,
                0x10, &[], // ACK
            ).await;
            return payload_len as u64;
        }
    }

    // Pure ACK with no data — ignore
    0
}

fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(0);
    h.finish() as u32
}

// ─── public entry point ─────────────────────────────────────────────

pub async fn serve(upstream: SocketAddr, tun_fd: i32) -> Result<()> {
    ffi::record_log(format!("[tun2socks] serve() called, upstream={upstream}, tun_fd={tun_fd}"));
    let fd = unsafe { libc::dup(tun_fd) };
    if fd < 0 {
        return Err(AetherError::Other(format!("dup(tun_fd={tun_fd}) failed")));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(AetherError::Other(format!("fcntl nonblock: {e}")));
    }

    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let tun = tokio::io::unix::AsyncFd::new(file)?;

    let conns: Arc<Mutex<HashMap<u16, TcpConn>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;
    let mut last_report = Instant::now();

    let mut pkt = vec![0u8; 65535];

    loop {
        // Wait for readable with timeout
        let mut guard = match tokio::time::timeout(Duration::from_secs(1), tun.ready(Interest::READABLE)).await {
            Ok(Ok(g)) => g,
            _ => {
                if last_report.elapsed() >= Duration::from_secs(1) {
                    if rx_total > 0 || tx_total > 0 {
                        ffi::emit_traffic(rx_total, tx_total);
                    }
                    last_report = Instant::now();
                }
                continue;
            }
        };

        match guard.try_io(|inner| {
            let fd = inner.as_raw_fd();
            let n = unsafe { libc::read(fd, pkt.as_mut_ptr() as *mut libc::c_void, pkt.len()) };
            if n > 0 { Ok(n as usize) } else { Err(std::io::ErrorKind::WouldBlock.into()) }
        }) {
            Ok(Ok(n)) => {
                if n < 20 { continue; }
                let version = pkt[0] >> 4;
                if version != 4 { continue; }
                rx_total += n as u64;
                let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                let proto = pkt[9];
                let src_ip = ip_from_bytes(&pkt[12..16]);
                let dst_ip = ip_from_bytes(&pkt[16..20]);
                let packet = &pkt[..n];

                match proto {
                    6 => {
                        let delta = handle_tcp(
                            packet, ihl, src_ip, dst_ip, &tun, &conns, upstream,
                        ).await;
                        tx_total += delta;
                    }
                    17 => {
                        let delta = handle_udp(
                            packet, ihl, src_ip, dst_ip, &tun, upstream,
                        ).await;
                        tx_total += delta;
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        if last_report.elapsed() >= Duration::from_secs(1) {
            if rx_total > 0 || tx_total > 0 {
                ffi::emit_traffic(rx_total, tx_total);
            }
            last_report = Instant::now();
        }
    }
}
