//! tun2socks bridge: reads raw IPv4 packets from a TUN fd,
//! parses TCP/UDP, and forwards through an upstream SOCKS5 proxy.
//! Includes bidirectional TCP data forwarding and DNS-over-TCP.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::{AetherError, Result};
use crate::ffi;

// ─── helpers ────────────────────────────────────────────────────────

fn ip_to_bytes(ip: Ipv4Addr) -> [u8; 4] { ip.octets() }
fn ip_from_bytes(b: &[u8]) -> Ipv4Addr { Ipv4Addr::new(b[0], b[1], b[2], b[3]) }

struct TcpConn {
    stream: TcpStream,
    seq_to_tun: u32,        // next seq number for data sent TO the app (SOCKS→TUN)
    ack_from_tun: u32,      // last ACK received from the app
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
                   stream.read_exact(&mut vec![0u8; l[0] as usize]).await?; }
        0x04 => { stream.read_exact(&mut vec![0u8; 16]).await?; }
        _ => {}
    }
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    Ok(())
}

async fn connect_through_socks(upstream: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream).await?;
    socks5_handshake(&mut stream).await?;
    socks5_connect(&mut stream, target).await?;
    Ok(stream)
}

// ─── TCP helpers ────────────────────────────────────────────────────

fn tcp_flags(buf: &[u8], ihl: usize) -> (bool, bool, bool) {
    if buf.len() < ihl + 14 { return (false, false, false); }
    let flags = buf[ihl + 13];
    (flags & 0x02 != 0, flags & 0x10 != 0, flags & 0x01 != 0) // SYN, ACK, FIN
}

fn send_tcp<'a>(
    tun: &'a tokio::io::unix::AsyncFd<tokio::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    sport: u16, dport: u16,
    seq: u32, ack: u32,
    flags: u8, payload: &[u8],
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send + 'a>> {
    Box::pin(async move {
        let tcp_len = 20 + payload.len();
        let ip_len = 20 + tcp_len;
        let mut pkt = vec![0u8; ip_len];

        // IP header
        pkt[0] = 0x45; pkt[1] = 0x00;
        pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&[0, 0]); // ID
        pkt[6..8].copy_from_slice(&[0x40, 0x00]); // DF
        pkt[8] = 64; pkt[9] = 6; // TTL=64, proto=TCP
        pkt[10..12].fill(0); // checksum (kernel fills)
        pkt[12..16].copy_from_slice(&ip_to_bytes(src_ip));
        pkt[16..20].copy_from_slice(&ip_to_bytes(dst_ip));

        // TCP header
        let o = 20;
        pkt[o..o+2].copy_from_slice(&dport.to_be_bytes());  // src=server
        pkt[o+2..o+4].copy_from_slice(&sport.to_be_bytes()); // dst=client
        pkt[o+4..o+8].copy_from_slice(&seq.to_be_bytes());
        pkt[o+8..o+12].copy_from_slice(&ack.to_be_bytes());
        pkt[o+12] = 0x50; // data offset
        pkt[o+13] = flags;
        pkt[o+14..o+16].copy_from_slice(&65535u16.to_be_bytes()); // window
        pkt[o+16..o+18].fill(0); // checksum (kernel fills)
        pkt[o+18..o+20].copy_from_slice(&0u16.to_be_bytes()); // urgent
        if !payload.is_empty() {
            pkt[o+20..].copy_from_slice(payload);
        }

        let written = pkt.len();
        match tun.write(&pkt).await {
            Ok(_) => written as u64,
            Err(_) => 0,
        }
    })
}

async fn send_udp(
    tun: &tokio::io::unix::AsyncFd<tokio::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    sport: u16, dport: u16,
    payload: &[u8],
) -> u64 {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut pkt = vec![0u8; ip_len];

    pkt[0] = 0x45; pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[8] = 64; pkt[9] = 17; // TTL, proto=UDP
    pkt[12..16].copy_from_slice(&ip_to_bytes(src_ip));
    pkt[16..20].copy_from_slice(&ip_to_bytes(dst_ip));

    let o = 20;
    pkt[o..o+2].copy_from_slice(&sport.to_be_bytes());
    pkt[o+2..o+4].copy_from_slice(&dport.to_be_bytes());
    pkt[o+4..o+6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[o+6..o+8].fill(0);
    pkt[o+8..].copy_from_slice(payload);

    match tun.write(&pkt).await {
        Ok(_) => ip_len as u64,
        Err(_) => 0,
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
    tun: &tokio::io::unix::AsyncFd<tokio::fs::File>,
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
            send_udp(tun, dst_ip, src_ip, 53, src_port, &response).await
        }
        Err(e) => {
            ffi::record_log(format!("[tun2socks] DNS FAILED: {e}"));
            0
        }
    }
}

// ─── TUN reader: reads responses from SOCKS and writes to TUN ──────

async fn tun_response_writer(
    mut stream: TcpStream,
    tun_write: tokio::io::unix::AsyncFd<tokio::fs::File>,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    sport: u16, dport: u16,
    mut seq_to_tun: u32,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                // Connection closed — send FIN
                let _ = send_tcp(&tun_write, dst_ip, src_ip, sport, dport,
                    seq_to_tun, 0, 0x11, &[]).await; // FIN+ACK
                break;
            }
            Ok(n) => {
                let _ = send_tcp(&tun_write, dst_ip, src_ip, sport, dport,
                    seq_to_tun, 0, 0x18, &buf[..n]).await; // PSH+ACK
                seq_to_tun = seq_to_tun.wrapping_add(n as u32);
            }
            Err(e) => {
                ffi::record_log(format!("[tun2socks] SOCKS read error: {e}"));
                let _ = send_tcp(&tun_write, dst_ip, src_ip, sport, dport,
                    seq_to_tun, 0, 0x04, &[]).await; // RST
                break;
            }
        }
    }
}

// ─── TCP handler ────────────────────────────────────────────────────

async fn handle_tcp(
    packet: &[u8], ihl: usize,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    tun: &tokio::io::unix::AsyncFd<tokio::fs::File>,
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

    let src = SocketAddr::new(IpAddr::V4(src_ip), sport);
    let dst = SocketAddr::new(IpAddr::V4(dst_ip), dport);

    // FIN / RST → cleanup
    if is_fin || is_rst_flag(tcp) {
        if let Some(conn) = conns.lock().await.remove(&sport) {
            drop(conn.stream);
        }
        return 0;
    }

    // SYN → connect through upstream SOCKS5
    if is_syn {
        ffi::record_log(format!("[tun2socks] TCP SYN {src} -> {dst}"));
        match connect_through_socks(upstream, dst).await {
            Ok(stream) => {
                ffi::record_log(format!("[tun2socks] SOCKS5 CONNECT OK {dst}"));
                let seq_to_tun: u32 = rand_u32();
                let stream_clone = stream.try_clone().unwrap();
                conns.lock().await.insert(sport, TcpConn {
                    stream: stream_clone,
                    seq_to_tun,
                    ack_from_tun: seq_num.wrapping_add(1),
                });
                let _ = send_tcp(
                    tun, dst_ip, src_ip, dst_port, sport,
                    seq_to_tun, seq_num.wrapping_add(1),
                    0x12, &[], // SYN+ACK
                ).await;
                // Spawn response reader
                let tun_clone = tokio::io::unix::AsyncFd::new(
                    tokio::fs::File::from_raw_fd(unsafe { libc::dup(tun.as_raw_fd()) })
                ).await.unwrap();
                tokio::spawn(tun_response_writer(stream, tun_clone, src_ip, dst_ip, sport, dport, seq_to_tun.wrapping_add(1)));
                64
            }
            Err(e) => {
                ffi::record_log(format!("[tun2socks] SOCKS5 CONNECT FAILED {dst}: {e}"));
                let _ = send_tcp(
                    tun, dst_ip, src_ip, dst_port, sport,
                    0, seq_num.wrapping_add(1), 0x14, &[], // ACK
                ).await;
                let _ = send_tcp(
                    tun, dst_ip, src_ip, dst_port, sport,
                    0, seq_num.wrapping_add(1), 0x04, &[], // RST
                ).await;
                0
            }
        }
    }
    // Established connection with data → forward to SOCKS
    else if is_ack && payload_len > 0 {
        if let Some(conn) = conns.lock().await.get_mut(&sport) {
            conn.ack_from_tun = seq_num.wrapping_add(payload_len as u32);
            let _ = conn.stream.write_all(payload).await;
            // Send ACK to app
            let _ = send_tcp(
                tun, dst_ip, src_ip, dst_port, sport,
                conn.seq_to_tun, conn.ack_from_tun,
                0x10, &[], // ACK
            ).await;
            payload_len as u64
        } else {
            0
        }
    } else {
        0
    }
}

fn is_rst_flag(tcp: &[u8]) -> bool {
    tcp.len() > 13 && (tcp[13] & 0x04 != 0)
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
    let mut tun = tokio::io::unix::AsyncFd::new(file).await?;

    let conns: Arc<Mutex<HashMap<u16, TcpConn>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;
    let mut last_report = Instant::now();

    let mut pkt = vec![0u8; 65535];

    loop {
        {
            let mut guard = tokio::time::timeout(Duration::from_secs(1), tun.readable_mut()).await;
            if guard.is_err() {
                if last_report.elapsed() >= Duration::from_secs(1) {
                    if rx_total > 0 || tx_total > 0 {
                        ffi::emit_traffic(rx_total, tx_total);
                    }
                    last_report = Instant::now();
                }
                continue;
            }
            if let Ok(ref mut rg) = guard {
                match rg.try_io(|inner| {
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
                            other => {
                                if rx_total < 1000 {
                                    ffi::record_log(format!("[tun2socks] ignored proto={other} from {src_ip} to {dst_ip}"));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if last_report.elapsed() >= Duration::from_secs(1) {
            if rx_total > 0 || tx_total > 0 {
                ffi::emit_traffic(rx_total, tx_total);
            }
            last_report = Instant::now();
        }
    }
}
