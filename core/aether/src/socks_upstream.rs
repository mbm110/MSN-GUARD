//! tun2socks bridge: reads raw IPv4 packets from a TUN fd,
//! parses TCP/UDP, and forwards through an upstream SOCKS5 proxy.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::io::unix::AsyncFd;

use crate::error::{AetherError, Result};
use crate::ffi;

/// Start the tun2socks bridge.
pub async fn serve(upstream: SocketAddr, tun_fd: i32) -> Result<()> {
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

    let tun = AsyncFd::new(unsafe { File::from_raw_fd(fd) })?;
    let conns: Arc<Mutex<HashMap<u16, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));

    log::info!("[tun2socks] bridge active -> upstream SOCKS5 {upstream}");

    let mut buf = vec![0u8; 65_535];
    let mut tx_total: u64 = 0;
    let mut rx_total: u64 = 0;
    let mut last_report = std::time::Instant::now();

    loop {
        let length = read_packet(&tun, &mut buf).await?;
        if length == 0 { continue; }
        let packet = &buf[..length];
        *rx_total += length as u64;

        if packet.len() < 20 { continue; }
        let version = (packet[0] >> 4) & 0xF;
        if version != 4 { continue; }
        let ihl = (packet[0] & 0xF) as usize * 4;
        let proto = packet[9];
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        match proto {
            6 => {
                let delta = handle_tcp(
                    packet, ihl, src_ip, dst_ip, &tun, &conns, upstream,
                ).await;
                tx_total += delta;
            }
            17 => {
                handle_udp(packet, ihl, src_ip, dst_ip).await;
            }
            _ => {}
        }

        if last_report.elapsed() >= std::time::Duration::from_secs(1) {
            ffi::emit_traffic(tx_total, rx_total);
            last_report = std::time::Instant::now();
        }
    }
}

// -- TCP handler --

async fn handle_tcp(
    packet: &[u8],
    ihl: usize,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tun: &AsyncFd<File>,
    conns: &Arc<Mutex<HashMap<u16, TcpStream>>>,
    upstream: SocketAddr,
) -> u64 {
    if packet.len() < ihl + 20 { return 0; }
    let tcp = &packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) & 0xF) as usize * 4;
    let flags = tcp[13];
    let payload = if tcp.len() > data_offset { &tcp[data_offset..] } else { &[] };

    let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
    let is_fin = (flags & 0x01) != 0;
    let is_rst = (flags & 0x04) != 0;

    let src = SocketAddr::new(IpAddr::V4(src_ip), src_port);
    let dst = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);

    // SYN -> connect through upstream SOCKS5
    if is_syn {
        log::info!("[tun2socks] TCP SYN {src} -> {dst}");
        match connect_through_socks(upstream, dst).await {
            Ok(stream) => {
                conns.lock().await.insert(src_port, stream);
                let _ = send_tcp(
                    tun, dst_ip, src_ip, dst_port, src_port,
                    ack_num.wrapping_add(1),
                    seq_num.wrapping_add(1),
                    0x12, &[],
                ).await;
            }
            Err(e) => {
                log::warn!("[tun2socks] SOCKS5 CONNECT to {dst} failed: {e}");
                let _ = send_tcp(
                    tun, dst_ip, src_ip, dst_port, src_port,
                    ack_num, seq_num.wrapping_add(1),
                    0x14, &[],
                ).await;
            }
        }
        return 0;
    }

    // FIN/RST -> close
    if is_fin || is_rst {
        if let Some(mut s) = conns.lock().await.remove(&src_port) {
            let _ = s.shutdown().await;
        }
        let _ = send_tcp(
            tun, dst_ip, src_ip, dst_port, src_port,
            ack_num.wrapping_add(1), seq_num.wrapping_add(1),
            0x10, &[],
        ).await;
        return 0;
    }

    // DATA -> forward through SOCKS5
    if !payload.is_empty() {
        if let Some(mut s) = conns.lock().await.get(&src_port) {
            let _ = s.write_all(payload).await;
            let _ = send_tcp(
                tun, dst_ip, src_ip, dst_port, src_port,
                ack_num.wrapping_add(payload.len() as u32),
                seq_num.wrapping_add(1),
                0x10, &[],
            ).await;
            return payload.len() as u64;
        }
    }
    0
}

// -- UDP handler (log only for now) --

async fn handle_udp(_packet: &[u8], _ihl: usize, _src_ip: Ipv4Addr, _dst_ip: Ipv4Addr) {
    // TODO: DNS forwarding via SOCKS5 UDP ASSOCIATE
}

// -- SOCKS5 CONNECT --

async fn connect_through_socks(upstream: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream).await
        .map_err(|e| AetherError::Other(format!("connect upstream: {e}")))?;

    // SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00]).await
        .map_err(|e| AetherError::Other(format!("SOCKS5 greeting write: {e}")))?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await
        .map_err(|e| AetherError::Other(format!("SOCKS5 greeting read: {e}")))?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(AetherError::Other(format!("SOCKS5 greeting failed: {:?}", resp)));
    }

    // SOCKS5 CONNECT request
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    match target.ip() {
        IpAddr::V4(v4) => req.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => {
            req[3] = 0x04;
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await
        .map_err(|e| AetherError::Other(format!("SOCKS5 CONNECT write: {e}")))?;

    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await
        .map_err(|e| AetherError::Other(format!("SOCKS5 CONNECT read: {e}")))?;
    if resp[1] != 0x00 {
        return Err(AetherError::Other(format!("SOCKS5 CONNECT reply: {}", resp[1])));
    }

    Ok(stream)
}

// -- Raw IP/TCP packet builder --

async fn send_tcp(
    tun: &AsyncFd<File>,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Result<()> {
    let tcp_len = 20 + payload.len();
    let ip_len = 20 + tcp_len;
    let mut pkt = vec![0u8; ip_len];

    // IP header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = flags;
    pkt[36..38].copy_from_slice(&65535u16.to_be_bytes());
    if !payload.is_empty() {
        pkt[40..].copy_from_slice(payload);
    }

    write_packet(tun, &pkt).await
}

// -- TUN I/O --

async fn read_packet(tun: &AsyncFd<File>, buf: &mut [u8]) -> Result<usize> {
    loop {
        let mut ready = tun.readable().await
            .map_err(|e| AetherError::Io(e))?;
        match ready.try_io(|inner| {
            let length = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if length < 0 { Err(std::io::Error::last_os_error()) }
            else { Ok(length as usize) }
        }) {
            Ok(Ok(n)) => return Ok(n),
            Ok(Err(e)) => return Err(AetherError::Io(e)),
            Err(_would_block) => continue,
        }
    }
}

async fn write_packet(tun: &AsyncFd<File>, pkt: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < pkt.len() {
        let mut ready = tun.writable().await
            .map_err(|e| AetherError::Io(e))?;
        match ready.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.get_ref().as_raw_fd(),
                    pkt[offset..].as_ptr().cast(),
                    pkt.len() - offset,
                )
            };
            if n < 0 { Err(std::io::Error::last_os_error()) }
            else { Ok(n as usize) }
        }) {
            Ok(Ok(n)) => offset += n,
            Ok(Err(e)) => return Err(AetherError::Io(e)),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}
