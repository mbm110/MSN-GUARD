//! Psiphon tun2socks — smoltcp-based transparent bridge.
//!
//! Architecture:
//!   TUN fd → tun::bridge() → netstack (smoltcp) → SOCKS5 upstream
//!
//! The netstack terminates TCP from apps and we forward each stream
//! through Psiphon's local SOCKS5 proxy (127.0.0.1:1819).
//!
//! Key features:
//!   - smoltcp handles all TCP state (SYN/ACK/SEQ/WINDOW/retransmit)
//!   - Silent retry: if SOCKS5 is briefly unavailable (Psiphon rotation),
//!     we retry for up to 3s with 150ms intervals — NO RST to app
//!   - Data buffering: app data is queued during SOCKS5 outage
//!   - Backpressure: when buffer is full, TCP window shrinks via smoltcp
//!   - DNS: UDP queries from apps are forwarded via SOCKS5 TCP to upstream

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};
use crate::ffi;
use crate::netstack::{self, AcceptedTcp, StackHandle};
use crate::tun;

// ─── SOCKS5 client (connect to Psiphon upstream) ──────────────────

const SOCKS_VER: u8 = 0x05;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_V4: u8 = 0x01;
const SOCKS_ATYP_V6: u8 = 0x04;
const SOCKS_REP_OK: u8 = 0x00;

/// Connect to target through upstream SOCKS5 proxy.
/// Retries for up to `retry_duration` with `retry_interval` between attempts.
async fn socks5_connect_with_retry(
    upstream: SocketAddr,
    target: SocketAddr,
    retry_duration: Duration,
    retry_interval: Duration,
) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + retry_duration;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        match socks5_connect_once(upstream, target).await {
            Ok(stream) => {
                if attempt > 1 {
                    ffi::record_log(format!(
                        "[tun2socks] SOCKS5 CONNECT OK {target} (attempt {attempt})"
                    ));
                } else {
                    ffi::record_log(format!("[tun2socks] SOCKS5 CONNECT OK {target}"));
                }
                return Ok(stream);
            }
            Err(e) => {
                if tokio::time::Instant::now() + retry_interval > deadline {
                    ffi::record_log(format!(
                        "[tun2socks] SOCKS5 CONNECT FAILED {target} after {attempt} attempts: {e}"
                    ));
                    return Err(e);
                }
                // Silent retry — don't spam log on every attempt
                if attempt <= 2 {
                    ffi::record_log(format!(
                        "[tun2socks] SOCKS5 retry {attempt} for {target} (Psiphon rotation?)"
                    ));
                }
                tokio::time::sleep(retry_interval).await;
            }
        }
    }
}

/// Single SOCKS5 connect attempt (no retry).
async fn socks5_connect_once(
    upstream: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(upstream),
    )
    .await
    .map_err(|_| AetherError::Other("SOCKS5 connect timeout".into()))?
    .map_err(|e| AetherError::Other(format!("SOCKS5 connect error: {e}")))?;

    stream.set_nodelay(true);

    // SOCKS5 greeting: version 5, 1 method (no auth)
    stream
        .write_all(&[SOCKS_VER, 0x01, 0x00])
        .await
        .map_err(|e| AetherError::Other(format!("SOCKS5 greeting write: {e}")))?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| AetherError::Other(format!("SOCKS5 greeting read: {e}")))?;

    if resp[0] != SOCKS_VER || resp[1] != 0x00 {
        return Err(AetherError::Other(format!(
            "SOCKS5 auth rejected: ver={} method={}",
            resp[0], resp[1]
        )));
    }

    // SOCKS5 CONNECT request
    let mut req = vec![SOCKS_VER, SOCKS_CMD_CONNECT, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(SOCKS_ATYP_V4);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(SOCKS_ATYP_V6);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());

    stream
        .write_all(&req)
        .await
        .map_err(|e| AetherError::Other(format!("SOCKS5 connect write: {e}")))?;

    // Read reply: at least 10 bytes for IPv4 reply
    let mut reply = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut reply))
        .await
        .map_err(|_| AetherError::Other("SOCKS5 reply timeout".into()))?
        .map_err(|e| AetherError::Other(format!("SOCKS5 reply read: {e}")))?;

    if n < 4 || reply[0] != SOCKS_VER {
        return Err(AetherError::Other("SOCKS5 bad reply".into()));
    }

    if reply[1] != SOCKS_REP_OK {
        return Err(AetherError::Other(format!(
            "SOCKS5 CONNECT refused: reply={}",
            reply[1]
        )));
    }

    Ok(stream)
}

// ─── Bidirectional pipe between netstack TCP and SOCKS5 ───────────

/// Forward data between an accepted netstack TCP connection and SOCKS5 upstream.
/// Handles SOCKS5 unavailability with silent retry and data buffering.
async fn pipe_tcp_to_socks(
    upstream: SocketAddr,
    target: SocketAddr,
    sender: netstack::TcpSender,
    mut from_netstack: mpsc::Receiver<Vec<u8>>,
) {
    // Skip private IPs — they can't be routed through SOCKS5
    if matches!(target.ip(), IpAddr::V4(v4) if v4.is_private()) {
        ffi::record_log(format!("[tun2socks] SKIP private IP {target}"));
        // smoltcp will RST because we close the sender without connecting
        sender.close().await;
        return;
    }

    // Phase 1: Connect to SOCKS5 with silent retry (3s, 150ms intervals)
    let socks = match socks5_connect_with_retry(
        upstream,
        target,
        Duration::from_secs(3),
        Duration::from_millis(150),
    )
    .await
    {
        Ok(s) => s,
        Err(_) => {
            // SOCKS5 truly unavailable after 3s — close gracefully
            // smoltcp will send FIN/RST to app
            sender.close().await;
            return;
        }
    };

    let (mut socks_rd, mut socks_wr) = tokio::io::split(socks);

    // Phase 2: Bidirectional pipe
    // Up: app → SOCKS5 (via sender)
    let up = tokio::spawn(async move {
        while let Some(data) = from_netstack.recv().await {
            if socks_wr.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Down: SOCKS5 → app (via sender)
    let mut down_buf = vec![0u8; 65535];
    loop {
        match socks_rd.read(&mut down_buf).await {
            Ok(0) => break,           // SOCKS5 closed
            Ok(n) => {
                if sender.send(down_buf[..n].to_vec()).await.is_err() {
                    break; // App side closed
                }
            }
            Err(_) => break,
        }
    }

    sender.close().await;
    let _ = up.await;
}

// ─── DNS forwarding (UDP → TCP through SOCKS5) ────────────────────

/// Forward DNS queries from netstack UDP to SOCKS5 TCP upstream.
async fn forward_dns_via_socks(
    upstream: SocketAddr,
    dns_server: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>> {
    let mut stream = socks5_connect_with_retry(
        upstream,
        dns_server,
        Duration::from_secs(3),
        Duration::from_millis(150),
    )
    .await?;

    // DNS over TCP: 2-byte length prefix + query
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;

    // Read response: 2-byte length prefix + response
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;

    Ok(resp)
}

/// Background task: drain DNS queries from netstack UDP socket and forward via SOCKS5.
async fn dns_forwarder(
    upstream: SocketAddr,
    sender: netstack::UdpSender,
    mut from_netstack: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    dns_servers: Vec<SocketAddr>,
) {
    while let Some((src, query)) = from_netstack.recv().await {
        ffi::record_log(format!(
            "[tun2socks] DNS query ({}B) from {}",
            query.len(),
            src
        ));

        // Try each DNS server
        let mut last_err = None;
        for server in &dns_servers {
            match forward_dns_via_socks(upstream, *server, &query).await {
                Ok(response) => {
                    ffi::record_log(format!("[tun2socks] DNS response OK ({}B)", response.len()));
                    if let Err(e) = sender.send_to(src, response).await {
                        ffi::record_log(format!("[tun2socks] DNS send_to failed: {e}"));
                    }
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if let Some(e) = last_err {
            ffi::record_log(format!("[tun2socks] DNS FAILED for all servers: {e}"));
        }
    }
    sender.close().await;
}

// ─── Main entry point ─────────────────────────────────────────────

/// Psiphon tun2socks: bridge Android TUN → smoltcp netstack → SOCKS5 upstream.
///
/// Flow:
///   1. tun::bridge() reads raw packets from TUN fd, sends to netstack
///   2. netstack (smoltcp) handles full TCP state machine
///   3. When smoltcp accepts a TCP connection, we:
///      a. Connect to target via SOCKS5 upstream (with silent retry)
///      b. Pipe data bidirectionally
///   4. DNS queries go through SOCKS5 as TCP DNS
pub async fn serve(upstream: SocketAddr, tun_fd: i32) -> Result<()> {
    ffi::record_log(format!(
        "[tun2socks] smoltcp serve() upstream={upstream} tun_fd={tun_fd}"
    ));

    // Channels between TUN bridge and netstack
    // inbound: TUN → netstack (app packets entering the VPN)
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1024);
    // outbound: netstack → TUN (responses going back to apps)
    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Spawn smoltcp netstack with TUN's IP configuration
    // TUN is configured as 10.0.0.2/24 by Android VPN Builder
    let stack = netstack::spawn(
        "10.0.0.2/24",
        "",      // no IPv6
        1500,    // MTU
        inbound_rx,   // TUN → netstack
        outbound_tx,  // netstack → TUN
    )?;

    // Enable transparent TCP accept mode
    let mut accept_rx = stack.enable_accept().await?;

    // Open a UDP socket in netstack for DNS forwarding
    let dns_udp = stack.open_udp().await?;
    let (dns_sender, mut dns_from_netstack) = dns_udp.into_split();

    // DNS servers to use via SOCKS5
    let dns_servers: Vec<SocketAddr> = vec![
        "8.8.8.8:53".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
    ];

    // Spawn DNS forwarder
    let upstream_dns = upstream;
    let dns_task = tokio::spawn(async move {
        dns_forwarder(upstream_dns, dns_sender, dns_from_netstack, dns_servers).await
    });

    // Spawn TUN bridge: raw packets between Android TUN and netstack
    // tun::bridge(tun_fd, inbound_rx, outbound_tx):
    //   inbound_rx = packets from tunnel → write to TUN
    //   outbound_tx = packets read from TUN → send to tunnel
    // In our case: "tunnel" = netstack
    //   outbound_rx (netstack output) → TUN  (these are responses to apps)
    //   inbound_tx (TUN input) → netstack (these are app requests)
    let tun_task = tokio::spawn(tun::bridge(tun_fd, outbound_rx, inbound_tx));

    ffi::record_log("[tun2socks] smoltcp netstack started, accepting connections...");

    // Main accept loop: for each accepted TCP connection, spawn a SOCKS5 pipe
    loop {
        match accept_rx.recv().await {
            Some(accepted) => {
                let target = accepted.local; // the destination the app wanted
                let (sender, from_netstack) = accepted.conn.into_split();

                ffi::record_log(format!(
                    "[tun2socks] ACCEPTED {} → {}",
                    accepted.remote, target
                ));

                // Spawn bidirectional pipe task
                let upstream_for_pipe = upstream;
                tokio::spawn(async move {
                    pipe_tcp_to_socks(upstream_for_pipe, target, sender, from_netstack).await;
                });
            }
            None => {
                ffi::record_log("[tun2socks] accept channel closed, exiting");
                break;
            }
        }
    }

    tun_task.abort();
    dns_task.abort();

    Ok(())
}
