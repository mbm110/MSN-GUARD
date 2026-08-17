#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};

#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};
use crate::ffi;

/// Drives the exit-IP measurement while the bridge runs.
///
/// Split out of [bridge] so the packet loop stays readable and so the state
/// machine can be unit-tested without a TUN fd. It owns no I/O: [bridge] asks it
/// for a packet to send and shows it every inbound packet.
#[cfg(unix)]
mod exitprobe {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use crate::exitip::Probe;

    /// Wait after the first byte crosses before asking. Sending the probe the
    /// instant the bridge starts races the handshake settling, and a lost first
    /// datagram costs a whole retry interval.
    const FIRST_DELAY: Duration = Duration::from_millis(1_200);
    /// Gap between retries of an unanswered probe.
    const RETRY_GAP: Duration = Duration::from_secs(3);
    /// Attempts per stage before giving up. DNS over a fresh tunnel can lose a
    /// datagram or two; four tries is ~12s, well short of annoying.
    const MAX_ATTEMPTS: u32 = 4;

    enum State {
        /// Waiting for the tunnel to carry something before probing.
        Idle,
        /// A probe is outstanding.
        Waiting { probe: Probe, attempts: u32, next: Instant },
        /// Nothing more to do — answered, or out of attempts.
        Done,
    }

    pub struct ExitProbe {
        local_ipv4: Ipv4Addr,
        state: State,
        /// When the bridge may first send a probe.
        start_after: Option<Instant>,
    }

    impl ExitProbe {
        pub fn new(local_ipv4: Ipv4Addr) -> ExitProbe {
            ExitProbe {
                local_ipv4,
                state: State::Idle,
                start_after: None,
            }
        }

        /// Whether this probe still needs the bridge to wake up on a timer.
        ///
        /// Once the measurement is finished the 400ms wake-up is pure battery
        /// cost: it drags the loop (and so the CPU) out of sleep several times a
        /// second for the entire life of the tunnel to ask a question that has
        /// already been answered. The bridge stops ticking when this goes false.
        pub fn needs_ticking(&self) -> bool {
            !matches!(self.state, State::Done)
        }

        /// Called once traffic has been seen, to arm the first probe.
        pub fn arm(&mut self, now: Instant) {
            if self.start_after.is_none() {
                self.start_after = Some(now + FIRST_DELAY);
            }
        }

        /// A packet to write into the tunnel now, if any is due.
        pub fn due(&mut self, now: Instant) -> Option<Vec<u8>> {
            // An unmeasurable local address (the identity had no usable v4) means
            // a reply could never come back to us; skip rather than send noise.
            if self.local_ipv4.is_unspecified() {
                self.state = State::Done;
                return None;
            }
            match &mut self.state {
                State::Idle => {
                    let ready = self.start_after.is_some_and(|at| now >= at);
                    if !ready {
                        return None;
                    }
                    let probe = Probe::whoami(self.local_ipv4);
                    let packet = probe.packet.clone();
                    self.state = State::Waiting {
                        probe,
                        attempts: 1,
                        next: now + RETRY_GAP,
                    };
                    Some(packet)
                }
                State::Waiting {
                    probe,
                    attempts,
                    next,
                } => {
                    if now < *next {
                        return None;
                    }
                    if *attempts >= MAX_ATTEMPTS {
                        log::debug!("[exitip] no answer after {attempts} tries");
                        let _ = probe;
                        self.state = State::Done;
                        return None;
                    }
                    *attempts += 1;
                    *next = now + RETRY_GAP;
                    Some(probe.packet.clone())
                }
                State::Done => None,
            }
        }

        /// Shows an inbound packet to the state machine.
        ///
        /// Returns true when the packet was one of our replies, in which case the
        /// caller must NOT forward it to Android: the app never sent this query,
        /// so its resolver would have no matching request outstanding.
        pub fn consume(&mut self, packet: &[u8], now: Instant) -> bool {
            let State::Waiting { probe, .. } = &self.state else {
                return false;
            };
            if !probe.matches(packet) {
                return false;
            }
            match probe.read(packet) {
                Some(ip) => {
                    log::info!("[exitip] tunnel exits at {ip}");
                    // The country is NOT resolved here. Cymru answers from the RIR
                    // registration, which is US for every Cloudflare range no
                    // matter where the exit really is; the app resolves the real
                    // geolocation from this address instead.
                    crate::ffi::emit_exit_ip(ip.to_string());
                    self.state = State::Done;
                }
                // Matched our question but held nothing usable. Let the retry path
                // have another go rather than trusting it.
                None => {
                    let _ = now;
                }
            }
            true
        }
    }
}

/// IPv4/IPv6 + TCP header overhead subtracted from the proven inner MTU.
///
/// IPv6 headers are 20 bytes larger than IPv4, so using the v6 figure for both
/// costs 20 bytes on v4 and is never wrong. TCP options (timestamps, SACK) live
/// inside the MSS the peer offers, so they need no allowance here.
const IP_TCP_OVERHEAD: usize = 40 + 20;

/// Rewrites the TCP MSS option in a SYN so the peer never sends us a segment
/// bigger than the tunnel proved it can carry.
///
/// Why this exists: on Hamrah-e-Aval a WireGuard endpoint completes a handshake,
/// passes small packets, and silently drops full-size ones. Nothing surfaces —
/// no ICMP "fragmentation needed", no RST — so TCP keeps retransmitting a
/// segment that can never arrive. Every site and Telegram hang while the
/// counters show a trickle: exactly the "connected but nothing loads" report.
///
/// Clamping MSS on the SYN and SYN-ACK is the standard fix for a path that
/// cannot do PMTU discovery, and it is what makes such an endpoint usable
/// instead of merely diagnosed. Applied to both directions because the
/// asymmetric case (we advertise small, the server advertises large) still
/// leaves the inbound half broken.
fn clamp_tcp_mss(packet: &mut [u8], max_inner: usize) -> bool {
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    let (ip_header_len, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            (((packet[0] & 0x0f) as usize) * 4, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            // Only a bare TCP next-header is handled; extension headers are rare
            // here and skipping them is safer than mis-parsing them.
            (40usize, packet[6])
        }
        _ => return false,
    };
    if protocol != 6 || packet.len() < ip_header_len + 20 {
        return false;
    }

    // Offsets are absolute into `packet` throughout: taking a `&mut` subslice for
    // the TCP header would keep that borrow alive across the checksum rewrite,
    // which needs the whole packet (the pseudo-header covers the IP addresses).
    let tcp = ip_header_len;
    // SYN must be set; anything else carries no MSS option.
    if packet[tcp + 13] & 0x02 == 0 {
        return false;
    }
    let data_offset = ((packet[tcp + 12] >> 4) as usize) * 4;
    if data_offset < 20 || packet.len() < tcp + data_offset {
        return false;
    }

    let target = max_inner.saturating_sub(IP_TCP_OVERHEAD);
    if target == 0 || target > u16::MAX as usize {
        return false;
    }
    let target = target as u16;

    let options_end = tcp + data_offset;
    let mut i = tcp + 20;
    while i + 1 < options_end {
        match packet[i] {
            0 => break,  // end of options
            1 => i += 1, // no-op
            2 => {
                if packet[i + 1] != 4 || i + 4 > options_end {
                    return false;
                }
                let current = u16::from_be_bytes([packet[i + 2], packet[i + 3]]);
                if current <= target {
                    return false;
                }
                packet[i + 2..i + 4].copy_from_slice(&target.to_be_bytes());
                // The TCP checksum covers the options, so it must be redone.
                // Recomputing from scratch is simpler than an incremental update
                // and this runs once per connection, not per packet.
                recompute_tcp_checksum(packet, ip_header_len, version);
                return true;
            }
            _ => {
                let len = packet[i + 1] as usize;
                if len < 2 {
                    return false;
                }
                i += len;
            }
        }
    }
    false
}

fn ones_complement_sum(bytes: &[u8], mut sum: u32) -> u32 {
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn recompute_tcp_checksum(packet: &mut [u8], ip_header_len: usize, version: u8) {
    let tcp_len = packet.len() - ip_header_len;
    packet[ip_header_len + 16..ip_header_len + 18].copy_from_slice(&[0, 0]);

    let mut sum = 0u32;
    // Pseudo-header: source and destination addresses, protocol, TCP length.
    if version == 4 {
        sum = ones_complement_sum(&packet[12..20], sum);
    } else {
        sum = ones_complement_sum(&packet[8..40], sum);
    }
    sum += 6u32; // protocol
    sum += tcp_len as u32;
    sum = ones_complement_sum(&packet[ip_header_len..], sum);

    let checksum = fold_checksum(sum);
    packet[ip_header_len + 16..ip_header_len + 18].copy_from_slice(&checksum.to_be_bytes());
}

/// Bridges Android's packet TUN file descriptor with Aether's raw-IP tunnel.
///
/// `local_ipv4` is the tunnel's own inner address, used as the source of the
/// exit-IP probes. Pass [Ipv4Addr::UNSPECIFIED] to disable that measurement.
#[cfg(unix)]
pub async fn bridge(
    tun_fd: i32,
    local_ipv4: std::net::Ipv4Addr,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Duplicate fd: Java owns original ParcelFileDescriptor lifetime.
    let fd = unsafe { libc::dup(tun_fd) };
    if fd < 0 {
        return Err(AetherError::Io(io::Error::last_os_error()));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(AetherError::Io(error));
    }

    // SAFETY: `fd` is successful duplicate, now owned by File.
    let tun = AsyncFd::new(unsafe { File::from_raw_fd(fd) })?;
    let mut packet = vec![0u8; 65_535];
    let mut rx_total = 0u64;
    let mut tx_total = 0u64;
    let mut last_report = std::time::Instant::now();
    // How many SYNs had their MSS lowered since the last report. Only logged, but
    // it is the one number that says whether the clamp is doing anything.
    let mut clamped_syns = 0u64;
    // Measures the exit IP from inside the tunnel. See [exitprobe].
    let mut exit_probe = exitprobe::ExitProbe::new(local_ipv4);
    // Wakes the loop so a due probe is sent even while the tunnel is silent —
    // otherwise `select!` could block in recv() past the probe's schedule.
    //
    // This timer is only needed until the measurement finishes. Left running for
    // the life of the tunnel it would wake the loop 2.5 times a second forever,
    // which on a phone means the CPU never gets a long idle window — the single
    // most expensive shape of background work there is. `probing` disables the
    // arm the moment the probe is done, after which the loop sleeps until real
    // traffic arrives.
    let mut probe_tick = tokio::time::interval(std::time::Duration::from_millis(400));
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut probing = true;

    loop {
        tokio::select! {
            tunnel_packet = inbound_rx.recv() => match tunnel_packet {
                Some(mut packet) => {
                    rx_total += packet.len() as u64;
                    // Our own DNS replies must be swallowed: Android never asked
                    // these questions, so handing them up would be an unsolicited
                    // datagram to a resolver with no matching request.
                    if probing && exit_probe.consume(&packet, std::time::Instant::now()) {
                        continue;
                    }
                    // Inbound SYN-ACK: the server's advertised MSS must be
                    // clamped too, or the download half still stalls.
                    if clamp_tcp_mss(&mut packet, crate::wireguard::inner_mtu_hint()) {
                        clamped_syns += 1;
                    }
                    write_packet(&tun, &packet).await?;
                },
                None => return Ok(()),
            },
            read = read_packet(&tun, &mut packet) => {
                let length = read?;
                if length == 0 {
                    return Ok(());
                }
                tx_total += length as u64;
                // Real traffic is moving, so the tunnel is worth measuring.
                if probing {
                    exit_probe.arm(std::time::Instant::now());
                }
                let mut outbound = packet[..length].to_vec();
                // Outbound SYN: cap what we ask the peer to send us.
                if clamp_tcp_mss(&mut outbound, crate::wireguard::inner_mtu_hint()) {
                    clamped_syns += 1;
                }
                outbound_tx.send(outbound).await
                    .map_err(|_| AetherError::Other("tunnel outbound channel closed".into()))?;
            },
            _ = probe_tick.tick(), if probing => {},
        }

        // Sent outside the select! arms so it happens on every wake-up, whichever
        // arm fired. A send failure means the tunnel is gone and the next loop
        // iteration will surface that properly.
        if probing {
            if let Some(probe) = exit_probe.due(std::time::Instant::now()) {
                if outbound_tx.send(probe).await.is_err() {
                    return Err(AetherError::Other("tunnel outbound channel closed".into()));
                }
            }
            probing = exit_probe.needs_ticking();
        }

        if last_report.elapsed() >= std::time::Duration::from_millis(1000) {
            ffi::emit_traffic(tx_total, rx_total);
            if clamped_syns > 0 {
                log::debug!(
                    "[tun] clamped MSS on {clamped_syns} SYN(s) to fit a {}-byte inner MTU",
                    crate::wireguard::inner_mtu_hint()
                );
                clamped_syns = 0;
            }
            last_report = std::time::Instant::now();
        }
    }
}

#[cfg(unix)]
async fn read_packet(tun: &AsyncFd<File>, packet: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = tun.readable().await?;
        match ready.try_io(|file| {
            let length = unsafe {
                libc::read(
                    file.get_ref().as_raw_fd(),
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                )
            };
            if length < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

#[cfg(unix)]
async fn write_packet(tun: &AsyncFd<File>, packet: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < packet.len() {
        let mut ready = tun.writable().await?;
        match ready.try_io(|file| {
            let length = unsafe {
                libc::write(
                    file.get_ref().as_raw_fd(),
                    packet[offset..].as_ptr().cast(),
                    packet.len() - offset,
                )
            };
            if length < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(Ok(length)) => offset += length,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn bridge(
    _tun_fd: i32,
    _local_ipv4: std::net::Ipv4Addr,
    _inbound_rx: mpsc::Receiver<Vec<u8>>,
    _outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    Err(AetherError::Other(
        "TUN mode requires a Unix platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal IPv4 TCP SYN whose option area holds `leading_nops` NOPs and then
    /// an MSS option of `mss`. 28 bytes of TCP header leaves room for both.
    fn syn_with_mss_padded(mss: u16, leading_nops: usize) -> Vec<u8> {
        assert!(leading_nops <= 4, "options area is 8 bytes");
        let mut pkt = vec![0u8; 20 + 28];
        pkt[0] = 0x45;
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 7 << 4; // data offset 28 bytes => 8 bytes of options
        pkt[33] = 0x02; // SYN
        for nop in 0..leading_nops {
            pkt[40 + nop] = 1;
        }
        let mut i = 40 + leading_nops;
        pkt[i] = 2; // MSS kind
        pkt[i + 1] = 4; // MSS length
        pkt[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
        i += 4;
        // Anything left in the options area is explicit end-of-options.
        while i < 48 {
            pkt[i] = 0;
            i += 1;
        }
        // A correct checksum to begin with, so a rewrite can be checked against it.
        recompute_tcp_checksum(&mut pkt, 20, 4);
        pkt
    }

    fn syn_with_mss(mss: u16) -> Vec<u8> {
        syn_with_mss_padded(mss, 0)
    }

    /// MSS value of a packet built by [syn_with_mss_padded].
    fn mss_at(pkt: &[u8], leading_nops: usize) -> u16 {
        let off = 20 + 20 + leading_nops + 2;
        u16::from_be_bytes([pkt[off], pkt[off + 1]])
    }

    fn mss_of(pkt: &[u8]) -> u16 {
        mss_at(pkt, 0)
    }

    /// True when the TCP checksum in `pkt` verifies. A wrong checksum makes the
    /// peer drop the SYN silently — the same symptom as the bug being fixed.
    fn tcp_checksum_valid(pkt: &[u8]) -> bool {
        let ip_header_len = ((pkt[0] & 0x0f) as usize) * 4;
        let tcp_len = pkt.len() - ip_header_len;
        let mut sum = ones_complement_sum(&pkt[12..20], 0);
        sum += 6u32;
        sum += tcp_len as u32;
        sum = ones_complement_sum(&pkt[ip_header_len..], sum);
        fold_checksum(sum) == 0
    }

    #[test]
    fn an_oversized_mss_is_clamped_to_the_proven_inner_mtu() {
        let mut pkt = syn_with_mss(1460);
        assert!(clamp_tcp_mss(&mut pkt, 1200));
        assert_eq!(mss_of(&pkt), 1200 - IP_TCP_OVERHEAD as u16);
    }

    #[test]
    fn an_mss_that_already_fits_is_left_alone() {
        let mut pkt = syn_with_mss(500);
        assert!(!clamp_tcp_mss(&mut pkt, 1200));
        assert_eq!(mss_of(&pkt), 500, "a fitting MSS must not be rewritten");
    }

    #[test]
    fn the_tcp_checksum_is_valid_after_clamping() {
        let mut pkt = syn_with_mss(1460);
        assert!(tcp_checksum_valid(&pkt), "fixture must start out valid");
        assert!(clamp_tcp_mss(&mut pkt, 800));
        assert!(
            tcp_checksum_valid(&pkt),
            "rewriting the MSS must leave a verifiable checksum"
        );
    }

    #[test]
    fn packets_without_a_syn_mss_option_are_untouched() {
        // Plain ACK: same shape, SYN bit clear.
        let mut ack = syn_with_mss(1460);
        ack[33] = 0x10;
        assert!(!clamp_tcp_mss(&mut ack, 1200));

        // UDP, not TCP.
        let mut udp = syn_with_mss(1460);
        udp[9] = 17;
        assert!(!clamp_tcp_mss(&mut udp, 1200));

        // Truncated and empty input must not panic.
        let mut empty: [u8; 0] = [];
        assert!(!clamp_tcp_mss(&mut empty, 1200));
        let mut short = [0x45u8, 0x00, 0x00];
        assert!(!clamp_tcp_mss(&mut short, 1200));
        // Unknown IP version.
        let mut bogus = [0x75u8, 0x00, 0x00, 0x00];
        assert!(!clamp_tcp_mss(&mut bogus, 1200));
    }

    #[test]
    fn options_before_the_mss_option_are_skipped() {
        // Two NOPs of padding before the MSS option, as real stacks emit.
        let mut pkt = syn_with_mss_padded(1460, 2);
        assert_eq!(mss_at(&pkt, 2), 1460);
        assert!(clamp_tcp_mss(&mut pkt, 1000));
        assert_eq!(mss_at(&pkt, 2), 1000 - IP_TCP_OVERHEAD as u16);
        assert!(tcp_checksum_valid(&pkt));
    }

    mod exit_probe {
        use super::super::exitprobe::ExitProbe;
        use std::net::Ipv4Addr;
        use std::time::{Duration, Instant};

        const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

        #[test]
        fn nothing_is_sent_before_traffic_has_been_seen() {
            let mut probe = ExitProbe::new(LOCAL);
            let now = Instant::now();
            // Even far in the future: without arm() there is nothing to measure.
            assert!(probe.due(now + Duration::from_secs(60)).is_none());
        }

        #[test]
        fn the_first_probe_waits_for_the_settle_delay() {
            let mut probe = ExitProbe::new(LOCAL);
            let t0 = Instant::now();
            probe.arm(t0);
            assert!(
                probe.due(t0 + Duration::from_millis(200)).is_none(),
                "must not fire immediately after traffic starts"
            );
            let packet = probe
                .due(t0 + Duration::from_millis(1_500))
                .expect("a probe should be due once the delay has passed");
            // A well-formed UDP datagram to port 53.
            assert_eq!(packet[0] >> 4, 4);
            assert_eq!(packet[9], 17);
            assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 53);
        }

        #[test]
        fn an_unanswered_probe_is_retried_then_abandoned() {
            let mut probe = ExitProbe::new(LOCAL);
            let t0 = Instant::now();
            probe.arm(t0);
            let mut now = t0 + Duration::from_millis(1_500);
            assert!(probe.due(now).is_some(), "first attempt");

            let mut sent = 1;
            for _ in 0..10 {
                now += Duration::from_secs(4);
                if probe.due(now).is_some() {
                    sent += 1;
                }
            }
            // Four attempts total, then it stops rather than probing forever.
            assert_eq!(sent, 4, "should stop after the attempt limit");
            assert!(probe.due(now + Duration::from_secs(60)).is_none());
        }

        #[test]
        fn an_unspecified_local_address_disables_the_measurement() {
            let mut probe = ExitProbe::new(Ipv4Addr::UNSPECIFIED);
            let t0 = Instant::now();
            probe.arm(t0);
            assert!(probe.due(t0 + Duration::from_secs(5)).is_none());
        }

        #[test]
        fn ticking_stops_once_there_is_nothing_left_to_measure() {
            // The bridge only keeps its 400ms wake-up timer while this is true, so
            // if it never goes false the tunnel never lets the CPU idle.
            let mut probe = ExitProbe::new(LOCAL);
            let t0 = Instant::now();
            probe.arm(t0);
            assert!(probe.needs_ticking(), "still measuring");

            let mut now = t0 + Duration::from_millis(1_500);
            assert!(probe.due(now).is_some());
            for _ in 0..10 {
                now += Duration::from_secs(4);
                probe.due(now);
            }
            assert!(
                !probe.needs_ticking(),
                "a probe that ran out of attempts must release the timer"
            );
        }

        #[test]
        fn an_unmeasurable_address_releases_the_timer_immediately() {
            let mut probe = ExitProbe::new(Ipv4Addr::UNSPECIFIED);
            let t0 = Instant::now();
            probe.arm(t0);
            // due() is what discovers the address is unusable, so ask once.
            assert!(probe.due(t0 + Duration::from_secs(5)).is_none());
            assert!(!probe.needs_ticking());
        }

        #[test]
        fn ordinary_inbound_traffic_is_passed_through() {
            let mut probe = ExitProbe::new(LOCAL);
            let t0 = Instant::now();
            probe.arm(t0);
            let _ = probe.due(t0 + Duration::from_millis(1_500));

            // A TCP packet, and a short/garbage packet: none are ours, so the
            // bridge must still forward them.
            let mut tcp = vec![0u8; 40];
            tcp[0] = 0x45;
            tcp[9] = 6;
            assert!(!probe.consume(&tcp, t0));
            assert!(!probe.consume(&[], t0));
            assert!(!probe.consume(&[0x45, 0x00], t0));
        }
    }
}
