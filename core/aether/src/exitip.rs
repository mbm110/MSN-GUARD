//! Reads the tunnel's own exit IP and country, using DNS carried *inside* the
//! tunnel.
//!
//! Why this exists. The app used to fetch its exit IP over HTTPS from
//! `MainActivity.fetchPublicIp()`. In native TUN mode that number is wrong, and
//! not by accident: `applySplitTunneling()` calls
//! `addDisallowedApplication(packageName)` to stop a routing loop, so our own
//! process is deliberately kept off the TUN. Its HTTP request therefore leaves
//! over the carrier link and reports the carrier's IP — Iran — while the browser,
//! which *is* on the TUN, exits in another country. The header showed one country
//! and reality was another.
//!
//! The exclusion cannot be dropped: on the native path the core provisions its
//! identity with plain unprotected sockets after `establish()`, and routing those
//! into a tunnel that does not exist yet deadlocks connect.
//!
//! So the measurement has to happen where the tunnel actually is. In native TUN
//! mode the core has no netstack — [crate::tun::bridge] pipes raw IP packets
//! straight to Android's fd — so there is no TCP socket to open and HTTP is not
//! available. DNS is, because a query is a single UDP datagram we can build by
//! hand and push through the same channel as any other packet:
//!
//!   1. `whoami.cloudflare TXT CH` at 1.1.1.1 answers with the source address
//!      the resolver saw, i.e. the tunnel's exit IP.
//!   2. `<reversed-octets>.origin.asn.cymru.com TXT` maps that address to
//!      `"ASN | prefix | CC | registry | date"`, giving the country without a
//!      geo-IP HTTP API.
//!
//! Both were verified answering from an uncensored host before this was written.
//! Two datagrams, no TCP, no netstack, and every byte crosses the tunnel — so
//! what it reports is what the tunnel really is.
//!
//! Everything here is bounds-checked and allocation-light: the parsers run on
//! bytes that arrived from the network, so a malformed reply must return `None`
//! rather than panic. A panic in the bridge task would take the tunnel down.

use std::net::Ipv4Addr;

/// UDP port 53, the only destination these probes use.
const DNS_PORT: u16 = 53;
/// Resolver queried inside the tunnel. Answers both lookups.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const QTYPE_TXT: u16 = 16;
const QCLASS_IN: u16 = 1;
/// Chaos class. `whoami.cloudflare` is only answered in CH, not IN.
const QCLASS_CH: u16 = 3;

const WHOAMI_NAME: &str = "whoami.cloudflare";
const CYMRU_SUFFIX: &str = "origin.asn.cymru.com";

/// Which lookup a reply belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// Asking the resolver what our address looks like from outside.
    Whoami,
    /// Asking Team Cymru which country that address belongs to.
    Country,
}

/// One outstanding DNS probe: what we asked, and how to recognise the answer.
pub struct Probe {
    pub stage: Stage,
    /// IPv4 packet, ready to hand to the tunnel.
    pub packet: Vec<u8>,
    /// Source port we chose, used to match the reply back to this probe.
    pub sport: u16,
    /// DNS transaction id, checked so an off-path reply cannot answer for us.
    pub id: u16,
    name: String,
    qclass: u16,
}

impl Probe {
    /// Builds the "what is my address" probe.
    pub fn whoami(src: Ipv4Addr) -> Probe {
        Probe::build(Stage::Whoami, src, WHOAMI_NAME.to_string(), QCLASS_CH)
    }

    /// Builds the "which country is `ip` in" probe.
    ///
    /// Cymru keys on reversed octets, the same convention as reverse DNS.
    pub fn country(src: Ipv4Addr, ip: Ipv4Addr) -> Probe {
        let o = ip.octets();
        let name = format!("{}.{}.{}.{}.{CYMRU_SUFFIX}", o[3], o[2], o[1], o[0]);
        Probe::build(Stage::Country, src, name, QCLASS_IN)
    }

    fn build(stage: Stage, src: Ipv4Addr, name: String, qclass: u16) -> Probe {
        let id: u16 = rand::random();
        // Ephemeral range, chosen at random so a reply is hard to guess at.
        let sport: u16 = 20_000 + (rand::random::<u16>() % 40_000);
        let query = build_query(id, &name, QTYPE_TXT, qclass);
        let packet = build_udp_ipv4(src, RESOLVER, sport, DNS_PORT, &query);
        Probe {
            stage,
            packet,
            sport,
            id,
            name,
            qclass,
        }
    }

    /// True when `packet` is the reply to this probe.
    ///
    /// Checks the full path — v4, UDP, from the resolver, to our source port —
    /// before trusting the DNS payload, then checks the transaction id and
    /// question inside it. Anything else belongs to the user's traffic and must
    /// be left alone.
    pub fn matches(&self, packet: &[u8]) -> bool {
        let Some(payload) = udp_payload(packet, RESOLVER, DNS_PORT, self.sport) else {
            return false;
        };
        question_matches(payload, self.id, &self.name, QTYPE_TXT, self.qclass)
    }

    /// Extracts the answer from a reply already accepted by [Probe::matches].
    pub fn read(&self, packet: &[u8]) -> Option<Answer> {
        let payload = udp_payload(packet, RESOLVER, DNS_PORT, self.sport)?;
        let txt = first_txt_record(payload)?;
        match self.stage {
            Stage::Whoami => txt.trim().parse().ok().map(Answer::Ip),
            Stage::Country => country_from_cymru(&txt).map(Answer::Country),
        }
    }
}

/// Result of a single probe.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Ip(Ipv4Addr),
    Country(String),
}

/// Parses the country code out of a Cymru TXT answer.
///
/// Shape is `"ASN | prefix | CC | registry | date"`. Only field 2 is wanted, and
/// only when it looks like a country code — Cymru returns `NA` or an empty field
/// for unallocated space, which must not reach the UI as a flag.
fn country_from_cymru(txt: &str) -> Option<String> {
    let field = txt.split('|').nth(2)?.trim();
    if field.len() != 2 || !field.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(field.to_ascii_uppercase())
}

/// Builds a DNS query message.
fn build_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    // Standard query, recursion desired.
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&1u16.to_be_bytes()); // one question
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no an/ns/ar records
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        // A label over 63 bytes cannot be encoded; callers only pass short ones.
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&qclass.to_be_bytes());
    q
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

fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wraps `payload` in a UDP datagram inside an IPv4 packet.
///
/// The UDP checksum is computed rather than zeroed: a resolver behind a strict
/// middlebox may drop a zero-checksum datagram, and a probe that is silently
/// discarded looks identical to a tunnel that does not work.
fn build_udp_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);

    pkt.push(0x45); // v4, 20-byte header
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // no flags, no fragment offset
    pkt.push(64); // ttl
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let ip_csum = fold(ones_complement_sum(&pkt[0..20], 0));
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // udp checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP pseudo-header: src, dst, zero, protocol, length.
    let mut sum = ones_complement_sum(&pkt[12..20], 0);
    sum += 17u32;
    sum += udp_len as u32;
    sum = ones_complement_sum(&pkt[20..], sum);
    let mut udp_csum = fold(sum);
    // Zero means "no checksum" on the wire, so the all-ones form is used instead.
    if udp_csum == 0 {
        udp_csum = 0xffff;
    }
    pkt[26..28].copy_from_slice(&udp_csum.to_be_bytes());
    pkt
}

/// Returns the UDP payload of `packet` when it comes from `src`:`sport` and is
/// addressed to `dport`, else `None`.
fn udp_payload(packet: &[u8], src: Ipv4Addr, sport: u16, dport: u16) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 || packet[9] != 17 {
        return None;
    }
    // A fragmented reply is not reassembled here; the answers are far too small
    // to fragment, so anything fragmented is not ours.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0 {
        return None;
    }
    if Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]) != src {
        return None;
    }
    let udp = &packet[ihl..];
    if u16::from_be_bytes([udp[0], udp[1]]) != sport
        || u16::from_be_bytes([udp[2], udp[3]]) != dport
    {
        return None;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 || len > udp.len() {
        return None;
    }
    Some(&udp[8..len])
}

/// True when `msg` is a response to our exact question.
fn question_matches(msg: &[u8], id: u16, name: &str, qtype: u16, qclass: u16) -> bool {
    if msg.len() < 12 {
        return false;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != id {
        return false;
    }
    if msg[2] & 0x80 == 0 {
        return false; // not a response
    }
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return false; // exactly one question expected
    }

    let mut pos = 12;
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = match msg.get(pos) {
            Some(v) => *v as usize,
            None => return false,
        };
        if len != label.len() {
            return false;
        }
        pos += 1;
        let end = match pos.checked_add(len) {
            Some(v) if v <= msg.len() => v,
            _ => return false,
        };
        if !msg[pos..end].eq_ignore_ascii_case(label.as_bytes()) {
            return false;
        }
        pos = end;
    }
    if msg.get(pos) != Some(&0) {
        return false;
    }
    pos += 1;
    if pos + 4 > msg.len() {
        return false;
    }
    u16::from_be_bytes([msg[pos], msg[pos + 1]]) == qtype
        && u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) == qclass
}

/// Advances past a (possibly compressed) domain name.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            // Compression pointer: two bytes, and the name ends here.
            return pos.checked_add(2).filter(|p| *p <= buf.len());
        }
        if len == 0 {
            return pos.checked_add(1).filter(|p| *p <= buf.len());
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > buf.len() {
            return None;
        }
    }
}

/// Concatenated character-strings of the first TXT record in the answer section.
///
/// TXT rdata is a sequence of length-prefixed strings; Cymru splits its answer
/// across several when it exceeds 255 bytes, so they are joined rather than
/// taking only the first.
fn first_txt_record(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4)?;
    }

    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos.checked_add(10)? > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        let end = pos.checked_add(rdlen)?;
        if end > msg.len() {
            return None;
        }
        if rtype == QTYPE_TXT {
            let mut out = String::new();
            let mut p = pos;
            while p < end {
                let len = msg[p] as usize;
                let start = p + 1;
                let stop = start.checked_add(len)?;
                if stop > end {
                    return None;
                }
                out.push_str(&String::from_utf8_lossy(&msg[start..stop]));
                p = stop;
            }
            if out.is_empty() {
                return None;
            }
            return Some(out);
        }
        pos = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a TXT reply for `name`, as a full IPv4/UDP packet from the
    /// resolver back to `sport`.
    fn txt_reply(id: u16, name: &str, qclass: u16, sport: u16, txt: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&[0x81, 0x80]); // response, no error
        msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        msg.extend_from_slice(&1u16.to_be_bytes()); // ancount
        msg.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&qclass.to_be_bytes());
        // Answer: compression pointer back to the question's name.
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&qclass.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes()); // ttl
        let rdata_len = 1 + txt.len();
        msg.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        msg.push(txt.len() as u8);
        msg.extend_from_slice(txt.as_bytes());

        build_udp_ipv4(
            RESOLVER,
            Ipv4Addr::new(10, 0, 0, 2),
            DNS_PORT,
            sport,
            &msg,
        )
    }

    #[test]
    fn the_whoami_reply_yields_the_exit_address() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let reply = txt_reply(probe.id, WHOAMI_NAME, QCLASS_CH, probe.sport, "203.0.113.7");
        assert!(probe.matches(&reply));
        assert_eq!(
            probe.read(&reply),
            Some(Answer::Ip(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    #[test]
    fn the_cymru_reply_yields_the_country_code() {
        let probe = Probe::country(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(203, 0, 113, 7));
        let reply = txt_reply(
            probe.id,
            "7.113.0.203.origin.asn.cymru.com",
            QCLASS_IN,
            probe.sport,
            "13335 | 203.0.113.0/24 | DE | ripencc | 2010-01-01",
        );
        assert!(probe.matches(&reply));
        assert_eq!(probe.read(&reply), Some(Answer::Country("DE".to_string())));
    }

    #[test]
    fn the_country_probe_reverses_the_octets() {
        let probe = Probe::country(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(probe.name, format!("4.3.2.1.{CYMRU_SUFFIX}"));
    }

    #[test]
    fn a_reply_to_a_different_transaction_is_rejected() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let reply = txt_reply(
            probe.id.wrapping_add(1),
            WHOAMI_NAME,
            QCLASS_CH,
            probe.sport,
            "203.0.113.7",
        );
        assert!(!probe.matches(&reply));
    }

    #[test]
    fn a_reply_to_a_different_port_is_rejected() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let reply = txt_reply(
            probe.id,
            WHOAMI_NAME,
            QCLASS_CH,
            probe.sport.wrapping_add(1),
            "203.0.113.7",
        );
        assert!(!probe.matches(&reply));
    }

    #[test]
    fn a_reply_in_the_wrong_class_is_rejected() {
        // whoami.cloudflare only answers in CH; an IN reply is not our answer.
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let reply = txt_reply(probe.id, WHOAMI_NAME, QCLASS_IN, probe.sport, "203.0.113.7");
        assert!(!probe.matches(&reply));
    }

    #[test]
    fn ordinary_user_traffic_is_never_claimed() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        // TCP to a web server: same tunnel, nothing to do with us.
        let mut tcp = vec![0u8; 40];
        tcp[0] = 0x45;
        tcp[9] = 6;
        assert!(!probe.matches(&tcp));
        // UDP from somewhere else on our port.
        let other = build_udp_ipv4(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            DNS_PORT,
            probe.sport,
            &[0u8; 32],
        );
        assert!(!probe.matches(&other));
    }

    #[test]
    fn truncating_a_reply_never_panics() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let reply = txt_reply(probe.id, WHOAMI_NAME, QCLASS_CH, probe.sport, "203.0.113.7");
        for cut in 0..reply.len() {
            let slice = &reply[..cut];
            // Both entry points must tolerate arbitrary truncation.
            let _ = probe.matches(slice);
            let _ = probe.read(slice);
        }
    }

    #[test]
    fn a_garbled_cymru_answer_is_not_a_country() {
        assert_eq!(country_from_cymru("13335 | 1.2.3.0/24 | DE | x | y"), Some("DE".into()));
        // Unallocated space: no usable country field.
        assert_eq!(country_from_cymru("NA | | | |"), None);
        assert_eq!(country_from_cymru("only one field"), None);
        assert_eq!(country_from_cymru(""), None);
        // A too-long or non-alphabetic field is not a country code.
        assert_eq!(country_from_cymru("1 | 2 | GERMANY | x"), None);
        assert_eq!(country_from_cymru("1 | 2 | 12 | x"), None);
    }

    #[test]
    fn the_probe_packet_is_a_well_formed_udp_datagram() {
        let probe = Probe::whoami(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = &probe.packet;
        assert_eq!(pkt[0] >> 4, 4, "must be IPv4");
        assert_eq!(pkt[9], 17, "must be UDP");
        assert_eq!(
            u16::from_be_bytes([pkt[2], pkt[3]]) as usize,
            pkt.len(),
            "IP total length must match the buffer"
        );
        // Header checksum must verify: fold of the sum over a correct header is 0.
        assert_eq!(fold(ones_complement_sum(&pkt[0..20], 0)), 0);
        // And the UDP checksum likewise, over the pseudo-header.
        let mut sum = ones_complement_sum(&pkt[12..20], 0);
        sum += 17u32;
        sum += (pkt.len() - 20) as u32;
        sum = ones_complement_sum(&pkt[20..], sum);
        assert_eq!(fold(sum), 0);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), DNS_PORT);
    }

    #[test]
    fn a_multi_string_txt_record_is_joined() {
        // Cymru splits answers over 255 bytes into several character-strings.
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x1234u16.to_be_bytes());
        msg.extend_from_slice(&[0x81, 0x80]);
        msg.extend_from_slice(&0u16.to_be_bytes()); // no question
        msg.extend_from_slice(&1u16.to_be_bytes()); // one answer
        msg.extend_from_slice(&[0, 0, 0, 0]);
        msg.push(0); // root name
        msg.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        let parts: [&str; 2] = ["13335 | 1.2.3.0/24 ", "| DE | ripencc"];
        let rdlen: usize = parts.iter().map(|p| 1 + p.len()).sum();
        msg.extend_from_slice(&(rdlen as u16).to_be_bytes());
        for part in parts {
            msg.push(part.len() as u8);
            msg.extend_from_slice(part.as_bytes());
        }
        let joined = first_txt_record(&msg).expect("a TXT record should parse");
        assert_eq!(joined, "13335 | 1.2.3.0/24 | DE | ripencc");
        assert_eq!(country_from_cymru(&joined), Some("DE".into()));
    }
}
