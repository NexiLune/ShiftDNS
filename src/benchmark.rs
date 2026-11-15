use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static TX_COUNTER: AtomicU16 = AtomicU16::new(0x4A1B);

fn next_tx_id() -> u16 {
    TX_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Builds a lightweight RFC 1035 DNS A-record query packet (RD=1).
pub fn build_dns_a_query(tx_id: u16, labels: &[&[u8]]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(36);
    packet.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[
        0x01, 0x00, // Standard query with recursion desired
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ]);
    for label in labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
    }
    packet.push(0x00); // Root label
    packet.extend_from_slice(&[
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ]);
    packet
}

pub fn is_valid_dns_response(buf: &[u8], expected_tx_id: u16) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let rx_id = u16::from_be_bytes([buf[0], buf[1]]);
    let is_response = (buf[2] & 0x80) != 0;
    let rcode = buf[3] & 0x0F;
    rx_id == expected_tx_id && is_response && (rcode == 0 || rcode == 3)
}

fn probe_udp_53(target: SocketAddr, labels: &[&[u8]], timeout: Duration) -> Option<u128> {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).ok()?;
    socket.connect(target).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let tx_id = next_tx_id();
    let packet = build_dns_a_query(tx_id, labels);
    let mut buf = [0u8; 512];

    let start = Instant::now();
    socket.send(&packet).ok()?;
    let len = socket.recv(&mut buf).ok()?;

    if is_valid_dns_response(&buf[..len], tx_id) {
        Some(start.elapsed().as_millis().max(1))
    } else {
        None
    }
}

fn probe_tcp_53(target: SocketAddr, labels: &[&[u8]], timeout: Duration) -> Option<u128> {
    use std::io::{Read, Write};

    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&target, timeout).ok()?;
    let _ = stream.set_nodelay(true);
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let tx_id = next_tx_id();
    let query = build_dns_a_query(tx_id, labels);
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);

    stream.write_all(&framed).ok()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;
    if msg_len < 12 || msg_len > 4096 {
        return None;
    }

    let mut hdr = [0u8; 12];
    stream.read_exact(&mut hdr).ok()?;
    if is_valid_dns_response(&hdr, tx_id) {
        Some(start.elapsed().as_millis().max(1))
    } else {
        None
    }
}

/// Measures true DNS resolver latency over port 53 (instead of ICMP ping, which many
/// gaming/privacy DNS servers drop or rate-limit): sends a lightweight RFC 1035 A-record
/// UDP query (with a fast retry on packet loss) and falls back to DNS-over-TCP port 53.
pub fn probe_dns_latency(server_ip: &str) -> Option<u128> {
    let ip: IpAddr = server_ip.trim().parse().ok()?;
    let target = SocketAddr::new(ip, 53);

    probe_udp_53(target, &[b"cloudflare", b"com"], Duration::from_millis(500))
        .or_else(|| probe_udp_53(target, &[b"example", b"com"], Duration::from_millis(500)))
        .or_else(|| probe_tcp_53(target, &[b"cloudflare", b"com"], Duration::from_millis(600)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_rfc1035_query_and_validates_response() {
        let q = build_dns_a_query(0xABCD, &[b"example", b"com"]);
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        assert!(q.ends_with(&[0x00, 0x00, 0x01, 0x00, 0x01]));

        let mut resp = q.clone();
        resp[2] |= 0x80; // QR = 1 (response)
        assert!(is_valid_dns_response(&resp, 0xABCD));
        assert!(!is_valid_dns_response(&q, 0xABCD)); // Query without QR bit must fail
        assert!(!is_valid_dns_response(&resp, 0x1234)); // Mismatched TXID must fail
    }
}
