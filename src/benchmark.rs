use crate::config::{is_valid_hostname, normalize_hostname, DEFAULT_RESOLVE_CHECK_DOMAIN};
use crate::win32::{is_allowed_release_url, GITHUB_RELEASES_URL};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const GITHUB_LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/NexiLune/ShiftDNS/releases/latest";

static TX_COUNTER: AtomicU16 = AtomicU16::new(0x4A1B);

fn next_tx_id() -> u16 {
    TX_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveStatus {
    Ok,
    Blocked,
    NoAnswer,
    Timeout,
}

impl ResolveStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolveStatus::Ok => "ok",
            ResolveStatus::Blocked => "blocked",
            ResolveStatus::NoAnswer => "no_answer",
            ResolveStatus::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProbeResult {
    pub rtt_ms: Option<u128>,
    pub status: ResolveStatus,
    pub resolved_ip: Option<String>,
}

/// Builds a lightweight RFC 1035 DNS A-record query packet (RD=1).
pub fn build_dns_a_query(tx_id: u16, labels: &[&[u8]]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(48);
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

/// Skips an RFC 1035 domain name (inline labels or compression pointer) with loop bounds.
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut steps = 0usize;
    while pos < buf.len() && steps < 128 {
        steps += 1;
        let len = buf[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // 2-byte compression pointer terminates the inline name
            return if pos + 2 <= buf.len() {
                Some(pos + 2)
            } else {
                None
            };
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        pos += 1 + len as usize;
    }
    None
}

/// Parses an RFC 1035 DNS response, verifying TXID/QR and extracting IPv4 A-record answers.
/// Returns `None` if malformed/mismatched, or `Some((rcode, answers))`.
pub fn parse_dns_a_answers(buf: &[u8], expected_tx_id: u16) -> Option<(u8, Vec<Ipv4Addr>)> {
    if buf.len() < 12 {
        return None;
    }
    let rx_id = u16::from_be_bytes([buf[0], buf[1]]);
    let is_response = (buf[2] & 0x80) != 0;
    if rx_id != expected_tx_id || !is_response {
        return None;
    }
    let rcode = buf[3] & 0x0F;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 4 > buf.len() {
            return None;
        }
        pos += 4; // QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            answers.push(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ));
        }
        pos += rdlength;
    }

    Some((rcode, answers))
}

/// Returns true if an IPv4 answer indicates sinkholing, local blocking, or national DNS hijacking
/// (e.g. `0.0.0.0`, `127.0.0.0/8`, `10.10.34.34–36` in `10.0.0.0/8`, CGNAT, link-local, private).
pub fn is_sinkholed_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 0
        || a == 127
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a >= 224
}

fn evaluate_dns_response(rtt_ms: u128, rcode: u8, answers: &[Ipv4Addr]) -> DnsProbeResult {
    if rcode != 0 || answers.is_empty() {
        return DnsProbeResult {
            rtt_ms: Some(rtt_ms),
            status: ResolveStatus::NoAnswer,
            resolved_ip: None,
        };
    }
    if let Some(valid) = answers.iter().find(|&&ip| !is_sinkholed_ipv4(ip)) {
        return DnsProbeResult {
            rtt_ms: Some(rtt_ms),
            status: ResolveStatus::Ok,
            resolved_ip: Some(valid.to_string()),
        };
    }
    DnsProbeResult {
        rtt_ms: Some(rtt_ms),
        status: ResolveStatus::Blocked,
        resolved_ip: answers.first().map(|ip| ip.to_string()),
    }
}

fn probe_udp_53(target: SocketAddr, labels: &[&[u8]], timeout: Duration) -> Option<DnsProbeResult> {
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
    let rtt = start.elapsed().as_millis().max(1);

    let (rcode, answers) = parse_dns_a_answers(&buf[..len], tx_id)?;
    Some(evaluate_dns_response(rtt, rcode, &answers))
}

fn probe_tcp_53(target: SocketAddr, labels: &[&[u8]], timeout: Duration) -> Option<DnsProbeResult> {
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

    let mut body = vec![0u8; msg_len];
    stream.read_exact(&mut body).ok()?;
    let rtt = start.elapsed().as_millis().max(1);

    let (rcode, answers) = parse_dns_a_answers(&body, tx_id)?;
    Some(evaluate_dns_response(rtt, rcode, &answers))
}

/// Measures port-53 DNS latency and verifies real A-record resolution (catching sinkholes
/// such as `0.0.0.0`, `127.x.x.x`, or `10.10.34.x` filtering IPs) over UDP with TCP fallback.
pub fn probe_dns_resolve(server_ip: &str, domain: &str) -> DnsProbeResult {
    let Ok(ip) = server_ip.trim().parse::<IpAddr>() else {
        return DnsProbeResult {
            rtt_ms: None,
            status: ResolveStatus::Timeout,
            resolved_ip: None,
        };
    };
    let clean_domain = if is_valid_hostname(domain) {
        normalize_hostname(domain)
    } else {
        DEFAULT_RESOLVE_CHECK_DOMAIN.to_string()
    };
    let labels: Vec<&[u8]> = clean_domain.split('.').map(|s| s.as_bytes()).collect();
    let target = SocketAddr::new(ip, 53);

    probe_udp_53(target, &labels, Duration::from_millis(650))
        .or_else(|| probe_udp_53(target, &labels, Duration::from_millis(650)))
        .or_else(|| probe_tcp_53(target, &labels, Duration::from_millis(800)))
        .unwrap_or(DnsProbeResult {
            rtt_ms: None,
            status: ResolveStatus::Timeout,
            resolved_ip: None,
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckOutcome {
    UpToDate { current_version: String },
    Available { latest_version: String, download_url: String },
    Error(String),
}

#[derive(Debug, Deserialize)]
struct GitHubReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubReleasePayload {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

pub fn parse_semver(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw
        .trim()
        .trim_start_matches(['v', 'V'])
        .split('-')
        .next()?;
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    let patch = if parts.len() == 3 {
        parts[2].parse::<u64>().ok()?
    } else {
        0
    };
    Some((major, minor, patch))
}

pub fn parse_github_release_json(raw_json: &str, current_version: &str) -> UpdateCheckOutcome {
    let Ok(payload) = serde_json::from_str::<GitHubReleasePayload>(raw_json) else {
        return UpdateCheckOutcome::Error("Invalid release response".to_string());
    };
    let Some(latest_ver) = parse_semver(&payload.tag_name) else {
        return UpdateCheckOutcome::Error("No valid release tag found".to_string());
    };
    let Some(curr_ver) = parse_semver(current_version) else {
        return UpdateCheckOutcome::Error("Invalid current version".to_string());
    };

    if latest_ver > curr_ver {
        let normalized_tag = format!("v{}.{}.{}", latest_ver.0, latest_ver.1, latest_ver.2);
        let setup_url = payload
            .assets
            .iter()
            .find(|a| {
                a.name.eq_ignore_ascii_case("ShiftDNS-Setup.exe")
                    && is_allowed_release_url(&a.browser_download_url)
            })
            .map(|a| a.browser_download_url.clone());
        let download_url = setup_url.unwrap_or_else(|| {
            if is_allowed_release_url(&payload.html_url) {
                payload.html_url
            } else {
                GITHUB_RELEASES_URL.to_string()
            }
        });
        UpdateCheckOutcome::Available {
            latest_version: normalized_tag,
            download_url,
        }
    } else {
        UpdateCheckOutcome::UpToDate {
            current_version: format!("v{}.{}.{}", curr_ver.0, curr_ver.1, curr_ver.2),
        }
    }
}

fn fetch_latest_release_json() -> Result<String, String> {
    let mut curl = Command::new("curl.exe");
    #[cfg(target_os = "windows")]
    curl.creation_flags(CREATE_NO_WINDOW);
    if let Ok(output) = curl
        .args([
            "-sS",
            "-L",
            "--max-time",
            "6",
            "-w",
            "\n%{http_code}",
            "-H",
            "User-Agent: ShiftDNS",
            "-H",
            "Accept: application/vnd.github+json",
            GITHUB_LATEST_RELEASE_API,
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some((body, code_line)) = stdout.rsplit_once('\n') {
                match code_line.trim() {
                    "200" => return Ok(body.to_string()),
                    "404" => return Err("No releases published yet".to_string()),
                    "403" => return Err("GitHub rate limit reached".to_string()),
                    code => return Err(format!("GitHub returned HTTP {code}")),
                }
            }
        }
    }

    // Fallback for older Windows installs without curl.exe
    let mut ps = Command::new("powershell");
    #[cfg(target_os = "windows")]
    ps.creation_flags(CREATE_NO_WINDOW);
    let output = ps
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Invoke-RestMethod -Uri 'https://api.github.com/repos/NexiLune/ShiftDNS/releases/latest' -Headers @{ 'User-Agent' = 'ShiftDNS'; 'Accept' = 'application/vnd.github+json' } -TimeoutSec 6 | ConvertTo-Json -Depth 6 -Compress",
        ])
        .output()
        .map_err(|_| "Could not reach GitHub Releases".to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("404") {
            Err("No releases published yet".to_string())
        } else {
            Err("Update check failed (check network)".to_string())
        }
    }
}

/// Checks GitHub Releases (`NexiLune/ShiftDNS`) for a newer version without extra crates.
pub fn check_github_update(current_version: &str) -> UpdateCheckOutcome {
    match fetch_latest_release_json() {
        Ok(json) => parse_github_release_json(&json, current_version),
        Err(msg) => UpdateCheckOutcome::Error(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_a_answer_with_compression_pointer() {
        let mut pkt = build_dns_a_query(0xABCD, &[b"cloudflare", b"com"]);
        pkt[2] |= 0x80; // QR = 1
        pkt[7] = 1; // ANCOUNT = 1
        // Answer RR: pointer to offset 12 (0xC00C), TYPE A, CLASS IN, TTL 60, RDLEN 4, 104.16.132.229
        pkt.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 104, 16, 132,
            229,
        ]);

        let (rcode, answers) = parse_dns_a_answers(&pkt, 0xABCD).expect("valid response");
        assert_eq!(rcode, 0);
        assert_eq!(answers, vec![Ipv4Addr::new(104, 16, 132, 229)]);
        assert_eq!(
            evaluate_dns_response(12, rcode, &answers).status,
            ResolveStatus::Ok
        );
    }

    #[test]
    fn flags_sinkholed_and_filtering_ips() {
        assert!(is_sinkholed_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_sinkholed_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_sinkholed_ipv4(Ipv4Addr::new(10, 10, 34, 35)));
        assert!(is_sinkholed_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_sinkholed_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_sinkholed_ipv4(Ipv4Addr::new(104, 16, 132, 229)));

        let blocked = evaluate_dns_response(15, 0, &[Ipv4Addr::new(10, 10, 34, 35)]);
        assert_eq!(blocked.status, ResolveStatus::Blocked);
        assert_eq!(blocked.resolved_ip.as_deref(), Some("10.10.34.35"));
    }

    #[test]
    fn parses_github_release_and_prefers_setup_exe() {
        let json = r#"{
            "tag_name": "v1.2.0",
            "html_url": "https://github.com/NexiLune/ShiftDNS/releases/tag/v1.2.0",
            "assets": [
                {
                    "name": "ShiftDNS-Setup.exe",
                    "browser_download_url": "https://github.com/NexiLune/ShiftDNS/releases/download/v1.2.0/ShiftDNS-Setup.exe"
                }
            ]
        }"#;
        assert_eq!(
            parse_github_release_json(json, "1.0.0"),
            UpdateCheckOutcome::Available {
                latest_version: "v1.2.0".into(),
                download_url: "https://github.com/NexiLune/ShiftDNS/releases/download/v1.2.0/ShiftDNS-Setup.exe".into(),
            }
        );
        assert_eq!(
            parse_github_release_json(json, "1.2.0"),
            UpdateCheckOutcome::UpToDate {
                current_version: "v1.2.0".into()
            }
        );
    }
}
