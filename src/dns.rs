use crate::config::DnsProfile;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub struct NetworkAdapter {
    pub name: String,
    pub description: String,
    pub metric: u32,
    pub state: String,
    pub current_dns: Vec<String>,
    pub is_dhcp: bool,
}

fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

fn has_word_token(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

pub fn is_excluded_adapter(name: &str, description: &str) -> bool {
    let lower_name = name.to_lowercase();
    let lower_desc = description.to_lowercase();
    // Match short ambiguous acronyms on word boundaries so "Tuned Ethernet" or "Tapestry" isn't hidden.
    if ["tun", "tap", "wsl"]
        .iter()
        .any(|kw| has_word_token(&lower_name, kw) || has_word_token(&lower_desc, kw))
    {
        return true;
    }
    [
        "xray",
        "v2ray",
        "sing-box",
        "clash",
        "wintun",
        "wireguard",
        "virtual",
        "loopback",
        "teredo",
        "isatap",
        "6to4",
        "iphttps",
        "vethernet",
        "vmware",
        "virtualbox",
        "hyper-v",
        "bluetooth",
        "npcap",
        "tailscale",
        "zerotier",
        "openvpn",
        "nordlynx",
        "proton",
        "hamachi",
        "radmin",
        "pseudo",
    ]
    .iter()
    .any(|kw| lower_name.contains(kw) || lower_desc.contains(kw))
}

fn parse_adapter_rows(stdout: &str) -> Vec<NetworkAdapter> {
    let mut physical = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Tab-separated: metric \t virtual(0|1) \t name \t InterfaceDescription \t NameServer
        let mut cols = trimmed.splitn(5, '\t');
        let metric = cols
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(9999);
        let is_virtual = cols.next().map(|s| s.trim() == "1").unwrap_or(false);
        let name = cols.next().unwrap_or("").trim().to_string();
        let description = cols.next().unwrap_or("").trim().to_string();
        let ns_raw = cols.next().unwrap_or("").trim();

        if name.is_empty() || is_virtual || is_excluded_adapter(&name, &description) {
            continue;
        }

        let current_dns: Vec<String> = ns_raw
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.parse::<std::net::Ipv4Addr>().is_ok())
            .map(str::to_string)
            .collect();
        let is_dhcp = current_dns.is_empty();

        physical.push(NetworkAdapter {
            name,
            description,
            metric,
            state: "Up".to_string(),
            current_dns,
            is_dhcp,
        });
    }

    physical.sort_by_key(|a| a.metric);
    physical
}

/// Enumerates connected physical network interfaces and their IPv4 DNS configuration in one
/// locale-independent PowerShell query (Status -eq 'Up', route metric, InterfaceDescription, and
/// TCPIP registry NameServer), avoiding localized netsh output and N+1 subprocesses.
pub fn list_adapters() -> Vec<NetworkAdapter> {
    let script = concat!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ",
        "$m=@{}; Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ",
        "ForEach-Object { $m[[int]$_.InterfaceIndex]=[int]$_.InterfaceMetric }; ",
        "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { ",
        "$idx=[int]$_.ifIndex; ",
        "$met=if($m.ContainsKey($idx)){$m[$idx]}else{9999}; ",
        "$virt=if($_.Virtual){'1'}else{'0'}; ",
        "$ns=(Get-ItemProperty -Path ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\'+$_.InterfaceGuid) -Name NameServer -ErrorAction SilentlyContinue).NameServer; ",
        "($met,$virt,$_.Name,$_.InterfaceDescription,[string]$ns) -join [char]9 }"
    );

    let output = match hidden_command("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
    {
        Ok(out) if out.status.success() => out,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_adapter_rows(&stdout)
}

/// Detects the real active DNS resolver currently set on the primary active physical adapter
/// (or selected adapter) and matches it against preset/custom profiles, returning None for DHCP.
pub fn detect_active_profile_id(
    adapters: &[NetworkAdapter],
    selected_adapter: Option<&str>,
    profiles: &[DnsProfile],
) -> Option<String> {
    let target = match selected_adapter {
        Some(name) => adapters.iter().find(|a| a.name == name),
        None => adapters.first(),
    }?;

    if target.is_dhcp || target.current_dns.is_empty() {
        return None;
    }

    let p1 = target.current_dns[0].trim();
    let p2 = target.current_dns.get(1).map(|s| s.trim()).unwrap_or("");

    // Prefer exact primary + secondary IPv4 match first
    if let Some(exact) = profiles.iter().find(|p| {
        p.primary_v4.trim() == p1
            && (p2.is_empty() || p.secondary_v4.trim() == p2)
    }) {
        return Some(exact.id.clone());
    }

    // Fallback to primary IPv4 match
    profiles
        .iter()
        .find(|p| p.primary_v4.trim() == p1)
        .map(|p| p.id.clone())
}

fn format_cmd_failure(label: &str, out: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if !err.trim().is_empty() {
        err.trim()
    } else {
        stdout.trim()
    };
    if detail.is_empty() {
        label.to_string()
    } else {
        format!("{label}: {detail}")
    }
}

fn run_netsh(label: &str, args: &[&str]) -> Result<(), String> {
    let out = hidden_command("netsh")
        .args(args)
        .output()
        .map_err(|e| format!("{label}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format_cmd_failure(label, &out))
    }
}

pub fn apply_profile(
    adapters: &[NetworkAdapter],
    target_adapter: Option<&str>,
    profile: &DnsProfile,
    enable_ipv6: bool,
    enable_doh: bool,
) -> Result<(), String> {
    let targets = resolve_targets(adapters, target_adapter);
    if targets.is_empty() {
        return Err("No connected network adapter found.".into());
    }

    for adapter in targets {
        let name_arg = format!("name={adapter}");
        let p4_arg = format!("address={}", profile.primary_v4);
        run_netsh(
            &format!("Failed setting primary IPv4 DNS on {adapter}"),
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &name_arg,
                "source=static",
                &p4_arg,
                "register=primary",
                "validate=no",
            ],
        )?;

        if !profile.secondary_v4.trim().is_empty() {
            let s4_arg = format!("address={}", profile.secondary_v4);
            run_netsh(
                &format!("Failed adding secondary IPv4 DNS on {adapter}"),
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    &name_arg,
                    &s4_arg,
                    "index=2",
                    "validate=no",
                ],
            )?;
        }

        // IPv6 DNS: apply static IPv6 if enabled and configured, otherwise reset IPv6 to DHCP
        // so stale IPv6 resolvers from a previous profile cannot bypass the new IPv4 DNS.
        if enable_ipv6 && !profile.primary_v6.trim().is_empty() {
            let p6_arg = format!("address={}", profile.primary_v6);
            run_netsh(
                &format!("Failed setting primary IPv6 DNS on {adapter}"),
                &[
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    &name_arg,
                    "source=static",
                    &p6_arg,
                    "validate=no",
                ],
            )?;

            if !profile.secondary_v6.trim().is_empty() {
                let s6_arg = format!("address={}", profile.secondary_v6);
                run_netsh(
                    &format!("Failed adding secondary IPv6 DNS on {adapter}"),
                    &[
                        "interface",
                        "ipv6",
                        "add",
                        "dnsservers",
                        &name_arg,
                        &s6_arg,
                        "index=2",
                        "validate=no",
                    ],
                )?;
            }
        } else {
            // Best-effort clear of stale IPv6 static DNS (IPv6 may be disabled on the NIC)
            let _ = run_netsh(
                &format!("Failed resetting IPv6 DNS on {adapter}"),
                &["interface", "ipv6", "set", "dnsservers", &name_arg, "source=dhcp"],
            );
        }
    }

    // Optional Windows 11 native DoH registration for primary & secondary IPv4 servers
    let doh_template = profile.doh_template.trim();
    if enable_doh && !doh_template.is_empty() {
        for server_ip in [profile.primary_v4.trim(), profile.secondary_v4.trim()] {
            if server_ip.is_empty() {
                continue;
            }
            let server_arg = format!("server={server_ip}");
            let template_arg = format!("dohtemplate={doh_template}");
            let add_res = run_netsh(
                &format!("Failed registering DoH for {server_ip}"),
                &[
                    "dns",
                    "add",
                    "encryption",
                    &server_arg,
                    &template_arg,
                    "autoupgrade=yes",
                    "udpfallback=no",
                ],
            );
            if add_res.is_err() {
                run_netsh(
                    &format!("Failed enabling DoH for {server_ip}"),
                    &[
                        "dns",
                        "set",
                        "encryption",
                        &server_arg,
                        &template_arg,
                        "autoupgrade=yes",
                        "udpfallback=no",
                    ],
                )?;
            }
        }
    }

    flush_dns()?;
    Ok(())
}

pub fn reset_to_dhcp(
    adapters: &[NetworkAdapter],
    target_adapter: Option<&str>,
) -> Result<(), String> {
    let targets = resolve_targets(adapters, target_adapter);
    if targets.is_empty() {
        return Err("No connected network adapter found.".into());
    }

    for adapter in targets {
        let name_arg = format!("name={adapter}");
        run_netsh(
            &format!("Failed resetting IPv4 DNS to DHCP on {adapter}"),
            &["interface", "ipv4", "set", "dnsservers", &name_arg, "source=dhcp"],
        )?;
        let _ = run_netsh(
            &format!("Failed resetting IPv6 DNS to DHCP on {adapter}"),
            &["interface", "ipv6", "set", "dnsservers", &name_arg, "source=dhcp"],
        );
    }

    flush_dns()?;
    Ok(())
}

pub fn flush_dns() -> Result<String, String> {
    let out = hidden_command("ipconfig")
        .arg("/flushdns")
        .output()
        .map_err(|e| format!("Failed to flush DNS cache: {e}"))?;

    if out.status.success() {
        Ok("DNS resolver cache flushed.".into())
    } else {
        Err(format_cmd_failure("Failed to flush DNS cache", &out))
    }
}

pub fn cycle_selected_adapter(
    current: Option<&str>,
    adapters: &[NetworkAdapter],
) -> Option<String> {
    let available: Vec<&str> = adapters
        .iter()
        .filter(|a| !is_excluded_adapter(&a.name, &a.description))
        .map(|a| a.name.as_str())
        .collect();
    if available.is_empty() {
        return None;
    }
    match current {
        None => Some(available[0].to_string()),
        Some(cur) => match available.iter().position(|name| *name == cur) {
            Some(idx) if idx + 1 < available.len() => Some(available[idx + 1].to_string()),
            _ => None,
        },
    }
}

fn resolve_targets(adapters: &[NetworkAdapter], target_adapter: Option<&str>) -> Vec<String> {
    match target_adapter {
        Some(name) => vec![name.to_string()],
        None => adapters.iter().map(|a| a.name.clone()).collect(),
    }
}
