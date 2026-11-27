use crate::config::DnsProfile;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub struct NetworkAdapter {
    pub name: String,
    pub guid: String,
    pub description: String,
    pub metric: u32,
    pub state: String,
    pub current_dns: Vec<String>,
    pub is_dhcp: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub fn parse_guid_str(raw: &str) -> Option<WinGuid> {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    let mut parts = trimmed.split('-');
    let p1 = parts.next()?;
    let p2 = parts.next()?;
    let p3 = parts.next()?;
    let p4 = parts.next()?;
    let p5 = parts.next()?;
    if parts.next().is_some()
        || p1.len() != 8
        || p2.len() != 4
        || p3.len() != 4
        || p4.len() != 4
        || p5.len() != 12
    {
        return None;
    }
    let data1 = u32::from_str_radix(p1, 16).ok()?;
    let data2 = u16::from_str_radix(p2, 16).ok()?;
    let data3 = u16::from_str_radix(p3, 16).ok()?;
    let mut data4 = [0u8; 8];
    data4[0] = u8::from_str_radix(&p4[0..2], 16).ok()?;
    data4[1] = u8::from_str_radix(&p4[2..4], 16).ok()?;
    for i in 0..6 {
        data4[2 + i] = u8::from_str_radix(&p5[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(WinGuid {
        data1,
        data2,
        data3,
        data4,
    })
}

fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(target_os = "windows")]
mod win_dns_api {
    use super::WinGuid;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    const DNS_INTERFACE_SETTINGS_VERSION1: u32 = 1;
    const DNS_SETTING_IPV6: u64 = 0x0001;
    const DNS_SETTING_NAMESERVER: u64 = 0x0002;

    #[repr(C)]
    struct DnsInterfaceSettings {
        version: u32,
        flags: u64,
        domain: *mut u16,
        name_server: *mut u16,
        search_list: *mut u16,
        registration_enabled: u32,
        register_adapter_name: u32,
        enable_llmnr: u32,
        query_adapter_name: u32,
        profile_name_server: *mut u16,
    }

    type SetInterfaceDnsSettingsFn =
        unsafe extern "system" fn(WinGuid, *const DnsInterfaceSettings) -> u32;
    type DnsFlushResolverCacheFn = unsafe extern "system" fn() -> i32;

    static SET_DNS_FN: OnceLock<Option<SetInterfaceDnsSettingsFn>> = OnceLock::new();
    static FLUSH_DNS_FN: OnceLock<Option<DnsFlushResolverCacheFn>> = OnceLock::new();

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn resolve_set_dns_fn() -> Option<SetInterfaceDnsSettingsFn> {
        *SET_DNS_FN.get_or_init(|| unsafe {
            let dll = to_wide("iphlpapi.dll");
            let module = LoadLibraryW(dll.as_ptr());
            if module.is_null() {
                return None;
            }
            let sym = GetProcAddress(module, b"SetInterfaceDnsSettings\0".as_ptr());
            sym.map(|f| std::mem::transmute::<_, SetInterfaceDnsSettingsFn>(f))
        })
    }

    fn resolve_flush_dns_fn() -> Option<DnsFlushResolverCacheFn> {
        *FLUSH_DNS_FN.get_or_init(|| unsafe {
            let dll = to_wide("dnsapi.dll");
            let module = LoadLibraryW(dll.as_ptr());
            if module.is_null() {
                return None;
            }
            let sym = GetProcAddress(module, b"DnsFlushResolverCache\0".as_ptr());
            sym.map(|f| std::mem::transmute::<_, DnsFlushResolverCacheFn>(f))
        })
    }

    /// Directly updates interface DNS via iphlpapi.dll::SetInterfaceDnsSettings (~1-3ms).
    /// Passing an empty `servers_csv` clears static DNS and restores DHCP.
    pub fn set_interface_dns(guid: WinGuid, ipv6: bool, servers_csv: &str) -> Result<(), u32> {
        let func = resolve_set_dns_fn().ok_or(u32::MAX)?;
        let mut ns_wide = to_wide(servers_csv);
        let flags = if ipv6 {
            DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER
        } else {
            DNS_SETTING_NAMESERVER
        };
        let settings = DnsInterfaceSettings {
            version: DNS_INTERFACE_SETTINGS_VERSION1,
            flags,
            domain: std::ptr::null_mut(),
            name_server: ns_wide.as_mut_ptr(),
            search_list: std::ptr::null_mut(),
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            profile_name_server: std::ptr::null_mut(),
        };
        let status = unsafe { func(guid, &settings) };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    type NotifyChangeFn = unsafe extern "system" fn(
        *mut *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> u32;

    fn resolve_iphlpapi_notify(symbol: &'static [u8]) -> Option<NotifyChangeFn> {
        unsafe {
            let dll = to_wide("iphlpapi.dll");
            let module = LoadLibraryW(dll.as_ptr());
            if module.is_null() {
                return None;
            }
            let sym = GetProcAddress(module, symbol.as_ptr());
            sym.map(|f| std::mem::transmute::<_, NotifyChangeFn>(f))
        }
    }

    pub fn spawn_network_change_watcher<F>(on_change: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        use std::sync::Arc;
        use std::time::Duration;

        let callback = Arc::new(on_change);
        for symbol in [b"NotifyAddrChange\0".as_slice(), b"NotifyRouteChange\0".as_slice()] {
            let Some(notify_fn) = resolve_iphlpapi_notify(symbol) else {
                continue;
            };
            let cb = Arc::clone(&callback);
            std::thread::spawn(move || loop {
                let status = unsafe { notify_fn(std::ptr::null_mut(), std::ptr::null_mut()) };
                if status == 0 {
                    cb();
                    // Coalesce rapid bursts during Wi-Fi roaming / DHCP lease acquisition.
                    std::thread::sleep(Duration::from_millis(1500));
                } else {
                    std::thread::sleep(Duration::from_secs(10));
                }
            });
        }
    }

    /// Directly flushes the Windows DNS resolver cache via dnsapi.dll::DnsFlushResolverCache (<1ms).
    pub fn flush_resolver_cache() -> bool {
        let Some(func) = resolve_flush_dns_fn() else {
            return false;
        };
        unsafe { func() != 0 }
    }
}

/// Watches OS IP address and routing table changes (Wi-Fi switch, disconnect/reconnect,
/// adapter link change) with zero polling and invokes `on_change`.
pub fn spawn_network_change_watcher<F>(on_change: F)
where
    F: Fn() + Send + Sync + 'static,
{
    #[cfg(target_os = "windows")]
    win_dns_api::spawn_network_change_watcher(on_change);
    #[cfg(not(target_os = "windows"))]
    let _ = on_change;
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
        // Tab-separated: metric \t virtual(0|1) \t name \t InterfaceGuid \t InterfaceDescription \t NameServer
        let mut cols = trimmed.splitn(6, '\t');
        let metric = cols
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(9999);
        let is_virtual = cols.next().map(|s| s.trim() == "1").unwrap_or(false);
        let name = cols.next().unwrap_or("").trim().to_string();
        let guid = cols.next().unwrap_or("").trim().to_string();
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
            guid,
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
/// locale-independent PowerShell query (Status -eq 'Up', route metric, InterfaceGuid,
/// InterfaceDescription, and TCPIP registry NameServer).
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
        "($met,$virt,$_.Name,$_.InterfaceGuid,$_.InterfaceDescription,[string]$ns) -join [char]9 }"
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

fn join_servers_csv(primary: &str, secondary: &str) -> String {
    let p = primary.trim();
    let s = secondary.trim();
    if p.is_empty() {
        String::new()
    } else if s.is_empty() {
        p.to_string()
    } else {
        format!("{p},{s}")
    }
}

fn apply_adapter_dns_netsh(
    adapter_name: &str,
    profile: &DnsProfile,
    enable_ipv6: bool,
) -> Result<(), String> {
    let name_arg = format!("name={adapter_name}");
    let p4_arg = format!("address={}", profile.primary_v4);
    run_netsh(
        &format!("Failed setting primary IPv4 DNS on {adapter_name}"),
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
            &format!("Failed adding secondary IPv4 DNS on {adapter_name}"),
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

    if enable_ipv6 && !profile.primary_v6.trim().is_empty() {
        let p6_arg = format!("address={}", profile.primary_v6);
        run_netsh(
            &format!("Failed setting primary IPv6 DNS on {adapter_name}"),
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
                &format!("Failed adding secondary IPv6 DNS on {adapter_name}"),
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
        let _ = run_netsh(
            &format!("Failed resetting IPv6 DNS on {adapter_name}"),
            &["interface", "ipv6", "set", "dnsservers", &name_arg, "source=dhcp"],
        );
    }

    Ok(())
}

fn reset_adapter_dhcp_netsh(adapter_name: &str) -> Result<(), String> {
    let name_arg = format!("name={adapter_name}");
    run_netsh(
        &format!("Failed resetting IPv4 DNS to DHCP on {adapter_name}"),
        &["interface", "ipv4", "set", "dnsservers", &name_arg, "source=dhcp"],
    )?;
    let _ = run_netsh(
        &format!("Failed resetting IPv6 DNS to DHCP on {adapter_name}"),
        &["interface", "ipv6", "set", "dnsservers", &name_arg, "source=dhcp"],
    );
    Ok(())
}

fn register_doh_async(primary_v4: String, secondary_v4: String, doh_template: String) {
    std::thread::spawn(move || {
        for server_ip in [primary_v4.trim(), secondary_v4.trim()] {
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
                let _ = run_netsh(
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
                );
            }
        }
    });
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

    let v4_csv = join_servers_csv(&profile.primary_v4, &profile.secondary_v4);
    let v6_csv = if enable_ipv6 {
        join_servers_csv(&profile.primary_v6, &profile.secondary_v6)
    } else {
        String::new()
    };

    for (adapter_name, guid_opt) in targets {
        #[cfg(target_os = "windows")]
        let applied_via_api = if let Some(guid) = guid_opt {
            if win_dns_api::set_interface_dns(guid, false, &v4_csv).is_ok() {
                // Best-effort IPv6 update/clear via Win32 API (IPv6 may be disabled on the NIC)
                let _ = win_dns_api::set_interface_dns(guid, true, &v6_csv);
                true
            } else {
                false
            }
        } else {
            false
        };

        #[cfg(not(target_os = "windows"))]
        let applied_via_api = {
            let _ = (&guid_opt, &v4_csv, &v6_csv);
            false
        };

        if !applied_via_api {
            apply_adapter_dns_netsh(&adapter_name, profile, enable_ipv6)?;
        }
    }

    // Optional Windows 11 native DoH registration runs asynchronously so switching stays instant
    let doh_template = profile.doh_template.trim().to_string();
    if enable_doh && !doh_template.is_empty() {
        register_doh_async(
            profile.primary_v4.clone(),
            profile.secondary_v4.clone(),
            doh_template,
        );
    }

    spawn_flush_dns_async();
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

    for (adapter_name, guid_opt) in targets {
        #[cfg(target_os = "windows")]
        let reset_via_api = if let Some(guid) = guid_opt {
            if win_dns_api::set_interface_dns(guid, false, "").is_ok() {
                let _ = win_dns_api::set_interface_dns(guid, true, "");
                true
            } else {
                false
            }
        } else {
            false
        };

        #[cfg(not(target_os = "windows"))]
        let reset_via_api = {
            let _ = &guid_opt;
            false
        };

        if !reset_via_api {
            reset_adapter_dhcp_netsh(&adapter_name)?;
        }
    }

    spawn_flush_dns_async();
    Ok(())
}

/// Flushes the Windows DNS resolver cache on a background thread using direct Win32
/// `DnsFlushResolverCache` (with `ipconfig /flushdns` fallback) so DNS switching never blocks.
pub fn spawn_flush_dns_async() {
    std::thread::spawn(|| {
        let _ = flush_dns();
    });
}

pub fn flush_dns() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    if win_dns_api::flush_resolver_cache() {
        return Ok("DNS resolver cache flushed.".into());
    }

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

fn resolve_targets(
    adapters: &[NetworkAdapter],
    target_adapter: Option<&str>,
) -> Vec<(String, Option<WinGuid>)> {
    match target_adapter {
        Some(name) => {
            let guid = adapters
                .iter()
                .find(|a| a.name == name)
                .and_then(|a| parse_guid_str(&a.guid));
            vec![(name.to_string(), guid)]
        }
        None => adapters
            .iter()
            .map(|a| (a.name.clone(), parse_guid_str(&a.guid)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_interface_guid() {
        let g = parse_guid_str("{6B29FC40-CA47-1067-B31D-00DD010662DA}").expect("valid guid");
        assert_eq!(g.data1, 0x6B29FC40);
        assert_eq!(g.data2, 0xCA47);
        assert_eq!(g.data3, 0x1067);
        assert_eq!(g.data4, [0xB3, 0x1D, 0x00, 0xDD, 0x01, 0x06, 0x62, 0xDA]);
        assert!(parse_guid_str("not-a-guid").is_none());
    }

    #[test]
    fn parses_adapter_rows_with_guid() {
        let row = "15\t0\tWi-Fi\t{6B29FC40-CA47-1067-B31D-00DD010662DA}\tIntel Wi-Fi 6E\t1.1.1.1,1.0.0.1";
        let list = parse_adapter_rows(row);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Wi-Fi");
        assert_eq!(list[0].guid, "{6B29FC40-CA47-1067-B31D-00DD010662DA}");
        assert_eq!(list[0].current_dns, vec!["1.1.1.1", "1.0.0.1"]);
    }
}
