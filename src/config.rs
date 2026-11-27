use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsProfile {
    pub id: String,
    pub name: String,
    pub category: String,
    pub primary_v4: String,
    pub secondary_v4: String,
    pub primary_v6: String,
    pub secondary_v6: String,
    pub doh_template: String,
    pub is_custom: bool,
}

pub const DEFAULT_RESOLVE_CHECK_DOMAIN: &str = "cloudflare.com";

fn default_true() -> bool {
    true
}

fn default_resolve_check_domain() -> String {
    DEFAULT_RESOLVE_CHECK_DOMAIN.to_string()
}

pub fn normalize_hostname(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn is_valid_hostname(domain: &str) -> bool {
    let clean = normalize_hostname(domain);
    if clean.is_empty() || clean.len() > 253 || !clean.contains('.') {
        return false;
    }
    if clean.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = clean.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    System,
    Dark,
    Light,
}

impl ThemeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            _ => None,
        }
    }

    pub fn resolve_dark(self, system_dark: bool) -> bool {
        match self {
            Self::System => system_dark,
            Self::Dark => true,
            Self::Light => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub selected_adapter: Option<String>,
    pub active_profile_id: Option<String>,
    pub enable_ipv6: bool,
    pub enable_doh: bool,
    pub start_minimized: bool,
    pub launch_at_startup: bool,
    pub dark_mode: bool,
    #[serde(default)]
    pub theme_mode: Option<ThemeMode>,
    #[serde(default = "default_true")]
    pub sound_effects: bool,
    #[serde(default = "default_resolve_check_domain")]
    pub resolve_check_domain: String,
    #[serde(default)]
    pub usage_counts: HashMap<String, u32>,
    pub profiles: Vec<DnsProfile>,
}

impl AppConfig {
    pub fn effective_theme_mode(&self) -> ThemeMode {
        self.theme_mode.unwrap_or(if self.dark_mode {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        })
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            selected_adapter: None,
            active_profile_id: None,
            enable_ipv6: true,
            enable_doh: false,
            start_minimized: false,
            launch_at_startup: false,
            dark_mode: true,
            theme_mode: Some(ThemeMode::System),
            sound_effects: true,
            resolve_check_domain: default_resolve_check_domain(),
            usage_counts: HashMap::new(),
            profiles: default_profiles(),
        }
    }
}

pub fn top_used_profiles(
    profiles: &[DnsProfile],
    usage_counts: &HashMap<String, u32>,
    limit: usize,
    active_profile_id: Option<&str>,
) -> Vec<DnsProfile> {
    if limit == 0 || profiles.is_empty() {
        return Vec::new();
    }
    let active = active_profile_id.and_then(|id| profiles.iter().find(|p| p.id == id).cloned());
    let mut ranked: Vec<(usize, u32, DnsProfile)> = profiles
        .iter()
        .enumerate()
        .filter(|(_, p)| active.as_ref().map_or(true, |a| a.id != p.id))
        .map(|(idx, p)| (idx, *usage_counts.get(&p.id).unwrap_or(&0), p.clone()))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut result = Vec::with_capacity(limit);
    if let Some(a) = active {
        result.push(a);
    }
    for (_, _, p) in ranked {
        if result.len() >= limit {
            break;
        }
        result.push(p);
    }
    result
}

pub fn default_profiles() -> Vec<DnsProfile> {
    vec![
        DnsProfile {
            id: "cloudflare".into(),
            name: "Cloudflare".into(),
            category: "Speed".into(),
            primary_v4: "1.1.1.1".into(),
            secondary_v4: "1.0.0.1".into(),
            primary_v6: "2606:4700:4700::1111".into(),
            secondary_v6: "2606:4700:4700::1001".into(),
            doh_template: "https://cloudflare-dns.com/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "cloudflare-family".into(),
            name: "Cloudflare Family".into(),
            category: "Family".into(),
            primary_v4: "1.1.1.3".into(),
            secondary_v4: "1.0.0.3".into(),
            primary_v6: "2606:4700:4700::1113".into(),
            secondary_v6: "2606:4700:4700::1003".into(),
            doh_template: "https://family.cloudflare-dns.com/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "quad9".into(),
            name: "Quad9".into(),
            category: "Security".into(),
            primary_v4: "9.9.9.9".into(),
            secondary_v4: "149.112.112.112".into(),
            primary_v6: "2620:fe::fe".into(),
            secondary_v6: "2620:fe::9".into(),
            doh_template: "https://dns.quad9.net/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "google".into(),
            name: "Google Public".into(),
            category: "Speed".into(),
            primary_v4: "8.8.8.8".into(),
            secondary_v4: "8.8.4.4".into(),
            primary_v6: "2001:4860:4860::8888".into(),
            secondary_v6: "2001:4860:4860::8844".into(),
            doh_template: "https://dns.google/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "adguard".into(),
            name: "AdGuard".into(),
            category: "Ad-Block".into(),
            primary_v4: "94.140.14.14".into(),
            secondary_v4: "94.140.15.15".into(),
            primary_v6: "2a10:50c0::ad1:ff".into(),
            secondary_v6: "2a10:50c0::ad2:ff".into(),
            doh_template: "https://dns.adguard-dns.com/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "mullvad".into(),
            name: "Mullvad".into(),
            category: "Privacy".into(),
            primary_v4: "194.242.2.2".into(),
            secondary_v4: "194.242.2.4".into(),
            primary_v6: "2a07:e340::2".into(),
            secondary_v6: "2a07:e340::4".into(),
            doh_template: "https://dns.mullvad.net/dns-query".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "controld".into(),
            name: "Control D".into(),
            category: "Ad-Block".into(),
            primary_v4: "76.76.2.2".into(),
            secondary_v4: "76.76.10.2".into(),
            primary_v6: "2606:1a40::2".into(),
            secondary_v6: "2606:1a40:1::2".into(),
            doh_template: "https://freedns.controld.com/p2".into(),
            is_custom: false,
        },
        DnsProfile {
            id: "opendns".into(),
            name: "OpenDNS Home".into(),
            category: "Security".into(),
            primary_v4: "208.67.222.222".into(),
            secondary_v4: "208.67.220.220".into(),
            primary_v6: "2620:119:35::35".into(),
            secondary_v6: "2620:119:53::53".into(),
            doh_template: "https://doh.opendns.com/dns-query".into(),
            is_custom: false,
        },
    ]
}

fn config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("ShiftDNS").join("config.json")
}

pub fn webview_data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("ShiftDNS").join("WebView2");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn is_valid_doh_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let after = &authority[end + 1..];
        if !after.is_empty() {
            let Some(port) = after.strip_prefix(':') else {
                return false;
            };
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        &authority[1..end]
    } else if let Some((h, port)) = authority.split_once(':') {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        h
    } else {
        authority
    };
    !host.is_empty() && (host.contains('.') || host.contains(':') || host.eq_ignore_ascii_case("localhost"))
}

fn is_valid_profile(p: &DnsProfile) -> bool {
    !p.id.trim().is_empty()
        && !p.name.trim().is_empty()
        && p.primary_v4.trim().parse::<std::net::Ipv4Addr>().is_ok()
        && (p.secondary_v4.trim().is_empty()
            || p.secondary_v4.trim().parse::<std::net::Ipv4Addr>().is_ok())
        && (p.primary_v6.trim().is_empty()
            || p.primary_v6.trim().parse::<std::net::Ipv6Addr>().is_ok())
        && (p.secondary_v6.trim().is_empty()
            || p.secondary_v6.trim().parse::<std::net::Ipv6Addr>().is_ok())
        && is_valid_doh_url(&p.doh_template)
}

impl AppConfig {
    pub fn load() -> Self {
        let path = config_path();
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(mut parsed) = serde_json::from_str::<AppConfig>(&raw) {
                parsed.profiles.retain(is_valid_profile);
                for p in &mut parsed.profiles {
                    p.id = p.id.trim().to_string();
                    p.name = p.name.trim().to_string();
                    p.primary_v4 = p.primary_v4.trim().to_string();
                    p.secondary_v4 = p.secondary_v4.trim().to_string();
                    p.primary_v6 = p.primary_v6.trim().to_string();
                    p.secondary_v6 = p.secondary_v6.trim().to_string();
                    p.doh_template = p.doh_template.trim().to_string();
                    match (p.id.as_str(), p.name.as_str()) {
                        ("google", "Google Public DNS") => p.name = "Google Public".into(),
                        ("adguard", "AdGuard DNS") => p.name = "AdGuard".into(),
                        ("mullvad", "Mullvad DNS") => p.name = "Mullvad".into(),
                        _ => {}
                    }
                }
                if let Some(ref active_id) = parsed.active_profile_id {
                    if !parsed.profiles.iter().any(|p| &p.id == active_id) {
                        parsed.active_profile_id = None;
                    }
                }
                if let Some(ref adapter) = parsed.selected_adapter {
                    let clean = adapter.trim();
                    if clean.is_empty() || clean.chars().any(|c| c.is_control()) {
                        parsed.selected_adapter = None;
                    }
                }
                if is_valid_hostname(&parsed.resolve_check_domain) {
                    parsed.resolve_check_domain = normalize_hostname(&parsed.resolve_check_domain);
                } else {
                    parsed.resolve_check_domain = default_resolve_check_domain();
                }
                return parsed;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed creating config directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed serializing config: {e}"))?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, json).map_err(|e| format!("Failed writing config: {e}"))?;
        if let Err(e) = fs::rename(&tmp_path, &path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed saving config: {e}"));
        }
        Ok(())
    }
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn encode_utf16_le_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn parse_whoami_sid(stdout: &str) -> Option<String> {
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    let trimmed = line.trim_end_matches('"');
    let sid = trimmed.rsplit('"').next()?.trim();
    if sid.starts_with("S-1-")
        && sid.len() > 4
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        Some(sid.to_string())
    } else {
        None
    }
}

fn current_windows_user_id() -> Result<String, String> {
    let mut cmd = Command::new("whoami");
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    if let Ok(output) = cmd.args(["/user", "/fo", "csv", "/nh"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(sid) = parse_whoami_sid(&stdout) {
                return Ok(sid);
            }
        }
    }

    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    if !user.is_empty() && !domain.is_empty() {
        Ok(format!("{domain}\\{user}"))
    } else if !user.is_empty() {
        Ok(user)
    } else {
        Err("Could not determine current Windows user.".into())
    }
}

fn build_startup_task_xml(user_id: &str, exe_path: &str, working_dir: &str) -> String {
    let user_xml = xml_escape(user_id);
    let exe_xml = xml_escape(exe_path);
    let wd_line = if working_dir.is_empty() {
        String::new()
    } else {
        format!("\r\n      <WorkingDirectory>{}</WorkingDirectory>", xml_escape(working_dir))
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
  <RegistrationInfo>\r\n\
    <Description>Launch ShiftDNS at Windows logon with administrator privileges.</Description>\r\n\
  </RegistrationInfo>\r\n\
  <Triggers>\r\n\
    <LogonTrigger>\r\n\
      <Enabled>true</Enabled>\r\n\
      <UserId>{user_xml}</UserId>\r\n\
      <Delay>PT3S</Delay>\r\n\
    </LogonTrigger>\r\n\
  </Triggers>\r\n\
  <Principals>\r\n\
    <Principal id=\"Author\">\r\n\
      <UserId>{user_xml}</UserId>\r\n\
      <LogonType>InteractiveToken</LogonType>\r\n\
      <RunLevel>HighestAvailable</RunLevel>\r\n\
    </Principal>\r\n\
  </Principals>\r\n\
  <Settings>\r\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
    <AllowHardTerminate>false</AllowHardTerminate>\r\n\
    <StartWhenAvailable>true</StartWhenAvailable>\r\n\
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n\
    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n\
    <Enabled>true</Enabled>\r\n\
    <Hidden>false</Hidden>\r\n\
    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n\
    <WakeToRun>false</WakeToRun>\r\n\
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
    <Priority>7</Priority>\r\n\
  </Settings>\r\n\
  <Actions Context=\"Author\">\r\n\
    <Exec>\r\n\
      <Command>{exe_xml}</Command>{wd_line}\r\n\
    </Exec>\r\n\
  </Actions>\r\n\
</Task>\r\n"
    )
}

fn schtasks_cmd() -> Command {
    let mut cmd = Command::new("schtasks");
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Registers or removes an elevated Windows Scheduled Task via Task Scheduler 1.2 XML so
/// ShiftDNS starts reliably at logon (including on laptop battery and from paths with spaces)
/// without triggering UAC, while honoring the user's `start_minimized` setting.
pub fn set_windows_startup(enabled: bool) -> Result<(), String> {
    if enabled {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Could not resolve executable path: {e}"))?;
        let raw_exe = exe.to_string_lossy();
        let exe_path = raw_exe.strip_prefix(r"\\?\").unwrap_or(&raw_exe);
        let working_dir = exe
            .parent()
            .map(|p| {
                let s = p.to_string_lossy();
                s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
            })
            .unwrap_or_default();
        let user_id = current_windows_user_id()?;
        let xml = build_startup_task_xml(&user_id, exe_path, &working_dir);

        let xml_path =
            std::env::temp_dir().join(format!("shiftdns-startup-{}.xml", std::process::id()));
        fs::write(&xml_path, encode_utf16_le_bom(&xml))
            .map_err(|e| format!("Failed writing startup task definition: {e}"))?;

        let output = schtasks_cmd()
            .arg("/Create")
            .arg("/TN")
            .arg("ShiftDNS")
            .arg("/XML")
            .arg(&xml_path)
            .arg("/F")
            .output();
        let _ = fs::remove_file(&xml_path);

        let output = output.map_err(|e| format!("Failed to invoke schtasks: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!("Startup registration failed: {detail}"));
        }
    } else {
        let query = schtasks_cmd()
            .args(["/Query", "/TN", "ShiftDNS"])
            .output()
            .map_err(|e| format!("Failed to invoke schtasks: {e}"))?;
        if !query.status.success() {
            return Ok(());
        }

        let output = schtasks_cmd()
            .args(["/Delete", "/TN", "ShiftDNS", "/F"])
            .output()
            .map_err(|e| format!("Failed to invoke schtasks: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!("Failed to remove startup task: {detail}"));
        }
    }

    Ok(())
}
