use crate::config::DnsProfile;
use crate::icon_gen::generate_tray_ring_rgba;
use std::cell::Cell;
use std::collections::HashMap;
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub struct TrayController {
    pub tray_icon: TrayIcon,
    icon_active: Icon,
    icon_dhcp: Icon,
    last_custom_active: Cell<bool>,
}

pub fn format_tray_tooltip(
    profiles: &[DnsProfile],
    active_profile_id: Option<&str>,
    latencies: Option<&HashMap<String, Option<u128>>>,
    enable_doh: bool,
) -> String {
    let raw = match active_profile_id.and_then(|id| profiles.iter().find(|p| p.id == id)) {
        Some(p) => {
            let mut parts = vec![format!("ShiftDNS — {} ({})", p.name, p.primary_v4)];
            if let Some(Some(ms)) = latencies.and_then(|map| map.get(&p.id)) {
                parts.push(format!("{ms} ms"));
            }
            if enable_doh && !p.doh_template.is_empty() {
                parts.push("DoH".to_string());
            }
            parts.join(" · ")
        }
        None => "ShiftDNS — System Default (DHCP)".to_string(),
    };

    if raw.chars().count() > 120 {
        raw.chars().take(117).collect::<String>() + "..."
    } else {
        raw
    }
}

impl TrayController {
    pub fn new(
        profiles: &[DnsProfile],
        active_profile_id: Option<&str>,
        enable_doh: bool,
    ) -> Result<Self, String> {
        let icon_active = build_tray_icon(true);
        let icon_dhcp = build_tray_icon(false);
        let custom_active = active_profile_id.is_some();
        let initial_icon = if custom_active {
            icon_active.clone()
        } else {
            icon_dhcp.clone()
        };
        let tooltip = format_tray_tooltip(profiles, active_profile_id, None, enable_doh);

        // Do not attach a native Win32 menu so right-click renders our custom WebView2 tray popup.
        let tray_icon = TrayIconBuilder::new()
            .with_tooltip(&tooltip)
            .with_icon(initial_icon)
            .build()
            .map_err(|e| format!("Failed to create tray icon: {e}"))?;

        Ok(Self {
            tray_icon,
            icon_active,
            icon_dhcp,
            last_custom_active: Cell::new(custom_active),
        })
    }

    pub fn sync_state(
        &self,
        profiles: &[DnsProfile],
        active_profile_id: Option<&str>,
        latencies: Option<&HashMap<String, Option<u128>>>,
        enable_doh: bool,
    ) {
        let custom_active = active_profile_id.is_some();
        if custom_active != self.last_custom_active.get() {
            let icon = if custom_active {
                self.icon_active.clone()
            } else {
                self.icon_dhcp.clone()
            };
            let _ = self.tray_icon.set_icon(Some(icon));
            self.last_custom_active.set(custom_active);
        }

        let tooltip = format_tray_tooltip(profiles, active_profile_id, latencies, enable_doh);
        let _ = self.tray_icon.set_tooltip(Some(tooltip));
    }
}

/// Generates a crisp 32x32 minimal concentric ring RGBA tray icon.
pub fn build_tray_icon(custom_active: bool) -> Icon {
    let rgba = generate_tray_ring_rgba(32, custom_active);
    Icon::from_rgba(rgba, 32, 32).expect("Valid 32x32 concentric ring RGBA icon")
}
