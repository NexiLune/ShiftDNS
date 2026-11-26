#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod benchmark;
mod config;
mod dns;
mod icon_gen;
mod tray;
mod win32;

use benchmark::{DnsProbeResult, ResolveStatus, UpdateCheckOutcome};
use config::{
    is_valid_doh_url, is_valid_hostname, normalize_hostname, set_windows_startup,
    top_used_profiles, AppConfig, DnsProfile,
};
use dns::NetworkAdapter;
use icon_gen::generate_app_icon_rgba;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tray::TrayController;
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
use win32::{
    acquire_single_instance, compute_tray_logical_height, configure_window_dwm,
    ensure_tray_topmost, focus_window, open_release_url, position_tray_window,
    resolve_tray_anchor, MAIN_WINDOW_HEIGHT, MAIN_WINDOW_WIDTH, TRAY_MAX_HEIGHT, TRAY_MIN_HEIGHT,
    TRAY_POPUP_WIDTH,
};
use wry::{WebContext, WebView, WebViewBuilder};

#[cfg(target_os = "windows")]
use tao::platform::windows::WindowBuilderExtWindows;

static DNS_MUTATION_MUTEX: Mutex<()> = Mutex::new(());
static LATEST_OP_GEN: AtomicU64 = AtomicU64::new(0);

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const WINDOW_TITLE: &str = "ShiftDNS";
const TRAY_WINDOW_TITLE: &str = "ShiftDNS Tray";

enum UserEvent {
    TrayIcon(TrayIconEvent),
    Ipc(String),
    TrayIpc(String),
    AdaptersRefreshed {
        gen: u64,
        adapters: Vec<NetworkAdapter>,
        detected_active_id: Option<String>,
        trigger_probe: bool,
    },
    DnsApplyFinished {
        gen: u64,
        previous_active_id: Option<String>,
        target_profile_id: Option<String>,
        adapters: Vec<NetworkAdapter>,
        result: Result<(), String>,
    },
    StartupTaskFinished {
        enable: bool,
        result: Result<(), String>,
    },
    ProbeResult {
        gen: u64,
        result: DnsProbeResult,
        manual: bool,
    },
    UpdateCheckFinished {
        outcome: UpdateCheckOutcome,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum IpcMessage {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "activateProfile")]
    ActivateProfile { id: Option<String> },
    #[serde(rename = "saveProfile")]
    SaveProfile { profile: SaveProfilePayload },
    #[serde(rename = "deleteProfile")]
    DeleteProfile { id: String },
    #[serde(rename = "reorderProfiles")]
    ReorderProfiles {
        #[serde(rename = "orderedIds")]
        ordered_ids: Vec<String>,
    },
    #[serde(rename = "resetDefaults")]
    ResetDefaults,
    #[serde(rename = "probeActive")]
    ProbeActive,
    #[serde(rename = "cycleAdapter")]
    CycleAdapter,
    #[serde(rename = "toggleSetting")]
    ToggleSetting { key: String, value: bool },
    #[serde(rename = "setResolveDomain")]
    SetResolveDomain { domain: String },
    #[serde(rename = "checkUpdate")]
    CheckUpdate,
    #[serde(rename = "openReleaseUrl")]
    OpenReleaseUrl { url: String },
    #[serde(rename = "dragWindow")]
    DragWindow,
    #[serde(rename = "beginHide")]
    BeginHide,
    #[serde(rename = "hideWindow")]
    HideWindow,
    #[serde(rename = "minimizeWindow")]
    MinimizeWindow,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum TrayIpcMessage {
    #[serde(rename = "trayReady")]
    Ready,
    #[serde(rename = "hideTray")]
    Hide,
    #[serde(rename = "resizeTray")]
    Resize { height: f64 },
    #[serde(rename = "trayShowMain")]
    ShowMain,
    #[serde(rename = "trayActivate")]
    Activate { id: Option<String> },
    #[serde(rename = "trayQuit")]
    Quit,
}

#[derive(Debug, Deserialize)]
struct SaveProfilePayload {
    id: Option<String>,
    name: String,
    category: String,
    primary_v4: String,
    secondary_v4: String,
    primary_v6: String,
    secondary_v6: String,
    doh_template: String,
}

#[derive(Clone, Serialize)]
struct UpdateUiState {
    status: &'static str,
    #[serde(rename = "latestVersion")]
    latest_version: Option<String>,
    #[serde(rename = "downloadUrl")]
    download_url: Option<String>,
    message: Option<String>,
}

impl UpdateUiState {
    fn idle() -> Self {
        Self {
            status: "idle",
            latest_version: None,
            download_url: None,
            message: None,
        }
    }

    fn checking() -> Self {
        Self {
            status: "checking",
            latest_version: None,
            download_url: None,
            message: Some("Checking GitHub...".to_string()),
        }
    }
}

#[derive(Serialize)]
struct UiSyncPayload<'a> {
    #[serde(rename = "appVersion")]
    app_version: &'static str,
    profiles: &'a [DnsProfile],
    #[serde(rename = "activeProfileId")]
    active_profile_id: Option<&'a str>,
    #[serde(rename = "darkMode")]
    dark_mode: bool,
    #[serde(rename = "soundEffects")]
    sound_effects: bool,
    #[serde(rename = "enableIpv6")]
    enable_ipv6: bool,
    #[serde(rename = "enableDoh")]
    enable_doh: bool,
    #[serde(rename = "startMinimized")]
    start_minimized: bool,
    #[serde(rename = "launchAtStartup")]
    launch_at_startup: bool,
    #[serde(rename = "resolveCheckDomain")]
    resolve_check_domain: &'a str,
    #[serde(rename = "adapterLabel")]
    adapter_label: String,
    #[serde(rename = "activeLatency", skip_serializing_if = "Option::is_none")]
    active_latency: Option<Option<u128>>,
    #[serde(rename = "activeResolveStatus")]
    active_resolve_status: Option<&'static str>,
    #[serde(rename = "activeResolvedIp")]
    active_resolved_ip: Option<&'a str>,
    #[serde(rename = "probingActive")]
    probing_active: bool,
    #[serde(rename = "updateState")]
    update_state: &'a UpdateUiState,
    #[serde(rename = "statusMessage")]
    status_message: &'a str,
    #[serde(rename = "statusIsError")]
    status_is_error: bool,
}

#[derive(Serialize)]
struct TraySyncPayload<'a> {
    #[serde(rename = "darkMode")]
    dark_mode: bool,
    #[serde(rename = "soundEffects")]
    sound_effects: bool,
    #[serde(rename = "mainVisible")]
    main_visible: bool,
    #[serde(rename = "activeProfileId")]
    active_profile_id: Option<&'a str>,
    #[serde(rename = "topProfiles")]
    top_profiles: Vec<DnsProfile>,
}

struct ValidatedProfile {
    name: String,
    category: String,
    primary_v4: String,
    secondary_v4: String,
    primary_v6: String,
    secondary_v6: String,
    doh_template: String,
}

fn validate_profile_payload(payload: &SaveProfilePayload) -> Result<ValidatedProfile, &'static str> {
    let name = payload.name.trim().to_string();
    let category = if payload.category.trim().is_empty() {
        "Custom".to_string()
    } else {
        payload.category.trim().to_string()
    };
    let primary_v4 = payload.primary_v4.trim().to_string();
    let secondary_v4 = payload.secondary_v4.trim().to_string();
    let primary_v6 = payload.primary_v6.trim().to_string();
    let secondary_v6 = payload.secondary_v6.trim().to_string();
    let doh_template = payload.doh_template.trim().to_string();

    if name.is_empty() {
        return Err("Name is required.");
    }
    if primary_v4.parse::<Ipv4Addr>().is_err() {
        return Err("Primary IPv4 address is invalid.");
    }
    if !secondary_v4.is_empty() && secondary_v4.parse::<Ipv4Addr>().is_err() {
        return Err("Secondary IPv4 address is invalid.");
    }
    if !primary_v6.is_empty() && !matches!(primary_v6.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        return Err("Primary IPv6 address is invalid.");
    }
    if !secondary_v6.is_empty() && !matches!(secondary_v6.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        return Err("Secondary IPv6 address is invalid.");
    }
    if !is_valid_doh_url(&doh_template) {
        return Err("DoH template must be a valid https:// URL.");
    }

    Ok(ValidatedProfile {
        name,
        category,
        primary_v4,
        secondary_v4,
        primary_v6,
        secondary_v6,
        doh_template,
    })
}

fn eval_js_payload<T: Serialize>(webview: &WebView, fn_name: &str, payload: &T) {
    if let Ok(json) = serde_json::to_string(payload) {
        let script = format!("window.{fn_name} && window.{fn_name}({json});");
        let _ = webview.evaluate_script(&script);
    }
}

struct AppState {
    config: AppConfig,
    adapters: Vec<NetworkAdapter>,
    active_latency: Option<Option<u128>>,
    active_resolve_status: Option<ResolveStatus>,
    active_resolved_ip: Option<String>,
    probing_active: bool,
    probe_generation: u64,
    update_state: UpdateUiState,
    update_checking: bool,
    op_generation: u64,
    op_in_flight: bool,
    refresh_generation: u64,
    last_refresh_at: Option<Instant>,
    status_message: String,
    status_is_error: bool,
    status_revert_at: Option<Instant>,
    tray: Option<TrayController>,
    proxy: EventLoopProxy<UserEvent>,
    webview_ready: bool,
    tray_webview_ready: bool,
    last_tray_anchor: Option<(i32, i32)>,
    last_tray_logical_height: f64,
    tray_opened_at: Option<Instant>,
    tray_blur_closed_at: Option<Instant>,
    main_target_visible: bool,
    main_hide_deadline: Option<Instant>,
}

impl AppState {
    fn new(
        config: AppConfig,
        adapters: Vec<NetworkAdapter>,
        tray: Option<TrayController>,
        proxy: EventLoopProxy<UserEvent>,
        main_target_visible: bool,
        initial_tray_height: f64,
    ) -> Self {
        let status_message =
            format_active_dns_status(&config.profiles, config.active_profile_id.as_deref());
        Self {
            config,
            adapters,
            active_latency: None,
            active_resolve_status: None,
            active_resolved_ip: None,
            probing_active: false,
            probe_generation: 0,
            update_state: UpdateUiState::idle(),
            update_checking: false,
            op_generation: 0,
            op_in_flight: false,
            refresh_generation: 0,
            last_refresh_at: None,
            status_message,
            status_is_error: false,
            status_revert_at: None,
            tray,
            proxy,
            webview_ready: false,
            tray_webview_ready: false,
            last_tray_anchor: None,
            last_tray_logical_height: initial_tray_height,
            tray_opened_at: None,
            tray_blur_closed_at: None,
            main_target_visible,
            main_hide_deadline: None,
        }
    }

    fn clear_active_probe_state(&mut self) {
        self.active_latency = None;
        self.active_resolve_status = None;
        self.active_resolved_ip = None;
        self.probing_active = false;
    }

    fn set_transient_status(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.status_is_error = false;
        self.status_revert_at = Some(Instant::now() + Duration::from_secs(3));
    }

    fn set_error_status(&mut self, msg: impl Into<String>) {
        self.status_message = msg.into();
        self.status_is_error = true;
        self.status_revert_at = None;
    }

    fn save_config(&mut self) {
        if let Err(err) = self.config.save() {
            self.set_error_status(err);
        }
    }

    fn spawn_refresh_adapters(&mut self, trigger_probe: bool) {
        if self.op_in_flight {
            return;
        }
        if self
            .last_refresh_at
            .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
        {
            if trigger_probe && self.config.active_profile_id.is_some() && !self.probing_active {
                self.spawn_active_probe(false);
            }
            return;
        }
        self.last_refresh_at = Some(Instant::now());
        self.refresh_generation = self.refresh_generation.saturating_add(1);
        let gen = self.refresh_generation;

        let selected_adapter = self.config.selected_adapter.clone();
        let profiles = self.config.profiles.clone();
        let proxy = self.proxy.clone();

        std::thread::spawn(move || {
            let adapters = dns::list_adapters();
            let detected_active_id = if adapters.is_empty() {
                None
            } else {
                dns::detect_active_profile_id(&adapters, selected_adapter.as_deref(), &profiles)
            };
            let _ = proxy.send_event(UserEvent::AdaptersRefreshed {
                gen,
                adapters,
                detected_active_id,
                trigger_probe,
            });
        });
    }

    fn adapter_label(&self) -> String {
        if let Some(selected) = self.config.selected_adapter.as_deref() {
            if !dns::is_excluded_adapter(selected, "") {
                let online = self.adapters.is_empty()
                    || self.adapters.iter().any(|a| a.name == selected);
                return if online {
                    format!("{selected} · Admin")
                } else {
                    format!("{selected} (Offline) · Admin")
                };
            }
        }
        if let Some(first) = self
            .adapters
            .iter()
            .find(|a| !dns::is_excluded_adapter(&a.name, &a.description))
        {
            format!("Auto ({}) · Admin", first.name)
        } else {
            "Auto · Admin".to_string()
        }
    }

    fn active_latency_map(&self) -> HashMap<String, Option<u128>> {
        let mut map = HashMap::new();
        if let (Some(id), Some(rtt)) = (self.config.active_profile_id.as_ref(), self.active_latency) {
            map.insert(id.clone(), rtt);
        }
        map
    }

    fn sync_tray_icon(&self) {
        if let Some(ref tray) = self.tray {
            let map = self.active_latency_map();
            tray.sync_state(
                &self.config.profiles,
                self.config.active_profile_id.as_deref(),
                Some(&map),
                self.config.enable_doh,
            );
        }
    }

    fn tray_logical_height(&self, main_visible: bool) -> f64 {
        let preset_count = top_used_profiles(
            &self.config.profiles,
            &self.config.usage_counts,
            3,
            self.config.active_profile_id.as_deref(),
        )
        .len();
        compute_tray_logical_height(main_visible, preset_count)
            .clamp(TRAY_MIN_HEIGHT, TRAY_MAX_HEIGHT)
    }

    fn sync_tray_webview(&self, tray_webview: &WebView, main_visible: bool) {
        if !self.tray_webview_ready {
            return;
        }
        let top_profiles = top_used_profiles(
            &self.config.profiles,
            &self.config.usage_counts,
            3,
            self.config.active_profile_id.as_deref(),
        );
        let payload = TraySyncPayload {
            dark_mode: self.config.dark_mode,
            sound_effects: self.config.sound_effects,
            main_visible,
            active_profile_id: self.config.active_profile_id.as_deref(),
            top_profiles,
        };
        eval_js_payload(tray_webview, "__shiftdnsTraySync", &payload);
    }

    fn sync_webview(&self, webview: &WebView) {
        if !self.webview_ready {
            return;
        }
        let payload = UiSyncPayload {
            app_version: APP_VERSION,
            profiles: &self.config.profiles,
            active_profile_id: self.config.active_profile_id.as_deref(),
            dark_mode: self.config.dark_mode,
            sound_effects: self.config.sound_effects,
            enable_ipv6: self.config.enable_ipv6,
            enable_doh: self.config.enable_doh,
            start_minimized: self.config.start_minimized,
            launch_at_startup: self.config.launch_at_startup,
            resolve_check_domain: &self.config.resolve_check_domain,
            adapter_label: self.adapter_label(),
            active_latency: self.active_latency,
            active_resolve_status: self.active_resolve_status.map(|s| s.as_str()),
            active_resolved_ip: self.active_resolved_ip.as_deref(),
            probing_active: self.probing_active,
            update_state: &self.update_state,
            status_message: &self.status_message,
            status_is_error: self.status_is_error,
        };
        eval_js_payload(webview, "__shiftdnsSync", &payload);
    }

    fn sync_all_ui(&self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        self.sync_webview(webview);
        self.sync_tray_webview(tray_webview, main_visible);
    }

    fn spawn_active_probe(&mut self, manual: bool) {
        let Some(active_id) = self.config.active_profile_id.as_deref() else {
            self.clear_active_probe_state();
            return;
        };
        let Some(profile) = self.config.profiles.iter().find(|p| p.id == active_id) else {
            return;
        };
        let target_ip = if !profile.primary_v4.is_empty() {
            profile.primary_v4.clone()
        } else {
            profile.primary_v6.clone()
        };
        if target_ip.is_empty() {
            return;
        }

        self.probe_generation = self.probe_generation.saturating_add(1);
        let gen = self.probe_generation;
        self.probing_active = true;

        let domain = self.config.resolve_check_domain.clone();
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let result = benchmark::probe_dns_resolve(&target_ip, &domain);
            let _ = proxy.send_event(UserEvent::ProbeResult {
                gen,
                result,
                manual,
            });
        });
    }

    fn set_resolve_domain(&mut self, domain: &str, webview: &WebView) {
        if !is_valid_hostname(domain) {
            self.set_error_status("Enter a valid domain (e.g. cloudflare.com)");
            self.sync_webview(webview);
            return;
        }
        let clean = normalize_hostname(domain);
        if clean == self.config.resolve_check_domain {
            if self.config.active_profile_id.is_some() {
                self.spawn_active_probe(true);
            }
            self.sync_webview(webview);
            return;
        }
        self.config.resolve_check_domain = clean.clone();
        self.clear_active_probe_state();
        self.save_config();
        self.set_transient_status(format!("Resolve check: {clean}"));
        if self.config.active_profile_id.is_some() {
            self.spawn_active_probe(false);
        }
        self.sync_webview(webview);
    }

    fn check_for_updates(&mut self, webview: &WebView) {
        if self.update_checking {
            return;
        }
        self.update_checking = true;
        self.update_state = UpdateUiState::checking();
        self.sync_webview(webview);

        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let outcome = benchmark::check_github_update(APP_VERSION);
            let _ = proxy.send_event(UserEvent::UpdateCheckFinished { outcome });
        });
    }

    fn cycle_adapter(&mut self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        if self.op_in_flight {
            return;
        }
        if self.adapters.is_empty() {
            self.adapters = dns::list_adapters();
        }
        let next = dns::cycle_selected_adapter(
            self.config.selected_adapter.as_deref(),
            &self.adapters,
        );
        self.config.selected_adapter = next.clone();
        let next_active_id = if self.adapters.is_empty() {
            None
        } else {
            dns::detect_active_profile_id(
                &self.adapters,
                self.config.selected_adapter.as_deref(),
                &self.config.profiles,
            )
        };
        if next_active_id != self.config.active_profile_id {
            self.config.active_profile_id = next_active_id;
            self.clear_active_probe_state();
            self.probe_generation = self.probe_generation.saturating_add(1);
        }
        self.save_config();
        self.sync_tray_icon();

        match &next {
            Some(name) => self.set_transient_status(format!("Adapter: {name}")),
            None => {
                let primary = self
                    .adapters
                    .iter()
                    .find(|a| !dns::is_excluded_adapter(&a.name, &a.description))
                    .map(|a| a.name.as_str());
                if let Some(name) = primary {
                    self.set_transient_status(format!("Adapter: Auto ({name})"));
                } else {
                    self.set_transient_status("Adapter: Auto");
                }
            }
        }

        if self.config.active_profile_id.is_some()
            && self.active_latency.is_none()
            && !self.probing_active
        {
            self.spawn_active_probe(false);
        }
        self.sync_all_ui(webview, tray_webview, main_visible);
        self.last_refresh_at = None;
        self.spawn_refresh_adapters(true);
    }

    fn begin_dns_op(
        &mut self,
        active_profile_id: Option<String>,
        probing_active: bool,
        status_message: String,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) -> u64 {
        self.op_generation = self.op_generation.saturating_add(1);
        let gen = self.op_generation;
        LATEST_OP_GEN.store(gen, Ordering::Release);
        self.op_in_flight = true;
        self.probe_generation = self.probe_generation.saturating_add(1);

        // Optimistic immediate UI update so FLIP animations & checkmark transitions run at 60fps
        self.config.active_profile_id = active_profile_id;
        self.clear_active_probe_state();
        self.probing_active = probing_active;
        self.status_revert_at = None;
        self.status_message = status_message;
        self.status_is_error = false;
        self.sync_tray_icon();
        self.sync_all_ui(webview, tray_webview, main_visible);
        gen
    }

    fn activate_profile(
        &mut self,
        profile_id: &str,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) {
        let Some(profile) = self.config.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let previous_active_id = self.config.active_profile_id.clone();

        let status = format_active_dns_status(&self.config.profiles, Some(&profile.id));
        let gen = self.begin_dns_op(
            Some(profile.id.clone()),
            true,
            status,
            webview,
            tray_webview,
            main_visible,
        );

        let cached_adapters = self.adapters.clone();
        let selected_adapter = self.config.selected_adapter.clone();
        let enable_ipv6 = self.config.enable_ipv6;
        let enable_doh = self.config.enable_doh;
        let proxy = self.proxy.clone();
        let target_id = profile.id.clone();

        std::thread::spawn(move || {
            let _guard = DNS_MUTATION_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if LATEST_OP_GEN.load(Ordering::Acquire) != gen {
                return;
            }
            let mut adapters = if cached_adapters.is_empty() {
                dns::list_adapters()
            } else {
                cached_adapters
            };
            let result = dns::apply_profile(
                &adapters,
                selected_adapter.as_deref(),
                &profile,
                enable_ipv6,
                enable_doh,
            );
            if result.is_ok() {
                let mut applied_dns = vec![profile.primary_v4.clone()];
                if !profile.secondary_v4.trim().is_empty() {
                    applied_dns.push(profile.secondary_v4.clone());
                }
                for a in &mut adapters {
                    if selected_adapter
                        .as_deref()
                        .map_or(true, |sel| sel == a.name.as_str())
                    {
                        a.current_dns = applied_dns.clone();
                        a.is_dhcp = false;
                    }
                }
            } else {
                let refreshed = dns::list_adapters();
                if !refreshed.is_empty() {
                    adapters = refreshed;
                }
            }
            let _ = proxy.send_event(UserEvent::DnsApplyFinished {
                gen,
                previous_active_id,
                target_profile_id: Some(target_id),
                adapters,
                result,
            });
        });
    }

    fn activate_dhcp(&mut self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        let previous_active_id = self.config.active_profile_id.clone();
        let gen = self.begin_dns_op(
            None,
            false,
            "System Default (DHCP)".to_string(),
            webview,
            tray_webview,
            main_visible,
        );

        let cached_adapters = self.adapters.clone();
        let selected_adapter = self.config.selected_adapter.clone();
        let proxy = self.proxy.clone();

        std::thread::spawn(move || {
            let _guard = DNS_MUTATION_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if LATEST_OP_GEN.load(Ordering::Acquire) != gen {
                return;
            }
            let mut adapters = if cached_adapters.is_empty() {
                dns::list_adapters()
            } else {
                cached_adapters
            };
            let result = dns::reset_to_dhcp(&adapters, selected_adapter.as_deref());
            if result.is_ok() {
                for a in &mut adapters {
                    if selected_adapter
                        .as_deref()
                        .map_or(true, |sel| sel == a.name.as_str())
                    {
                        a.current_dns.clear();
                        a.is_dhcp = true;
                    }
                }
            } else {
                let refreshed = dns::list_adapters();
                if !refreshed.is_empty() {
                    adapters = refreshed;
                }
            }
            let _ = proxy.send_event(UserEvent::DnsApplyFinished {
                gen,
                previous_active_id,
                target_profile_id: None,
                adapters,
                result,
            });
        });
    }

    fn save_profile(
        &mut self,
        payload: SaveProfilePayload,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) {
        let validated = match validate_profile_payload(&payload) {
            Ok(v) => v,
            Err(err) => {
                self.set_error_status(err);
                self.sync_webview(webview);
                return;
            }
        };

        if let Some(editing_id) = payload.id.filter(|id| !id.is_empty()) {
            let mut updated = false;
            if let Some(target) = self.config.profiles.iter_mut().find(|p| p.id == editing_id) {
                target.name = validated.name.clone();
                target.category = validated.category;
                target.primary_v4 = validated.primary_v4;
                target.secondary_v4 = validated.secondary_v4;
                target.primary_v6 = validated.primary_v6;
                target.secondary_v6 = validated.secondary_v6;
                target.doh_template = validated.doh_template;
                updated = true;
            }
            self.save_config();
            if updated && self.config.active_profile_id.as_deref() == Some(editing_id.as_str()) {
                self.activate_profile(&editing_id, webview, tray_webview, main_visible);
                return;
            }
            self.sync_tray_icon();
            self.set_transient_status(format!("Updated {}", validated.name));
            self.sync_all_ui(webview, tray_webview, main_visible);
            return;
        }

        let slug: String = validated
            .name
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let clean_slug = slug.trim_matches('-');
        let base_id = format!(
            "custom-{}",
            if clean_slug.is_empty() {
                "server"
            } else {
                clean_slug
            }
        );
        let mut id = base_id.clone();
        let mut suffix = 1usize;
        while self.config.profiles.iter().any(|p| p.id == id) {
            id = format!("{base_id}-{suffix}");
            suffix += 1;
        }

        self.config.profiles.push(DnsProfile {
            id,
            name: validated.name.clone(),
            category: validated.category,
            primary_v4: validated.primary_v4,
            secondary_v4: validated.secondary_v4,
            primary_v6: validated.primary_v6,
            secondary_v6: validated.secondary_v6,
            doh_template: validated.doh_template,
            is_custom: true,
        });
        self.save_config();
        self.sync_tray_icon();
        self.set_transient_status(format!("Added {}", validated.name));
        self.sync_all_ui(webview, tray_webview, main_visible);
    }

    fn delete_profile(
        &mut self,
        id: &str,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) {
        let removed_name = self
            .config
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.clone());
        let was_active = self.config.active_profile_id.as_deref() == Some(id);
        self.config.profiles.retain(|p| p.id != id);
        if was_active {
            self.save_config();
            self.activate_dhcp(webview, tray_webview, main_visible);
            return;
        }
        self.save_config();
        self.sync_tray_icon();
        self.set_transient_status(
            removed_name
                .map(|n| format!("Removed {n}"))
                .unwrap_or_else(|| "Removed DNS profile".to_string()),
        );
        self.sync_all_ui(webview, tray_webview, main_visible);
    }

    fn reorder_profiles(
        &mut self,
        ordered_ids: Vec<String>,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) {
        let mut by_id: HashMap<String, DnsProfile> = self
            .config
            .profiles
            .drain(..)
            .map(|p| (p.id.clone(), p))
            .collect();
        let mut reordered = Vec::with_capacity(by_id.len());
        for id in ordered_ids {
            if let Some(p) = by_id.remove(&id) {
                reordered.push(p);
            }
        }
        for (_, p) in by_id {
            reordered.push(p);
        }
        self.config.profiles = reordered;
        self.save_config();
        self.sync_tray_icon();
        self.set_transient_status("Updated order");
        self.sync_all_ui(webview, tray_webview, main_visible);
    }

    fn reset_defaults(&mut self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        let custom_only: Vec<DnsProfile> = self
            .config
            .profiles
            .iter()
            .filter(|p| p.is_custom)
            .cloned()
            .collect();
        let mut restored = config::default_profiles();
        restored.extend(custom_only);
        self.config.profiles = restored;
        let dropped_active = self
            .config
            .active_profile_id
            .as_ref()
            .is_some_and(|active_id| !self.config.profiles.iter().any(|p| &p.id == active_id));
        if dropped_active {
            self.save_config();
            self.activate_dhcp(webview, tray_webview, main_visible);
            return;
        }
        self.save_config();
        self.sync_tray_icon();
        self.set_transient_status("Restored default DNS list");
        self.sync_all_ui(webview, tray_webview, main_visible);
    }

    fn toggle_setting(
        &mut self,
        key: &str,
        value: bool,
        webview: &WebView,
        tray_webview: &WebView,
        main_visible: bool,
    ) {
        match key {
            "darkMode" => {
                self.config.dark_mode = value;
                self.save_config();
            }
            "soundEffects" => {
                self.config.sound_effects = value;
                self.save_config();
                self.set_transient_status(if value {
                    "UI sounds enabled"
                } else {
                    "UI sounds disabled"
                });
            }
            "enableIpv6" => {
                self.config.enable_ipv6 = value;
                self.save_config();
                self.set_transient_status(if value {
                    "IPv6 DNS enabled"
                } else {
                    "IPv6 DNS disabled"
                });
            }
            "enableDoh" => {
                self.config.enable_doh = value;
                self.save_config();
                self.sync_tray_icon();
                self.set_transient_status(if value {
                    "Windows 11 DoH enabled"
                } else {
                    "Windows 11 DoH disabled"
                });
            }
            "startMinimized" => {
                self.config.start_minimized = value;
                self.save_config();
                self.set_transient_status(if value {
                    "Start minimized enabled"
                } else {
                    "Start minimized disabled"
                });
            }
            "launchAtStartup" => {
                self.config.launch_at_startup = value;
                self.status_revert_at = None;
                self.status_message = "Updating startup task...".to_string();
                self.status_is_error = false;
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let result = set_windows_startup(value);
                    let _ = proxy.send_event(UserEvent::StartupTaskFinished {
                        enable: value,
                        result,
                    });
                });
            }
            _ => {}
        }
        self.sync_all_ui(webview, tray_webview, main_visible);
    }

    fn show_window(&mut self, window: &Window, webview: &WebView, tray_webview: &WebView) {
        self.main_target_visible = true;
        self.main_hide_deadline = None;
        configure_window_dwm(window, true, self.config.dark_mode);
        if self.webview_ready {
            let _ = webview
                .evaluate_script("window.__shiftdnsPrepareShow && window.__shiftdnsPrepareShow();");
        }
        window.set_visible(true);
        window.set_minimized(false);
        window.set_focus();
        if self.webview_ready {
            let _ = webview
                .evaluate_script("window.__shiftdnsAnimateShow && window.__shiftdnsAnimateShow();");
        }
        self.spawn_refresh_adapters(true);
        self.sync_all_ui(webview, tray_webview, true);
    }

    fn request_hide_window(&mut self, window: &Window, webview: &WebView, tray_webview: &WebView) {
        self.main_target_visible = false;
        if self.webview_ready && window.is_visible() {
            self.main_hide_deadline = Some(Instant::now() + Duration::from_millis(240));
            let _ = webview
                .evaluate_script("window.__shiftdnsAnimateHide && window.__shiftdnsAnimateHide();");
        } else {
            self.finalize_hide_window(window, tray_webview);
        }
    }

    fn finalize_hide_window(&mut self, window: &Window, tray_webview: &WebView) {
        self.main_hide_deadline = None;
        if self.main_target_visible {
            return;
        }
        window.set_visible(false);
        self.sync_tray_webview(tray_webview, false);
    }

    fn open_tray_popup(
        &mut self,
        window: &Window,
        tray_window: &Window,
        tray_webview: &WebView,
        click_x: i32,
        click_y: i32,
    ) {
        let main_visible = is_main_effectively_visible(window);
        let exact_h = self.tray_logical_height(main_visible);
        self.last_tray_logical_height = exact_h;
        self.sync_tray_webview(tray_webview, main_visible);
        let (ax, ay) = resolve_tray_anchor(click_x, click_y);
        self.last_tray_anchor = Some((ax, ay));
        position_tray_window(tray_window, ax, ay, exact_h);
        configure_window_dwm(tray_window, true, self.config.dark_mode);
        ensure_tray_topmost(tray_window);
        self.tray_opened_at = Some(Instant::now());
        self.tray_blur_closed_at = None;
        tray_window.set_visible(true);
        tray_window.set_focus();
        focus_window(tray_window);
        ensure_tray_topmost(tray_window);
        let _ = tray_webview
            .evaluate_script("window.__shiftdnsTrayOpen && window.__shiftdnsTrayOpen();");
    }

    fn close_tray_popup(&mut self, tray_window: &Window, tray_webview: &WebView, by_blur: bool) {
        self.tray_opened_at = None;
        self.tray_blur_closed_at = if by_blur {
            Some(Instant::now())
        } else {
            None
        };
        if self.tray_webview_ready {
            let _ = tray_webview
                .evaluate_script("window.__shiftdnsTrayClose && window.__shiftdnsTrayClose();");
        }
        tray_window.set_visible(false);
    }

    fn toggle_window(&mut self, window: &Window, webview: &WebView, tray_webview: &WebView) {
        if self.main_target_visible && is_main_effectively_visible(window) {
            self.request_hide_window(window, webview, tray_webview);
        } else {
            self.show_window(window, webview, tray_webview);
        }
    }
}

fn is_main_effectively_visible(window: &Window) -> bool {
    window.is_visible() && !window.is_minimized()
}

fn format_active_dns_status(profiles: &[DnsProfile], active_id: Option<&str>) -> String {
    match active_id.and_then(|id| profiles.iter().find(|p| p.id == id)) {
        Some(p) => format!("Active: {} ({})", p.name, p.primary_v4),
        None => "System Default (DHCP)".to_string(),
    }
}

fn main() {
    let _instance_guard = match acquire_single_instance(WINDOW_TITLE) {
        Some(guard) => guard,
        None => return,
    };

    let start_minimized_arg = std::env::args().any(|a| a == "--minimized" || a == "-m");
    let config = AppConfig::load();
    let adapters = Vec::new();

    let hide_on_boot = start_minimized_arg || config.start_minimized;

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::TrayIcon(event));
    }));

    let window_icon = WindowIcon::from_rgba(generate_app_icon_rgba(32), 32, 32).ok();

    let mut main_builder = WindowBuilder::new()
        .with_title(WINDOW_TITLE)
        .with_inner_size(LogicalSize::new(MAIN_WINDOW_WIDTH, MAIN_WINDOW_HEIGHT))
        .with_decorations(false)
        .with_resizable(false)
        .with_visible(!hide_on_boot)
        .with_window_icon(window_icon);

    #[cfg(target_os = "windows")]
    {
        main_builder = main_builder.with_undecorated_shadow(true);
    }

    let window = main_builder
        .build(&event_loop)
        .expect("Failed to create ShiftDNS window");
    let main_window_id = window.id();
    configure_window_dwm(&window, true, config.dark_mode);

    let initial_tray_presets = top_used_profiles(
        &config.profiles,
        &config.usage_counts,
        3,
        config.active_profile_id.as_deref(),
    )
    .len();
    let initial_tray_height = compute_tray_logical_height(!hide_on_boot, initial_tray_presets);

    let mut tray_builder = WindowBuilder::new()
        .with_title(TRAY_WINDOW_TITLE)
        .with_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, initial_tray_height))
        .with_decorations(false)
        .with_resizable(false)
        .with_always_on_top(true)
        .with_visible(false);

    #[cfg(target_os = "windows")]
    {
        tray_builder = tray_builder
            .with_skip_taskbar(true)
            .with_undecorated_shadow(true);
    }

    let tray_window = tray_builder
        .build(&event_loop)
        .expect("Failed to create ShiftDNS tray popup window");
    let tray_window_id = tray_window.id();
    configure_window_dwm(&tray_window, true, config.dark_mode);
    ensure_tray_topmost(&tray_window);

    let mut web_context = WebContext::new(Some(config::webview_data_dir()));
    let bg_color = if config.dark_mode {
        (14, 16, 18, 255)
    } else {
        (255, 255, 255, 255)
    };
    let tray_bg_color = bg_color;

    let ipc_proxy = proxy.clone();
    let webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_html(include_str!("ui.html"))
        .with_background_color(bg_color)
        .with_devtools(cfg!(debug_assertions))
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let _ = ipc_proxy.send_event(UserEvent::Ipc(req.body().clone()));
        })
        .build(&window)
        .expect("Failed to initialize main WebView2");

    let tray_ipc_proxy = proxy.clone();
    let tray_webview = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_html(include_str!("tray.html"))
        .with_background_color(tray_bg_color)
        .with_devtools(cfg!(debug_assertions))
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let _ = tray_ipc_proxy.send_event(UserEvent::TrayIpc(req.body().clone()));
        })
        .build(&tray_window)
        .expect("Failed to initialize tray WebView2");

    let tray = TrayController::new(
        &config.profiles,
        config.active_profile_id.as_deref(),
        config.enable_doh,
    )
    .ok();

    let mut state = AppState::new(
        config,
        adapters,
        tray,
        proxy,
        !hide_on_boot,
        initial_tray_height,
    );
    state.spawn_refresh_adapters(!hide_on_boot);

    event_loop.run(move |event, _, control_flow| {
        match event {
            Event::NewEvents(StartCause::ResumeTimeReached { .. })
            | Event::MainEventsCleared => {
                if let Some(deadline) = state.main_hide_deadline {
                    if Instant::now() >= deadline {
                        state.finalize_hide_window(&window, &tray_webview);
                    }
                }
                if let Some(deadline) = state.status_revert_at {
                    if Instant::now() >= deadline {
                        state.status_revert_at = None;
                        state.status_message = format_active_dns_status(
                            &state.config.profiles,
                            state.config.active_profile_id.as_deref(),
                        );
                        state.status_is_error = false;
                        state.sync_webview(&webview);
                    }
                }
            }
            Event::WindowEvent {
                window_id, event, ..
            } => {
                if window_id == main_window_id {
                    match event {
                        WindowEvent::CloseRequested => {
                            state.request_hide_window(&window, &webview, &tray_webview);
                        }
                        WindowEvent::Focused(true) => {
                            if window.is_visible() {
                                if !state.main_target_visible && state.main_hide_deadline.is_none() {
                                    state.show_window(&window, &webview, &tray_webview);
                                } else if state.main_target_visible {
                                    state.spawn_refresh_adapters(true);
                                    state.sync_tray_webview(
                                        &tray_webview,
                                        is_main_effectively_visible(&window),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                } else if window_id == tray_window_id {
                    match event {
                        WindowEvent::CloseRequested => {
                            state.close_tray_popup(&tray_window, &tray_webview, false);
                        }
                        WindowEvent::Focused(false) => {
                            let within_open_debounce = state
                                .tray_opened_at
                                .is_some_and(|t| t.elapsed() < Duration::from_millis(150));
                            if !within_open_debounce && tray_window.is_visible() {
                                state.close_tray_popup(&tray_window, &tray_webview, true);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::UserEvent(user_event) => match user_event {
                UserEvent::TrayIcon(tray_event) => match tray_event {
                    TrayIconEvent::Click {
                        button,
                        button_state: MouseButtonState::Up,
                        position,
                        ..
                    } => match button {
                        MouseButton::Left => {
                            state.close_tray_popup(&tray_window, &tray_webview, false);
                            state.toggle_window(&window, &webview, &tray_webview);
                        }
                        MouseButton::Right => {
                            let just_closed_by_blur = state
                                .tray_blur_closed_at
                                .take()
                                .is_some_and(|t| t.elapsed() < Duration::from_millis(250));
                            if tray_window.is_visible() || just_closed_by_blur {
                                state.close_tray_popup(&tray_window, &tray_webview, false);
                            } else {
                                state.open_tray_popup(
                                    &window,
                                    &tray_window,
                                    &tray_webview,
                                    position.x.round() as i32,
                                    position.y.round() as i32,
                                );
                            }
                        }
                        _ => {}
                    },
                    TrayIconEvent::Click { .. } | TrayIconEvent::DoubleClick { .. } => {}
                    _ => {}
                },
                UserEvent::Ipc(raw) => {
                    let main_visible = is_main_effectively_visible(&window);
                    if let Ok(msg) = serde_json::from_str::<IpcMessage>(&raw) {
                        match msg {
                            IpcMessage::Ready => {
                                state.webview_ready = true;
                                if !state.main_target_visible {
                                    let _ = webview.evaluate_script(
                                        "window.__shiftdnsPrepareShow && window.__shiftdnsPrepareShow();",
                                    );
                                }
                                state.sync_webview(&webview);
                            }
                            IpcMessage::ActivateProfile { id } => match id {
                                Some(profile_id) => state.activate_profile(
                                    &profile_id,
                                    &webview,
                                    &tray_webview,
                                    main_visible,
                                ),
                                None => state.activate_dhcp(&webview, &tray_webview, main_visible),
                            },
                            IpcMessage::SaveProfile { profile } => {
                                state.save_profile(profile, &webview, &tray_webview, main_visible);
                            }
                            IpcMessage::DeleteProfile { id } => {
                                state.delete_profile(&id, &webview, &tray_webview, main_visible);
                            }
                            IpcMessage::ReorderProfiles { ordered_ids } => {
                                state.reorder_profiles(
                                    ordered_ids,
                                    &webview,
                                    &tray_webview,
                                    main_visible,
                                );
                            }
                            IpcMessage::ResetDefaults => {
                                state.reset_defaults(&webview, &tray_webview, main_visible);
                            }
                            IpcMessage::ProbeActive => {
                                state.spawn_active_probe(true);
                                state.sync_webview(&webview);
                            }
                            IpcMessage::CycleAdapter => {
                                state.cycle_adapter(&webview, &tray_webview, main_visible);
                            }
                            IpcMessage::ToggleSetting { key, value } => {
                                state.toggle_setting(
                                    &key,
                                    value,
                                    &webview,
                                    &tray_webview,
                                    main_visible,
                                );
                                if key == "darkMode" {
                                    configure_window_dwm(&window, true, state.config.dark_mode);
                                    configure_window_dwm(&tray_window, true, state.config.dark_mode);
                                }
                            }
                            IpcMessage::SetResolveDomain { domain } => {
                                state.set_resolve_domain(&domain, &webview);
                            }
                            IpcMessage::CheckUpdate => {
                                state.check_for_updates(&webview);
                            }
                            IpcMessage::OpenReleaseUrl { url } => {
                                match open_release_url(&url) {
                                    Ok(()) => state
                                        .set_transient_status("Opening ShiftDNS-Setup.exe download..."),
                                    Err(err) => state.set_error_status(err),
                                }
                                state.sync_webview(&webview);
                            }
                            IpcMessage::DragWindow => {
                                let _ = window.drag_window();
                            }
                            IpcMessage::BeginHide => {
                                state.main_target_visible = false;
                                if window.is_visible() && state.main_hide_deadline.is_none() {
                                    state.main_hide_deadline =
                                        Some(Instant::now() + Duration::from_millis(240));
                                }
                            }
                            IpcMessage::HideWindow => {
                                state.main_target_visible = false;
                                state.finalize_hide_window(&window, &tray_webview);
                            }
                            IpcMessage::MinimizeWindow => {
                                state.main_hide_deadline = None;
                                window.set_minimized(true);
                                state.sync_tray_webview(&tray_webview, false);
                            }
                        }
                    }
                }
                UserEvent::TrayIpc(raw) => {
                    if let Ok(msg) = serde_json::from_str::<TrayIpcMessage>(&raw) {
                        match msg {
                            TrayIpcMessage::Ready => {
                                state.tray_webview_ready = true;
                                let main_visible = is_main_effectively_visible(&window);
                                let exact_h = state.tray_logical_height(main_visible);
                                state.last_tray_logical_height = exact_h;
                                tray_window
                                    .set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, exact_h));
                                state.sync_tray_webview(&tray_webview, main_visible);
                            }
                            TrayIpcMessage::Hide => {
                                state.close_tray_popup(&tray_window, &tray_webview, false);
                            }
                            TrayIpcMessage::Resize { height } => {
                                let clamped = height.clamp(TRAY_MIN_HEIGHT, TRAY_MAX_HEIGHT);
                                if (clamped - state.last_tray_logical_height).abs() >= 1.0 {
                                    state.last_tray_logical_height = clamped;
                                    tray_window
                                        .set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, clamped));
                                    if tray_window.is_visible() {
                                        if let Some((ax, ay)) = state.last_tray_anchor {
                                            position_tray_window(&tray_window, ax, ay, clamped);
                                            ensure_tray_topmost(&tray_window);
                                        }
                                    }
                                }
                            }
                            TrayIpcMessage::ShowMain => {
                                state.close_tray_popup(&tray_window, &tray_webview, false);
                                state.show_window(&window, &webview, &tray_webview);
                            }
                            TrayIpcMessage::Activate { id } => {
                                state.close_tray_popup(&tray_window, &tray_webview, false);
                                let main_visible = is_main_effectively_visible(&window);
                                match id {
                                    Some(profile_id) => state.activate_profile(
                                        &profile_id,
                                        &webview,
                                        &tray_webview,
                                        main_visible,
                                    ),
                                    None => {
                                        state.activate_dhcp(&webview, &tray_webview, main_visible)
                                    }
                                }
                            }
                            TrayIpcMessage::Quit => {
                                state.close_tray_popup(&tray_window, &tray_webview, false);
                                state.tray = None;
                                *control_flow = ControlFlow::Exit;
                                return;
                            }
                        }
                    }
                }
                UserEvent::AdaptersRefreshed {
                    gen,
                    adapters,
                    detected_active_id,
                    trigger_probe,
                } => {
                    if !state.op_in_flight && gen == state.refresh_generation {
                        let target_present = match state.config.selected_adapter.as_deref() {
                            Some(sel) => adapters.iter().any(|a| a.name == sel),
                            None => !adapters.is_empty(),
                        };
                        state.adapters = adapters;
                        if target_present && detected_active_id != state.config.active_profile_id {
                            state.config.active_profile_id = detected_active_id;
                            state.clear_active_probe_state();
                            state.save_config();
                            if state.status_revert_at.is_none() {
                                state.status_message = format_active_dns_status(
                                    &state.config.profiles,
                                    state.config.active_profile_id.as_deref(),
                                );
                            }
                            state.sync_tray_icon();
                        }
                        if trigger_probe
                            && state.config.active_profile_id.is_some()
                            && !state.probing_active
                        {
                            state.spawn_active_probe(false);
                        }
                        state.sync_all_ui(
                            &webview,
                            &tray_webview,
                            is_main_effectively_visible(&window),
                        );
                    }
                }
                UserEvent::DnsApplyFinished {
                    gen,
                    previous_active_id,
                    target_profile_id,
                    adapters,
                    result,
                } => {
                    if gen == state.op_generation {
                        state.op_in_flight = false;
                        if !adapters.is_empty() {
                            state.adapters = adapters;
                        }
                        match result {
                            Ok(()) => {
                                state.config.active_profile_id = target_profile_id.clone();
                                if let Some(ref id) = target_profile_id {
                                    let count =
                                        state.config.usage_counts.entry(id.clone()).or_insert(0);
                                    *count = count.saturating_add(1);
                                }
                                state.save_config();
                                state.sync_tray_icon();
                                if target_profile_id.is_some() {
                                    state.spawn_active_probe(false);
                                } else {
                                    state.clear_active_probe_state();
                                }
                            }
                            Err(err) => {
                                state.config.active_profile_id = if !state.adapters.is_empty() {
                                    dns::detect_active_profile_id(
                                        &state.adapters,
                                        state.config.selected_adapter.as_deref(),
                                        &state.config.profiles,
                                    )
                                } else {
                                    previous_active_id
                                };
                                state.save_config();
                                state.clear_active_probe_state();
                                state.sync_tray_icon();
                                state.set_error_status(err);
                            }
                        }
                        state.sync_all_ui(
                            &webview,
                            &tray_webview,
                            is_main_effectively_visible(&window),
                        );
                    }
                }
                UserEvent::StartupTaskFinished { enable, result } => {
                    match result {
                        Ok(()) => {
                            state.config.launch_at_startup = enable;
                            state.save_config();
                            if !state.status_is_error {
                                state.set_transient_status(if enable {
                                    "Startup task enabled"
                                } else {
                                    "Startup task disabled"
                                });
                            }
                        }
                        Err(err) => {
                            state.config.launch_at_startup = !enable;
                            state.set_error_status(err);
                        }
                    }
                    state.sync_all_ui(
                        &webview,
                        &tray_webview,
                        is_main_effectively_visible(&window),
                    );
                }
                UserEvent::ProbeResult {
                    gen,
                    result,
                    manual,
                } => {
                    if gen == state.probe_generation {
                        state.probing_active = false;
                        state.active_latency = Some(result.rtt_ms);
                        state.active_resolve_status = Some(result.status);
                        state.active_resolved_ip = result.resolved_ip.clone();
                        let domain = state.config.resolve_check_domain.clone();
                        match result.status {
                            ResolveStatus::Blocked => {
                                let ip = result.resolved_ip.as_deref().unwrap_or("0.0.0.0");
                                state.set_transient_status(format!("Blocked: {domain} → {ip}"));
                            }
                            ResolveStatus::Ok if manual => {
                                if let (Some(ip), Some(ms)) = (result.resolved_ip.as_deref(), result.rtt_ms) {
                                    state.set_transient_status(format!("{domain} → {ip} ({ms} ms)"));
                                }
                            }
                            ResolveStatus::NoAnswer if manual => {
                                state.set_transient_status(format!("No A record for {domain}"));
                            }
                            ResolveStatus::Timeout if manual => {
                                state.set_transient_status(format!("Timeout resolving {domain}"));
                            }
                            _ => {}
                        }
                        state.sync_tray_icon();
                        state.sync_webview(&webview);
                    }
                }
                UserEvent::UpdateCheckFinished { outcome } => {
                    state.update_checking = false;
                    match outcome {
                        UpdateCheckOutcome::UpToDate { current_version } => {
                            state.update_state = UpdateUiState {
                                status: "up_to_date",
                                latest_version: Some(current_version.clone()),
                                download_url: None,
                                message: Some(format!("Up to date ({current_version})")),
                            };
                            state.set_transient_status(format!("Up to date ({current_version})"));
                        }
                        UpdateCheckOutcome::Available {
                            latest_version,
                            download_url,
                        } => {
                            state.update_state = UpdateUiState {
                                status: "available",
                                latest_version: Some(latest_version.clone()),
                                download_url: Some(download_url),
                                message: Some(format!("Update {latest_version} available")),
                            };
                            state.set_transient_status(format!("Update {latest_version} available"));
                        }
                        UpdateCheckOutcome::Error(msg) => {
                            state.update_state = UpdateUiState {
                                status: "error",
                                latest_version: None,
                                download_url: None,
                                message: Some(msg.clone()),
                            };
                            state.set_transient_status(msg);
                        }
                    }
                    state.sync_webview(&webview);
                }
            },
            _ => {}
        }

        let next_deadline = match (state.status_revert_at, state.main_hide_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        if let Some(deadline) = next_deadline {
            *control_flow = ControlFlow::WaitUntil(deadline);
        } else {
            *control_flow = ControlFlow::Wait;
        }
    });
}
