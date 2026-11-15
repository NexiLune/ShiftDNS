#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod benchmark;
mod config;
mod dns;
mod icon_gen;
mod tray;

use config::{is_valid_doh_url, set_windows_startup, top_used_profiles, AppConfig, DnsProfile};
use dns::NetworkAdapter;
use icon_gen::generate_app_icon_rgba;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static DNS_MUTATION_MUTEX: Mutex<()> = Mutex::new(());
static LATEST_OP_GEN: AtomicU64 = AtomicU64::new(0);
use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tray::TrayController;
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
use wry::{WebContext, WebView, WebViewBuilder};

#[cfg(target_os = "windows")]
use tao::platform::windows::{WindowBuilderExtWindows, WindowExtWindows};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, POINT,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWCP_ROUND, DWMWA_TRANSITIONS_FORCEDISABLED,
    DWMWA_WINDOW_CORNER_PREFERENCE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::CreateMutexW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetCursorPos, SetForegroundWindow, SetWindowPos, ShowWindow, HWND_TOPMOST,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_RESTORE, SW_SHOW,
};

const WINDOW_TITLE: &str = "ShiftDNS";
const TRAY_WINDOW_TITLE: &str = "ShiftDNS Tray";
const WINDOW_WIDTH: f64 = 420.0;
const WINDOW_HEIGHT: f64 = 286.0;
const TRAY_POPUP_WIDTH: f64 = 256.0;
const TRAY_EDGE_GAP_PX: f64 = 8.0;

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
        target_profile_id: Option<String>,
        profile_name: Option<String>,
        adapters: Vec<NetworkAdapter>,
        result: Result<(), String>,
    },
    StartupTaskFinished {
        enable: bool,
        result: Result<(), String>,
    },
    ProbeResult {
        gen: u64,
        rtt: Option<u128>,
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
    #[serde(rename = "dragWindow")]
    DragWindow,
    #[serde(rename = "beginHide")]
    BeginHide,
    #[serde(rename = "hideWindow")]
    HideWindow,
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

#[derive(Serialize)]
struct UiSyncPayload<'a> {
    profiles: &'a [DnsProfile],
    #[serde(rename = "activeProfileId")]
    active_profile_id: Option<&'a str>,
    #[serde(rename = "darkMode")]
    dark_mode: bool,
    #[serde(rename = "enableIpv6")]
    enable_ipv6: bool,
    #[serde(rename = "enableDoh")]
    enable_doh: bool,
    #[serde(rename = "startMinimized")]
    start_minimized: bool,
    #[serde(rename = "launchAtStartup")]
    launch_at_startup: bool,
    #[serde(rename = "adapterLabel")]
    adapter_label: String,
    #[serde(rename = "activeLatency", skip_serializing_if = "Option::is_none")]
    active_latency: Option<Option<u128>>,
    #[serde(rename = "probingActive")]
    probing_active: bool,
    #[serde(rename = "statusMessage")]
    status_message: &'a str,
    #[serde(rename = "statusIsError")]
    status_is_error: bool,
}

#[derive(Serialize)]
struct TraySyncPayload<'a> {
    #[serde(rename = "darkMode")]
    dark_mode: bool,
    #[serde(rename = "mainVisible")]
    main_visible: bool,
    #[serde(rename = "activeProfileId")]
    active_profile_id: Option<&'a str>,
    #[serde(rename = "topProfiles")]
    top_profiles: Vec<DnsProfile>,
}

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
struct SingleInstanceGuard(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn focus_hwnd(hwnd: HWND) {
    if !hwnd.is_null() {
        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(target_os = "windows")]
fn focus_window_by_title(window_title: &str) {
    let title = to_wide(window_title);
    let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    focus_hwnd(hwnd);
}

#[cfg(not(target_os = "windows"))]
fn focus_window_by_title(_window_title: &str) {}

#[cfg(target_os = "windows")]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    let name = to_wide("Local\\ShiftDNS_SingleInstance_Mutex");
    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            CloseHandle(handle);
            focus_window_by_title(WINDOW_TITLE);
            return None;
        }
        Some(SingleInstanceGuard(handle))
    }
}

#[cfg(not(target_os = "windows"))]
struct SingleInstanceGuard;

#[cfg(not(target_os = "windows"))]
fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    Some(SingleInstanceGuard)
}

#[cfg(target_os = "windows")]
fn configure_window_dwm_hwnd(hwnd: HWND, disable_transitions: bool, dark_mode: bool) {
    if hwnd.is_null() {
        return;
    }
    unsafe {
        let preference = DWMWCP_ROUND; // 2: Rounded Windows 11 corners
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &preference as *const _ as *const _,
            std::mem::size_of_val(&preference) as u32,
        );
        // Match subtle 1px Windows 11 DWM border color (#22252A dark / #E5E5E5 light in COLORREF 0x00BBGGRR)
        const DWMWA_BORDER_COLOR: u32 = 34;
        let border_color: u32 = if dark_mode { 0x002A2522 } else { 0x00E5E5E5 };
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR,
            &border_color as *const _ as *const _,
            std::mem::size_of_val(&border_color) as u32,
        );
        if disable_transitions {
            let force_disable: i32 = 1; // Win32 BOOL TRUE
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_TRANSITIONS_FORCEDISABLED as u32,
                &force_disable as *const _ as *const _,
                std::mem::size_of_val(&force_disable) as u32,
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn configure_window_dwm(window: &Window, disable_transitions: bool, dark_mode: bool) {
    let hwnd = window.hwnd() as HWND;
    configure_window_dwm_hwnd(hwnd, disable_transitions, dark_mode);
}

#[cfg(not(target_os = "windows"))]
fn configure_window_dwm(_window: &Window, _disable_transitions: bool, _dark_mode: bool) {}

fn compute_tray_logical_height(main_visible: bool, preset_count: usize) -> f64 {
    // Matches tray.html layout metrics:
    // .tray-menu: 2px border + 10px vertical padding, 2px flex row gap
    // .menu-item: 30px height; .divider: 9px (1px border + 8px vertical margin)
    let menu_items = if main_visible { 0 } else { 1 } + 1 + preset_count + 1;
    let dividers = if main_visible { 1 } else { 2 };
    let child_count = menu_items + dividers;
    let gaps = child_count.saturating_sub(1);
    (12 + menu_items * 30 + dividers * 9 + gaps * 2) as f64
}

#[cfg(target_os = "windows")]
fn resolve_tray_anchor(anchor_x: i32, anchor_y: i32) -> (i32, i32) {
    if anchor_x != 0 || anchor_y != 0 {
        return (anchor_x, anchor_y);
    }
    let mut pt = POINT { x: 0, y: 0 };
    unsafe {
        if GetCursorPos(&mut pt) != 0 {
            return (pt.x, pt.y);
        }
    }
    (anchor_x, anchor_y)
}

#[cfg(not(target_os = "windows"))]
fn resolve_tray_anchor(anchor_x: i32, anchor_y: i32) -> (i32, i32) {
    (anchor_x, anchor_y)
}

#[cfg(target_os = "windows")]
fn ensure_tray_topmost(tray_window: &Window) {
    tray_window.set_always_on_top(true);
    let hwnd = tray_window.hwnd() as HWND;
    if !hwnd.is_null() {
        unsafe {
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_tray_topmost(tray_window: &Window) {
    tray_window.set_always_on_top(true);
}

#[cfg(target_os = "windows")]
fn position_tray_window(tray_window: &Window, anchor_x: i32, anchor_y: i32, logical_h: f64) {
    let clamped_h = logical_h.clamp(85.0, 340.0);
    let (cursor_x, cursor_y) = resolve_tray_anchor(anchor_x, anchor_y);

    unsafe {
        let pt = POINT {
            x: cursor_x,
            y: cursor_y,
        };
        let hmon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if !hmon.is_null() && GetMonitorInfoW(hmon, &mut mi as *mut MONITORINFO) != 0 {
            let work = mi.rcWork;
            let work_mid_y = work.top + (work.bottom - work.top) / 2;

            let initial_scale = tray_window.scale_factor().max(1.0);
            tray_window.set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, clamped_h));

            let compute_xy = |scale: f64, outer_w: i32, outer_h: i32| -> (i32, i32, i32, i32) {
                let w = outer_w.max((TRAY_POPUP_WIDTH * scale).round() as i32);
                let h = outer_h.max((clamped_h * scale).round() as i32);
                let edge_gap = (TRAY_EDGE_GAP_PX * scale).round() as i32;

                let raw_x = cursor_x - w + (24.0 * scale).round() as i32;
                let x = raw_x
                    .max(work.left + edge_gap)
                    .min((work.right - w - edge_gap).max(work.left + edge_gap));

                // Anchor relative to cursor Y while clamping bottom edge >= 8px above rcWork.bottom
                let raw_y = if cursor_y >= work_mid_y {
                    (cursor_y - h - edge_gap).min(work.bottom - h - edge_gap)
                } else {
                    (cursor_y + edge_gap).max(work.top + edge_gap)
                };
                let y = raw_y
                    .max(work.top + edge_gap)
                    .min((work.bottom - h - edge_gap).max(work.top + edge_gap));
                (x, y, w, h)
            };

            let outer = tray_window.outer_size();
            let (mut x, mut y, mut w, mut h) =
                compute_xy(initial_scale, outer.width as i32, outer.height as i32);
            tray_window.set_outer_position(PhysicalPosition::new(x, y));

            // Re-sync if moving onto another monitor updated the window's DPI scale factor
            let settled_scale = tray_window.scale_factor().max(1.0);
            if (settled_scale - initial_scale).abs() > 0.01 {
                tray_window.set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, clamped_h));
                let outer_after = tray_window.outer_size();
                (x, y, w, h) = compute_xy(
                    settled_scale,
                    outer_after.width as i32,
                    outer_after.height as i32,
                );
                tray_window.set_outer_position(PhysicalPosition::new(x, y));
            }

            let hwnd = tray_window.hwnd() as HWND;
            if !hwnd.is_null() {
                SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE);
            }
            return;
        }
    }

    let scale = tray_window.scale_factor().max(1.0);
    let w = (TRAY_POPUP_WIDTH * scale).round() as i32;
    let h = (clamped_h * scale).round() as i32;
    let edge_gap = (TRAY_EDGE_GAP_PX * scale).round() as i32;
    tray_window.set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, clamped_h));
    tray_window.set_outer_position(PhysicalPosition::new(
        (cursor_x - w).max(0),
        (cursor_y - h - edge_gap).max(0),
    ));
}

#[cfg(not(target_os = "windows"))]
fn position_tray_window(tray_window: &Window, anchor_x: i32, anchor_y: i32, logical_h: f64) {
    tray_window.set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, logical_h.clamp(85.0, 340.0)));
    tray_window.set_outer_position(PhysicalPosition::new(anchor_x, anchor_y));
}

struct AppState {
    config: AppConfig,
    adapters: Vec<NetworkAdapter>,
    active_latency: Option<Option<u128>>,
    probing_active: bool,
    probe_generation: u64,
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
            probing_active: false,
            probe_generation: 0,
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
                self.spawn_active_probe();
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
        compute_tray_logical_height(main_visible, preset_count).clamp(85.0, 340.0)
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
            main_visible,
            active_profile_id: self.config.active_profile_id.as_deref(),
            top_profiles,
        };
        if let Ok(json) = serde_json::to_string(&payload) {
            let script = format!("window.__shiftdnsTraySync && window.__shiftdnsTraySync({json});");
            let _ = tray_webview.evaluate_script(&script);
        }
    }

    fn sync_webview(&self, webview: &WebView) {
        if !self.webview_ready {
            return;
        }
        let payload = UiSyncPayload {
            profiles: &self.config.profiles,
            active_profile_id: self.config.active_profile_id.as_deref(),
            dark_mode: self.config.dark_mode,
            enable_ipv6: self.config.enable_ipv6,
            enable_doh: self.config.enable_doh,
            start_minimized: self.config.start_minimized,
            launch_at_startup: self.config.launch_at_startup,
            adapter_label: self.adapter_label(),
            active_latency: self.active_latency,
            probing_active: self.probing_active,
            status_message: &self.status_message,
            status_is_error: self.status_is_error,
        };
        if let Ok(json) = serde_json::to_string(&payload) {
            let script = format!("window.__shiftdnsSync && window.__shiftdnsSync({json});");
            let _ = webview.evaluate_script(&script);
        }
    }

    fn sync_all_ui(&self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        self.sync_webview(webview);
        self.sync_tray_webview(tray_webview, main_visible);
    }

    fn spawn_active_probe(&mut self) {
        let Some(active_id) = self.config.active_profile_id.as_deref() else {
            self.active_latency = None;
            self.probing_active = false;
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

        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let rtt = benchmark::probe_dns_latency(&target_ip);
            let _ = proxy.send_event(UserEvent::ProbeResult { gen, rtt });
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
            self.active_latency = None;
            self.probing_active = false;
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
            self.spawn_active_probe();
        }
        self.sync_all_ui(webview, tray_webview, main_visible);
        self.last_refresh_at = None;
        self.spawn_refresh_adapters(true);
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

        self.op_generation = self.op_generation.saturating_add(1);
        let gen = self.op_generation;
        LATEST_OP_GEN.store(gen, Ordering::Release);
        self.op_in_flight = true;
        self.probe_generation = self.probe_generation.saturating_add(1);

        // Optimistic immediate UI update so FLIP animations & checkmark transitions run at 60fps
        self.config.active_profile_id = Some(profile.id.clone());
        self.active_latency = None;
        self.probing_active = true;
        self.status_revert_at = None;
        self.status_message = format!("Applying {}...", profile.name);
        self.status_is_error = false;
        self.sync_tray_icon();
        self.sync_all_ui(webview, tray_webview, main_visible);

        let selected_adapter = self.config.selected_adapter.clone();
        let enable_ipv6 = self.config.enable_ipv6;
        let enable_doh = self.config.enable_doh;
        let proxy = self.proxy.clone();
        let target_id = profile.id.clone();
        let profile_name = profile.name.clone();

        std::thread::spawn(move || {
            let _guard = DNS_MUTATION_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if LATEST_OP_GEN.load(Ordering::Acquire) != gen {
                return;
            }
            let initial_adapters = dns::list_adapters();
            let result = dns::apply_profile(
                &initial_adapters,
                selected_adapter.as_deref(),
                &profile,
                enable_ipv6,
                enable_doh,
            );
            let updated_adapters = dns::list_adapters();
            let _ = proxy.send_event(UserEvent::DnsApplyFinished {
                gen,
                target_profile_id: Some(target_id),
                profile_name: Some(profile_name),
                adapters: updated_adapters,
                result,
            });
        });
    }

    fn activate_dhcp(&mut self, webview: &WebView, tray_webview: &WebView, main_visible: bool) {
        self.op_generation = self.op_generation.saturating_add(1);
        let gen = self.op_generation;
        LATEST_OP_GEN.store(gen, Ordering::Release);
        self.op_in_flight = true;
        self.probe_generation = self.probe_generation.saturating_add(1);

        self.config.active_profile_id = None;
        self.active_latency = None;
        self.probing_active = false;
        self.status_revert_at = None;
        self.status_message = "Restoring DHCP...".to_string();
        self.status_is_error = false;
        self.sync_tray_icon();
        self.sync_all_ui(webview, tray_webview, main_visible);

        let selected_adapter = self.config.selected_adapter.clone();
        let proxy = self.proxy.clone();

        std::thread::spawn(move || {
            let _guard = DNS_MUTATION_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if LATEST_OP_GEN.load(Ordering::Acquire) != gen {
                return;
            }
            let initial_adapters = dns::list_adapters();
            let result = dns::reset_to_dhcp(&initial_adapters, selected_adapter.as_deref());
            let updated_adapters = dns::list_adapters();
            let _ = proxy.send_event(UserEvent::DnsApplyFinished {
                gen,
                target_profile_id: None,
                profile_name: None,
                adapters: updated_adapters,
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
        let name = payload.name.trim().to_string();
        let category = if payload.category.trim().is_empty() {
            "Custom".to_string()
        } else {
            payload.category.trim().to_string()
        };
        let p4 = payload.primary_v4.trim().to_string();
        let s4 = payload.secondary_v4.trim().to_string();
        let p6 = payload.primary_v6.trim().to_string();
        let s6 = payload.secondary_v6.trim().to_string();
        let doh = payload.doh_template.trim().to_string();

        if name.is_empty() {
            self.set_error_status("Name is required.");
            self.sync_webview(webview);
            return;
        }
        if p4.parse::<Ipv4Addr>().is_err() {
            self.set_error_status("Primary IPv4 address is invalid.");
            self.sync_webview(webview);
            return;
        }
        if !s4.is_empty() && s4.parse::<Ipv4Addr>().is_err() {
            self.set_error_status("Secondary IPv4 address is invalid.");
            self.sync_webview(webview);
            return;
        }
        if !p6.is_empty() && !matches!(p6.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            self.set_error_status("Primary IPv6 address is invalid.");
            self.sync_webview(webview);
            return;
        }
        if !s6.is_empty() && !matches!(s6.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            self.set_error_status("Secondary IPv6 address is invalid.");
            self.sync_webview(webview);
            return;
        }
        if !is_valid_doh_url(&doh) {
            self.set_error_status("DoH template must be a valid https:// URL.");
            self.sync_webview(webview);
            return;
        }

        if let Some(editing_id) = payload.id.filter(|id| !id.is_empty()) {
            let mut updated_profile = None;
            if let Some(target) = self.config.profiles.iter_mut().find(|p| p.id == editing_id) {
                target.name = name.clone();
                target.category = category;
                target.primary_v4 = p4;
                target.secondary_v4 = s4;
                target.primary_v6 = p6;
                target.secondary_v6 = s6;
                target.doh_template = doh;
                updated_profile = Some(target.clone());
            }
            self.save_config();
            if self.config.active_profile_id.as_deref() == Some(editing_id.as_str()) {
                if updated_profile.is_some() {
                    self.activate_profile(&editing_id, webview, tray_webview, main_visible);
                    return;
                }
            }
            self.sync_tray_icon();
            self.set_transient_status(format!("Updated {name}"));
            self.sync_all_ui(webview, tray_webview, main_visible);
            return;
        }

        let slug: String = name
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
            name: name.clone(),
            category,
            primary_v4: p4,
            secondary_v4: s4,
            primary_v6: p6,
            secondary_v6: s6,
            doh_template: doh,
            is_custom: true,
        });
        self.save_config();
        self.sync_tray_icon();
        self.set_transient_status(format!("Added {name}"));
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
    let _instance_guard = match acquire_single_instance() {
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
        .with_inner_size(LogicalSize::new(WINDOW_WIDTH, WINDOW_HEIGHT))
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
                                let main_visible = is_main_effectively_visible(&window);
                                let exact_h = state.tray_logical_height(main_visible);
                                state.last_tray_logical_height = exact_h;
                                state.sync_tray_webview(&tray_webview, main_visible);
                                let (ax, ay) = resolve_tray_anchor(
                                    position.x.round() as i32,
                                    position.y.round() as i32,
                                );
                                state.last_tray_anchor = Some((ax, ay));
                                tray_window
                                    .set_inner_size(LogicalSize::new(TRAY_POPUP_WIDTH, exact_h));
                                position_tray_window(&tray_window, ax, ay, exact_h);
                                configure_window_dwm(&tray_window, true, state.config.dark_mode);
                                ensure_tray_topmost(&tray_window);
                                state.tray_opened_at = Some(Instant::now());
                                state.tray_blur_closed_at = None;
                                tray_window.set_visible(true);
                                tray_window.set_focus();
                                #[cfg(target_os = "windows")]
                                focus_hwnd(tray_window.hwnd() as HWND);
                                ensure_tray_topmost(&tray_window);
                                let _ = tray_webview.evaluate_script(
                                    "window.__shiftdnsTrayOpen && window.__shiftdnsTrayOpen();",
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
                                state.spawn_active_probe();
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
                                let clamped = height.clamp(85.0, 340.0);
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
                            state.active_latency = None;
                            state.probing_active = false;
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
                            state.spawn_active_probe();
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
                    target_profile_id,
                    profile_name,
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
                                if let Some(name) = profile_name {
                                    if !state.status_is_error {
                                        state.set_transient_status(format!(
                                            "Applied {name} · Cache flushed"
                                        ));
                                    }
                                    state.spawn_active_probe();
                                } else {
                                    state.probing_active = false;
                                    state.active_latency = None;
                                    if !state.status_is_error {
                                        state.set_transient_status("Restored DHCP · Cache flushed");
                                    }
                                }
                            }
                            Err(err) => {
                                if !state.adapters.is_empty() {
                                    state.config.active_profile_id = dns::detect_active_profile_id(
                                        &state.adapters,
                                        state.config.selected_adapter.as_deref(),
                                        &state.config.profiles,
                                    );
                                    state.save_config();
                                }
                                state.probing_active = false;
                                state.active_latency = None;
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
                UserEvent::ProbeResult { gen, rtt } => {
                    if gen == state.probe_generation {
                        state.probing_active = false;
                        state.active_latency = Some(rtt);
                        state.sync_tray_icon();
                        state.sync_webview(&webview);
                    }
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
