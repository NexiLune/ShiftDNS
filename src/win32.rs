#[cfg(target_os = "windows")]
use std::sync::OnceLock;
use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::window::Window;

#[cfg(target_os = "windows")]
use tao::platform::windows::WindowExtWindows;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, POINT,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Graphics::Dwm::{
    DwmFlush, DwmSetWindowAttribute, DWMWCP_ROUND, DWMWA_TRANSITIONS_FORCEDISABLED,
    DWMWA_WINDOW_CORNER_PREFERENCE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Graphics::Gdi::{
    CreateSolidBrush, GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::CreateMutexW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetCursorPos, SetForegroundWindow, SetWindowPos, ShowWindow, GCLP_HBRBACKGROUND,
    HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL,
};
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
use windows_sys::Win32::UI::WindowsAndMessaging::SetClassLongPtrW;
#[cfg(all(target_os = "windows", target_pointer_width = "32"))]
use windows_sys::Win32::UI::WindowsAndMessaging::SetClassLongW;

pub const MAIN_WINDOW_WIDTH: f64 = 420.0;
pub const MAIN_WINDOW_HEIGHT: f64 = 286.0; // 44px titlebar + 204px body (DHCP + 3 DNS rows) + 36px footer + 2px border

pub const TRAY_POPUP_WIDTH: f64 = 256.0;
pub const TRAY_EDGE_GAP_PX: f64 = 8.0;
pub const TRAY_MIN_HEIGHT: f64 = 85.0;
pub const TRAY_MAX_HEIGHT: f64 = 340.0;

pub fn compute_tray_logical_height(main_visible: bool, preset_count: usize) -> f64 {
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
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
pub struct SingleInstanceGuard(HANDLE);

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

#[cfg(not(target_os = "windows"))]
pub struct SingleInstanceGuard;

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
pub fn focus_window(window: &Window) {
    focus_hwnd(window.hwnd() as HWND);
}

#[cfg(not(target_os = "windows"))]
pub fn focus_window(window: &Window) {
    window.set_focus();
}

#[cfg(target_os = "windows")]
fn focus_window_by_title(window_title: &str) {
    let title = to_wide(window_title);
    let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    focus_hwnd(hwnd);
}

#[cfg(target_os = "windows")]
pub fn acquire_single_instance(window_title: &str) -> Option<SingleInstanceGuard> {
    let name = to_wide("Local\\ShiftDNS_SingleInstance_Mutex");
    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if !handle.is_null() && GetLastError() == ERROR_ALREADY_EXISTS {
            CloseHandle(handle);
            focus_window_by_title(window_title);
            return None;
        }
        Some(SingleInstanceGuard(handle))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn acquire_single_instance(_window_title: &str) -> Option<SingleInstanceGuard> {
    Some(SingleInstanceGuard)
}

#[cfg(target_os = "windows")]
fn window_bg_brush(dark_mode: bool) -> usize {
    static DARK_BRUSH: OnceLock<usize> = OnceLock::new();
    static LIGHT_BRUSH: OnceLock<usize> = OnceLock::new();
    let cell = if dark_mode { &DARK_BRUSH } else { &LIGHT_BRUSH };
    *cell.get_or_init(|| unsafe {
        // COLORREF (0x00BBGGRR): #141415 dark / #FFFFFF light prevents bare-HWND white flashes
        let color: u32 = if dark_mode { 0x00151414 } else { 0x00FFFFFF };
        CreateSolidBrush(color) as usize
    })
}

#[cfg(target_os = "windows")]
fn set_window_cloaked(hwnd: HWND, cloaked: bool) {
    if hwnd.is_null() {
        return;
    }
    const DWMWA_CLOAK: u32 = 13;
    let value: i32 = if cloaked { 1 } else { 0 };
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CLOAK,
            &value as *const _ as *const _,
            std::mem::size_of_val(&value) as u32,
        );
    }
}

#[cfg(target_os = "windows")]
pub fn minimize_window_cleanly(window: &Window) {
    let hwnd = window.hwnd() as HWND;
    set_window_cloaked(hwnd, true);
    window.set_minimized(true);
    unsafe {
        let _ = DwmFlush();
    }
    set_window_cloaked(hwnd, false);
}

#[cfg(not(target_os = "windows"))]
pub fn minimize_window_cleanly(window: &Window) {
    window.set_minimized(true);
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
        const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
        let dark_val: i32 = if dark_mode { 1 } else { 0 };
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark_val as *const _ as *const _,
            std::mem::size_of_val(&dark_val) as u32,
        );
        // Match subtle 1px Windows 11 DWM border color (#262628 dark / #E4E4E7 light in COLORREF 0x00BBGGRR)
        const DWMWA_BORDER_COLOR: u32 = 34;
        let border_color: u32 = if dark_mode { 0x00282626 } else { 0x00E7E4E4 };
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR,
            &border_color as *const _ as *const _,
            std::mem::size_of_val(&border_color) as u32,
        );
        let brush = window_bg_brush(dark_mode);
        if brush != 0 {
            #[cfg(target_pointer_width = "64")]
            {
                let _ = SetClassLongPtrW(hwnd, GCLP_HBRBACKGROUND, brush as isize);
            }
            #[cfg(target_pointer_width = "32")]
            {
                let _ = SetClassLongW(hwnd, GCLP_HBRBACKGROUND, brush as i32);
            }
        }
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
pub fn configure_window_dwm(window: &Window, disable_transitions: bool, dark_mode: bool) {
    let hwnd = window.hwnd() as HWND;
    configure_window_dwm_hwnd(hwnd, disable_transitions, dark_mode);
}

#[cfg(not(target_os = "windows"))]
pub fn configure_window_dwm(_window: &Window, _disable_transitions: bool, _dark_mode: bool) {}

#[cfg(target_os = "windows")]
pub fn resolve_tray_anchor(anchor_x: i32, anchor_y: i32) -> (i32, i32) {
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
pub fn resolve_tray_anchor(anchor_x: i32, anchor_y: i32) -> (i32, i32) {
    (anchor_x, anchor_y)
}

#[cfg(target_os = "windows")]
pub fn ensure_tray_topmost(tray_window: &Window) {
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
pub fn ensure_tray_topmost(tray_window: &Window) {
    tray_window.set_always_on_top(true);
}

#[cfg(target_os = "windows")]
pub fn position_tray_window(tray_window: &Window, anchor_x: i32, anchor_y: i32, logical_h: f64) {
    let clamped_h = logical_h.clamp(TRAY_MIN_HEIGHT, TRAY_MAX_HEIGHT);
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
pub fn position_tray_window(tray_window: &Window, anchor_x: i32, anchor_y: i32, logical_h: f64) {
    tray_window.set_inner_size(LogicalSize::new(
        TRAY_POPUP_WIDTH,
        logical_h.clamp(TRAY_MIN_HEIGHT, TRAY_MAX_HEIGHT),
    ));
    tray_window.set_outer_position(PhysicalPosition::new(anchor_x, anchor_y));
}

pub const GITHUB_RELEASES_URL: &str = "https://github.com/NexiLune/ShiftDNS/releases";

pub fn is_allowed_release_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    trimmed.starts_with("https://github.com/NexiLune/ShiftDNS/releases/")
        || trimmed == GITHUB_RELEASES_URL
}

#[cfg(target_os = "windows")]
pub fn open_release_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if !is_allowed_release_url(trimmed) {
        return Err("Blocked invalid release URL.".to_string());
    }
    let verb = to_wide("open");
    let target = to_wide(trimmed);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (result as isize) <= 32 {
        return Err("Failed to open download link in browser.".to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn open_release_url(url: &str) -> Result<(), String> {
    if !is_allowed_release_url(url) {
        return Err("Blocked invalid release URL.".to_string());
    }
    Ok(())
}

