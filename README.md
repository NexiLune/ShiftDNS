# ShiftDNS — Lightweight Windows DNS Switcher (Rust)

Minimal, single-binary Windows DNS switcher written in Rust (`wry` + `tao` WebView2 + `tray-icon`), compiled with LTO and size optimization for minimal memory and disk footprint.

## Features

- **System Tray Quick-Toggle**: Left-click the tray icon to show/hide the window; right-click to switch top DNS presets, reset to DHCP (automatically flushing the Windows DNS cache), or exit without opening the main window.
- **Single-Instance & Close-to-Tray**: Uses a Windows Mutex to prevent duplicate instances (re-focusing the running window instead) and closes cleanly to the system tray.
- **Curated & Custom Profiles**: Built-in presets (Cloudflare, Cloudflare Family, Quad9, Google Public, AdGuard, Mullvad, Control D, OpenDNS Home) plus custom IPv4/IPv6 + DoH profiles saved to `%APPDATA%\ShiftDNS\config.json`.
- **Real UDP Port 53 Latency Probing**: Probes the active resolver directly over UDP port 53 when selected, focused, or clicked to retest.
- **Physical-Adapter Switching & Auto-Flush**: Targets connected physical adapters (`Wi-Fi`, `Ethernet`) and automatically runs `ipconfig /flushdns` after every change.
- **Windows 11 Native DoH & IPv6 Support**: Optional automatic registration of DNS-over-HTTPS templates via `netsh dns add encryption`.
- **Silent Elevated Startup**: Uses Windows Task Scheduler (`schtasks /RL HIGHEST`) when "Launch at Windows sign-in" is enabled so UAC does not block startup.

## Build & Installer (Windows 10 / 11)

1. Run `cargo build --release` inside `rust-windows/` to build `target\release\ShiftDNS.exe`.
2. Compile `rust-windows/installer.iss` with Inno Setup 6 (`ISCC.exe`)—or push a `v*` tag to trigger the GitHub Actions release workflow—to produce `ShiftDNS-Setup.exe`.
3. Uninstall cleanly at any time via **Windows Settings → Apps → Installed apps**.
