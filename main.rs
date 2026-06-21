#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem, WindowEvent,
};

// ---------------------------------------------------------------------------
// System tray menu
// ---------------------------------------------------------------------------

fn build_tray_menu() -> SystemTrayMenu {
    SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("open",    "Open Persistence Hunter").accelerator(""))
        .add_item(CustomMenuItem::new("scan",    "Scan Now"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("pause",   "Pause Protection (5 min)"))
        .add_item(CustomMenuItem::new("settings","Settings"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("about",   "About"))
        .add_item(CustomMenuItem::new("quit",    "Quit"))
}

// ---------------------------------------------------------------------------
// IPC commands — called from React via invoke()
// ---------------------------------------------------------------------------

/// Tells Tauri to show the main window (called when user clicks a toast)
#[tauri::command]
fn show_window(window: tauri::Window) {
    window.get_window("main").map(|w| {
        w.show().ok();
        w.set_focus().ok();
    });
}

/// Update the tray icon based on threat status from the Python API
/// Called by the React frontend after polling /api/status
#[tauri::command]
fn update_tray_status(app: tauri::AppHandle, status: String) {
    let icon_path = match status.as_str() {
        "danger"  => "icons/tray-danger.png",
        "warning" => "icons/tray-warning.png",
        "notice"  => "icons/tray-clean.png",
        _         => "icons/tray-clean.png",
    };

    if let Ok(icon) = tauri::Icon::File(std::path::PathBuf::from(icon_path)).into() {
        app.tray_handle().set_icon(icon).ok();
    }

    let tooltip = match status.as_str() {
        "danger"  => "Persistence Hunter — Threat detected",
        "warning" => "Persistence Hunter — Items to review",
        _         => "Persistence Hunter — Protected",
    };
    app.tray_handle().set_tooltip(tooltip).ok();
}

/// Triggered by frontend to fire a native toast notification
/// (Tauri's notification plugin handles the actual OS notification)
#[tauri::command]
fn notify(title: String, body: String) {
    // Forward to OS notification — Tauri handles this cross-platform
    // In production, wire to tauri-plugin-notification
    println!("[notify] {title}: {body}");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let tray = SystemTray::new().with_menu(build_tray_menu());

    tauri::Builder::default()
        .system_tray(tray)
        // ── Tray click / menu events ────────────────────────────────────
        .on_system_tray_event(|app, event| match event {
            // Left-click tray icon → show/focus window
            SystemTrayEvent::LeftButtonUp { .. } => {
                if let Some(window) = app.get_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        window.set_focus().ok();
                    } else {
                        window.show().ok();
                        window.set_focus().ok();
                    }
                }
            }

            // Menu items
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "open" => {
                    if let Some(window) = app.get_window("main") {
                        window.show().ok();
                        window.set_focus().ok();
                    }
                }
                "scan" => {
                    // Emit event to frontend → frontend calls /api/scan
                    app.emit_all("tray:scan", ()).ok();
                }
                "pause" => {
                    app.emit_all("tray:pause", ()).ok();
                }
                "settings" => {
                    if let Some(window) = app.get_window("main") {
                        window.show().ok();
                        window.emit("navigate", "/settings").ok();
                    }
                }
                "about" => {
                    tauri::api::shell::open(
                        &app.shell_scope(),
                        "https://github.com/JimmyDevvvvv/Persistence-Hunter",
                        None,
                    ).ok();
                }
                "quit" => {
                    app.exit(0);
                }
                _ => {}
            },
            _ => {}
        })
        // ── Window close → hide to tray instead of quit ─────────────────
        .on_window_event(|event| {
            if let WindowEvent::CloseRequested { api, .. } = event.event() {
                event.window().hide().ok();
                api.prevent_close();
            }
        })
        // ── IPC commands ─────────────────────────────────────────────────
        .invoke_handler(tauri::generate_handler![
            show_window,
            update_tray_status,
            notify,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Persistence Hunter");
}
