// ──────────────────────────────────────────────────────────────
//  Raypher — System Tray Panic Button (Phase 4)
//  Runs a system tray icon with a context menu showing proxy
//  status. The "Kill All Agents" menu item immediately kills
//  all AI agent processes registered in the allow-list.
//
//  FEATURE GATE: Only compiled when `--features desktop` is set.
//  Must run on the main thread (GUI requirement on macOS + Windows).
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "desktop")]
pub mod tray_impl {
    use tracing::{info, warn};

    // ── Tray Entry Point ───────────────────────────────────────

    /// Start the system tray icon and event loop.
    /// This function BLOCKS — it must be called on the main thread
    /// or a dedicated thread spawned for tray management.
    ///
    /// # Arguments
    /// * `on_kill_all` — Callback invoked when user clicks "Kill All Agents".
    pub fn start_tray<F>(on_kill_all: F)
    where
        F: Fn() + Send + 'static,
    {
        use tray_icon::{TrayIconBuilder, menu::{Menu, MenuItem, PredefinedMenuItem}};

        info!("Starting system tray...");

        // Build context menu
        let menu = Menu::new();
        let kill_item = MenuItem::new("🚨 Kill All Agents", true, None);
        let sep = PredefinedMenuItem::separator();
        let quit_item = MenuItem::new("Quit Raypher", true, None);

        menu.append(&kill_item).ok();
        menu.append(&sep).ok();
        menu.append(&quit_item).ok();

        // Load icon (inline PNG bytes so no external file dependency)
        let icon = load_tray_icon();

        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Raypher — AI Agent Proxy Active")
            .with_icon(icon)
            .build()
            .expect("Failed to create system tray icon");

        info!("System tray active");

        // Event loop
        use tray_icon::TrayIconEvent;

        loop {
            if let Ok(event) = TrayIconEvent::receiver().try_recv() {
                info!("Tray event: {:?}", event);
            }

            // Check for menu item clicks
            if let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                if event.id == kill_item.id() {
                    warn!("PANIC BUTTON PRESSED — killing all AI agents");
                    on_kill_all();
                } else if event.id == quit_item.id() {
                    info!("Tray quit requested");
                    std::process::exit(0);
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Load the tray icon from compiled-in bytes.
    /// Falls back to a minimal generated icon if the PNG is not available.
    fn load_tray_icon() -> tray_icon::Icon {
        // Embed the icon at compile time if available
        const ICON_PNG: &[u8] = if cfg!(feature = "desktop") {
            // Try to include icon at compile time; fallback path
            include_bytes!("../assets/icon.png")
        } else {
            &[]
        };

        if !ICON_PNG.is_empty() {
            if let Ok(img) = image::load_from_memory(ICON_PNG) {
                let rgba = img.into_rgba8();
                let (w, h) = rgba.dimensions();
                return tray_icon::Icon::from_rgba(rgba.into_raw(), w, h)
                    .expect("Failed to create icon from PNG");
            }
        }

        // Fallback: 16x16 solid color icon (raypher purple = #6B2FBE)
        let size = 16u32;
        let pixels: Vec<u8> = (0..size * size)
            .flat_map(|_| vec![0x6B_u8, 0x2F, 0xBE, 0xFF]) // RGBA purple
            .collect();
        tray_icon::Icon::from_rgba(pixels, size, size)
            .expect("Failed to create fallback icon")
    }

    // ── Status Update (for future badge/tooltip changes) ──────

    /// Update the tray tooltip text.
    /// Call this when proxy state changes (e.g., agent count).
    pub fn update_tooltip(msg: &str) {
        info!("Tray tooltip: {}", msg);
        // In a production implementation, we'd call tray.set_tooltip(msg)
        // via a shared Arc<Mutex<TrayIcon>>. Simplified for now.
    }
}

// ── Stub for non-desktop builds ────────────────────────────────

#[cfg(not(feature = "desktop"))]
pub mod tray_impl {
    /// No-op stub — tray is only available with `--features desktop`.
    pub fn start_tray<F>(_on_kill_all: F)
    where
        F: Fn() + Send + 'static,
    {
        tracing::info!("System tray disabled (build without --features desktop)");
    }

    pub fn update_tooltip(_msg: &str) {}
}

// ── Public re-exports ──────────────────────────────────────────

pub use tray_impl::start_tray;
pub use tray_impl::update_tooltip;
