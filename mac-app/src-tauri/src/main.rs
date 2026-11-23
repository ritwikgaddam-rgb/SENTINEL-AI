#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;
mod messages;
mod monitor;

fn main() {
    let api = backend::LocalApi::new().expect("Could not initialize the local API client");
    tauri::Builder::default()
        .manage(api)
        .manage(monitor::Monitor::default())
        .invoke_handler(tauri::generate_handler![
            backend::backend_health,
            backend::backend_history,
            backend::scan_url,
            backend::scan_email,
            messages::check_messages_access,
            messages::open_privacy_settings,
            monitor::start_monitoring,
            monitor::pause_monitoring,
            monitor::resume_monitoring,
            monitor::stop_monitoring,
            monitor::monitoring_status,
            monitor::message_scan_history,
            monitor::message_history_summary,
            monitor::clear_message_scan_history,
        ])
        .run(tauri::generate_context!())
        .expect("Could not start SentinelAI");
}
