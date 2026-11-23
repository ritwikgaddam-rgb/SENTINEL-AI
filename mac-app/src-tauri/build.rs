fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "backend_health",
        "backend_history",
        "scan_url",
        "scan_email",
        "check_messages_access",
        "open_privacy_settings",
        "start_monitoring",
        "pause_monitoring",
        "resume_monitoring",
        "stop_monitoring",
        "monitoring_status",
        "message_scan_history",
        "message_history_summary",
        "clear_message_scan_history",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("Could not prepare the SentinelAI native app");
}
