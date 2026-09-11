#![cfg(unix)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Mutex, OnceLock},
    thread,
};

use deka_cli_core::{CliPaths, HealthProbe, HealthStatus, MonitorReport, ProductSpec, SharedCli};

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn shared(root: &std::path::Path) -> SharedCli {
    SharedCli::with_paths(
        ProductSpec::new(
            "linkhash",
            "1.0.0",
            "https://linkha.sh",
            HealthProbe::argv(&["--self-test"]),
        )
        .unwrap(),
        CliPaths {
            bin_dir: root.join("bin"),
            config_dir: root.join("config"),
            state_dir: root.join("state"),
        },
    )
}

fn report() -> MonitorReport {
    MonitorReport {
        name: "linkhash".into(),
        installed_version: semver::Version::parse("1.0.0").unwrap(),
        installed_digest: "a".repeat(64),
        latest_version: Some(semver::Version::parse("1.0.1").unwrap()),
        update_available: true,
        health: HealthStatus::Healthy,
        key_id: "harar-release-2026".into(),
        anchor_generation: 7,
        checked_at: chrono::Utc::now(),
    }
}

#[test]
fn ruba_bearer_rejects_cleartext_non_loopback_origins() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("RUBA_URL", "http://example.com");
    std::env::set_var("RUBA_SOURCE_TOKEN", "must-not-be-sent");
    let error = shared(temp.path())
        .emit_monitor_report(&report())
        .unwrap_err()
        .to_string();
    assert!(error.contains("HTTPS"), "{error}");
    std::env::remove_var("RUBA_URL");
    std::env::remove_var("RUBA_SOURCE_TOKEN");
}

#[test]
fn ruba_emission_rejects_redirects_without_following_them() {
    let _guard = env_lock();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://example.com/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    std::env::set_var("RUBA_URL", origin);
    std::env::set_var("RUBA_SOURCE_TOKEN", "redirect-secret");
    let error = shared(temp.path())
        .emit_monitor_report(&report())
        .unwrap_err()
        .to_string();
    assert!(error.contains("307"), "{error}");
    server.join().unwrap();
    std::env::remove_var("RUBA_URL");
    std::env::remove_var("RUBA_SOURCE_TOKEN");
}
