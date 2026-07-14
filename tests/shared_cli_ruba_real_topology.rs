#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use tana_cli_core::{CliPaths, HealthProbe, HealthStatus, MonitorReport, ProductSpec, SharedCli};

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
fn shared_cli_monitor_crosses_a_separate_ruba_process() {
    let _guard = env_lock();
    let temp = tempfile::tempdir().unwrap();
    let ready = temp.path().join("ready");
    let capture = temp.path().join("request");
    let mut peer = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ruba_peer_process", "--nocapture"])
        .env("TANA_RUBA_PEER_MODE", "1")
        .env("TANA_RUBA_PEER_READY", &ready)
        .env("TANA_RUBA_PEER_CAPTURE", &capture)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for_file(&ready);
    let origin = fs::read_to_string(&ready).unwrap();
    std::env::set_var("RUBA_URL", origin.trim());
    std::env::set_var("RUBA_SOURCE_TOKEN", "ruba-source-secret");

    shared(temp.path()).emit_monitor_report(&report()).unwrap();

    assert!(peer.wait().unwrap().success());
    let request = fs::read_to_string(capture).unwrap();
    assert!(request.starts_with("POST /v1/push HTTP/1.1"));
    assert!(request.contains("authorization: Bearer ruba-source-secret"));
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["source_id"], "cli.linkhash");
    assert_eq!(body["events"][0]["kind"], "cli.self.monitor");
    assert!(body["events"][0]["ts"].is_number());
    assert_eq!(body["events"][0]["payload"]["actor"], "cli.linkhash");
    assert_eq!(body["events"][0]["payload"]["name"], "linkhash");
    std::env::remove_var("RUBA_URL");
    std::env::remove_var("RUBA_SOURCE_TOKEN");
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
        let _ = read_request(&mut stream);
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

#[test]
fn ruba_peer_process() {
    if std::env::var_os("TANA_RUBA_PEER_MODE").is_none() {
        return;
    }
    let ready = std::env::var_os("TANA_RUBA_PEER_READY").unwrap();
    let capture = std::env::var_os("TANA_RUBA_PEER_CAPTURE").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    fs::write(&ready, format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let request = read_request(&mut stream);
    fs::write(capture, request).unwrap();
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
}

fn wait_for_file(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("separate Ruba process did not become ready");
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk).unwrap();
        bytes.extend_from_slice(&chunk[..count]);
        let text = String::from_utf8_lossy(&bytes);
        if let Some(header_end) = text.find("\r\n\r\n") {
            let content_length = text[..header_end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        assert_ne!(count, 0, "HTTP peer closed before request completed");
    }
    String::from_utf8(bytes).unwrap()
}
