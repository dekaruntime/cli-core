#![cfg(unix)]

use std::{
    fs,
    io::Cursor,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{Duration as ChronoDuration, SecondsFormat, Timelike as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tana_cli_core::{
    verify_and_install, AtomicInstaller, CliName, HttpReleaseTransport, ReleaseChannel,
    TargetTriple, TrustStore, UpdateError, UpdateRequest, VersionSelector,
};

const ROOT_A_ID: &str = "PLACEHOLDER-harar-root-a";
const ROOT_B_ID: &str = "PLACEHOLDER-harar-root-b";
const RELEASE_ID: &str = "topology-release-key";
const FRESHNESS_ID: &str = "topology-freshness-key";
const ANCHOR_DOMAIN: &[u8] = b"tana.anchor-set.v1\n";
const MANIFEST_DOMAIN: &[u8] = b"tana.release-manifest.v1\n";
const ARTIFACT_DOMAIN: &[u8] = b"tana.release-artifact.v1\n";
const LATEST_DOMAIN: &[u8] = b"tana.latest-statement.v1\n";

struct Fixture {
    root: tempfile::TempDir,
    server: Child,
    origin: String,
    artifact_path: PathBuf,
    expected_binary: Vec<u8>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

impl Fixture {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let release = SigningKey::from_bytes(&[31; 32]);
        let freshness = SigningKey::from_bytes(&[32; 32]);
        let root_a = SigningKey::from_bytes(&[11; 32]);
        let root_b = SigningKey::from_bytes(&[13; 32]);
        let binary = b"#!/bin/sh\n# real topology signed artifact\nexit 0\n".to_vec();
        let artifact = zstd::stream::encode_all(Cursor::new(&binary), 7).unwrap();
        let artifact_name = "deka-1.8.0-x86_64-unknown-linux-musl.zst";
        let manifest = serde_json::to_vec(&json!({
            "schema": "tana.release-manifest.v1",
            "algorithm": "ed25519",
            "key_id": RELEASE_ID,
            "promotion_id": "prm_real_topology",
            "name": "deka",
            "channel": "stable",
            "version": "1.8.0",
            "platform": "x86_64-unknown-linux-musl",
            "artifact": artifact_name,
            "compression": "zstd-single-file",
            "artifact_size": artifact.len(),
            "artifact_sha256": sha(&artifact),
            "binary_size": binary.len(),
            "binary_sha256": sha(&binary),
            "source_repo": "tana/deka",
            "source_git_sha": "a".repeat(40),
            "build_recipe_sha256": "b".repeat(64),
            "toolchain_digest": format!("sha256:{}", "c".repeat(64)),
            "provenance_digest": format!("sha256:{}", "d".repeat(64)),
            "builders": [
                {"builder_id":"gild-a","run_id":"run-a","attestation_sha256":"e".repeat(64)},
                {"builder_id":"gild-b","run_id":"run-b","attestation_sha256":"f".repeat(64)}
            ],
            "promoted_at": "2026-07-13T12:00:00Z"
        }))
        .unwrap();
        let issued = Utc::now().with_nanosecond(0).unwrap();
        let latest = serde_json::to_vec(&json!({
            "schema": "tana.latest-statement.v1",
            "algorithm": "ed25519",
            "key_id": FRESHNESS_ID,
            "name": "deka",
            "channel": "stable",
            "platform": "x86_64-unknown-linux-musl",
            "version": "1.8.0",
            "manifest": "release-manifest.json",
            "manifest_size": manifest.len(),
            "manifest_sha256": sha(&manifest),
            "counter": 1,
            "issued_at": issued.to_rfc3339_opts(SecondsFormat::Secs, true),
            "expires_at": (issued + ChronoDuration::hours(72)).to_rfc3339_opts(SecondsFormat::Secs, true)
        }))
        .unwrap();
        let anchor_set = serde_json::to_vec(&json!({
            "schema": "tana.anchor-set.v1",
            "generation": 2,
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "threshold": 1,
            "roots": [
                root_entry(ROOT_A_ID, &root_a),
                root_entry(ROOT_B_ID, &root_b)
            ],
            "keys": [
                key_entry("release", RELEASE_ID, &release),
                key_entry("freshness", FRESHNESS_ID, &freshness)
            ]
        }))
        .unwrap();
        let anchor_signatures = serde_json::to_vec(&json!({
            "schema": "tana.anchor-signatures.v1",
            "signatures": [{
                "key_id": ROOT_A_ID,
                "algorithm": "ed25519",
                "signature_base64": BASE64.encode(sign(&root_a, ANCHOR_DOMAIN, &anchor_set))
            }]
        }))
        .unwrap();

        write(
            root.path(),
            "api/v1/releases/trust/anchor-set.json",
            &anchor_set,
        );
        write(
            root.path(),
            "api/v1/releases/trust/anchor-set.sig",
            &anchor_signatures,
        );
        let live = "api/v1/releases/deka/stable/x86_64-unknown-linux-musl";
        write(root.path(), &format!("{live}/latest.json"), &latest);
        write(
            root.path(),
            &format!("{live}/latest.sig"),
            &sign(&freshness, LATEST_DOMAIN, &latest),
        );
        let immutable = "api/v1/releases/deka/stable/1.8.0/x86_64-unknown-linux-musl";
        write(
            root.path(),
            &format!("{immutable}/release-manifest.json"),
            &manifest,
        );
        write(
            root.path(),
            &format!("{immutable}/release-manifest.sig"),
            &sign(&release, MANIFEST_DOMAIN, &manifest),
        );
        let artifact_path = root.path().join(immutable).join(artifact_name);
        write(
            root.path(),
            &format!("{immutable}/{artifact_name}"),
            &artifact,
        );
        write(
            root.path(),
            &format!("{immutable}/{artifact_name}.sig"),
            &sign(&release, ARTIFACT_DOMAIN, &artifact),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let server = Command::new("python3")
            .args([
                "-m",
                "http.server",
                &port.to_string(),
                "--bind",
                "127.0.0.1",
                "--directory",
                root.path().to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let origin = format!("http://127.0.0.1:{port}");
        wait_ready(&origin);
        Self {
            root,
            server,
            origin,
            artifact_path,
            expected_binary: binary,
        }
    }

    fn request(&self, suffix: &str) -> UpdateRequest {
        UpdateRequest {
            name: CliName::new("deka").unwrap(),
            channel: ReleaseChannel::Stable,
            target: TargetTriple::new("x86_64-unknown-linux-musl").unwrap(),
            selector: VersionSelector::Latest {
                allow_major_upgrade: false,
            },
            install_path: self.root.path().join(format!("install/{suffix}/deka")),
        }
    }
}

#[test]
fn client_verifies_real_signed_artifact_across_http_process_boundary() {
    let fixture = Fixture::start();
    let request = fixture.request("valid");
    let install_path = request.install_path.clone();
    let transport = HttpReleaseTransport::new(&fixture.origin, Duration::from_secs(3)).unwrap();
    let mut trust = TrustStore::open(fixture.root.path().join("trust-valid")).unwrap();
    let installed =
        verify_and_install(request, &transport, &AtomicInstaller::default(), &mut trust).unwrap();
    assert_eq!(installed.version().to_string(), "1.8.0");
    assert_eq!(fs::read(install_path).unwrap(), fixture.expected_binary);
}

#[test]
fn process_boundary_artifact_tamper_never_reaches_install_path() {
    let fixture = Fixture::start();
    let mut tampered = fs::read(&fixture.artifact_path).unwrap();
    tampered[2] ^= 0x80;
    fs::write(&fixture.artifact_path, tampered).unwrap();
    let request = fixture.request("tampered");
    let install_path = request.install_path.clone();
    let transport = HttpReleaseTransport::new(&fixture.origin, Duration::from_secs(3)).unwrap();
    let mut trust = TrustStore::open(fixture.root.path().join("trust-tampered")).unwrap();
    let error = verify_and_install(request, &transport, &AtomicInstaller::default(), &mut trust)
        .unwrap_err();
    assert!(matches!(error, UpdateError::Digest(_)));
    assert!(!install_path.exists());
}

fn root_entry(id: &str, key: &SigningKey) -> serde_json::Value {
    let bytes = key.verifying_key().to_bytes();
    json!({
        "key_id": id,
        "public_key_base64": BASE64.encode(bytes),
        "fingerprint_sha256": sha(&bytes)
    })
}

fn key_entry(role: &str, id: &str, key: &SigningKey) -> serde_json::Value {
    json!({
        "role": role,
        "key_id": id,
        "public_key_base64": BASE64.encode(key.verifying_key().as_bytes()),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2030-01-01T00:00:00Z",
        "status": "active"
    })
}

fn sign(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    key.sign(&input).to_bytes().to_vec()
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn wait_ready(origin: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if reqwest::blocking::get(origin).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("real-topology fixture did not become ready");
}
