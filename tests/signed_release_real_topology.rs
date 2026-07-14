#![cfg(unix)]

use std::{
    env, fs,
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
    ReleaseCoordinates, ReleaseTransport, TargetTriple, TransportError, TrustStore, UpdateError,
    UpdateRequest, VersionSelector,
};

const ROOT_A_ID: &str = "harar-root-a";
const RELEASE_ID: &str = "topology-release-key";
const FRESHNESS_ID: &str = "topology-freshness-key";
const ANCHOR_DOMAIN: &[u8] = b"tana.anchor-set.v1\n";
const MANIFEST_DOMAIN: &[u8] = b"tana.release-manifest.v1\n";
const ARTIFACT_DOMAIN: &[u8] = b"tana.release-artifact.v1\n";
const LATEST_DOMAIN: &[u8] = b"tana.latest-statement.v1\n";

struct Fixture {
    root: tempfile::TempDir,
    server: Child,
    transport: LinkhashProducerTransport,
    artifact_path: PathBuf,
    expected_binary: Vec<u8>,
    root_key: ed25519_dalek::VerifyingKey,
    release_key: ed25519_dalek::VerifyingKey,
    freshness_key: ed25519_dalek::VerifyingKey,
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
            "roots": [root_entry(ROOT_A_ID, &root_a)],
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

        let store_path = root.path().join("store");
        let data_path = root.path().join("data");
        let config_path = data_path.join("config/linkhash.toml");
        initialize_linkhash(&store_path, &data_path, &config_path);
        let releases_path = root.path().join("releases");
        let immutable =
            releases_path.join("production/deka/stable/1.8.0/x86_64-unknown-linux-musl");
        write(&immutable, "release-manifest.json", &manifest);
        write(
            &immutable,
            "release-manifest.sig",
            &sign(&release, MANIFEST_DOMAIN, &manifest),
        );
        let artifact_path = immutable.join(artifact_name);
        write(&immutable, artifact_name, &artifact);
        write(
            &immutable,
            &format!("{artifact_name}.sig"),
            &sign(&release, ARTIFACT_DOMAIN, &artifact),
        );
        let latest_dir = releases_path.join("latest/deka/stable/x86_64-unknown-linux-musl/1");
        write(&latest_dir, "latest.json", &latest);
        write(
            &latest_dir,
            "latest.sig",
            &sign(&freshness, LATEST_DOMAIN, &latest),
        );
        write(
            &releases_path.join("latest/deka/stable/x86_64-unknown-linux-musl"),
            "current",
            b"1",
        );

        let linkhash_anchor = serde_json::to_vec(&json!({
            "schema": "tana.anchor-set.v1",
            "generation": 1,
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:00:00Z",
            "threshold": 1,
            "roots": [root_entry(ROOT_A_ID, &root_a)],
            "keys": [
                key_entry("release", RELEASE_ID, &release),
                key_entry("freshness", FRESHNESS_ID, &freshness)
            ]
        }))
        .unwrap();
        let linkhash_anchor_path = root.path().join("linkhash-anchor.json");
        let linkhash_anchor_sig_path = root.path().join("linkhash-anchor.sig");
        fs::write(&linkhash_anchor_path, &linkhash_anchor).unwrap();
        fs::write(&linkhash_anchor_sig_path, serde_json::to_vec(&json!({
            "schema": "tana.anchor-signatures.v1",
            "signatures": [{
                "key_id": ROOT_A_ID,
                "algorithm": "ed25519",
                "signature_base64": BASE64.encode(sign(&root_a, ANCHOR_DOMAIN, &linkhash_anchor))
            }]
        })).unwrap()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let origin = format!("http://127.0.0.1:{port}");
        let server = Command::new(linkhash_binary())
            .args(["start", "api", "--bind", &format!("127.0.0.1:{port}")])
            .env("LINKHASH_STORE_PATH", &store_path)
            .env("LINKHASH_AUTH_SECRET", "real-topology-auth-secret-32-bytes")
            .env("LINKHASH_AUTH_ISSUER", "real-topology")
            .env("LINKHASH_AUTH_AUDIENCE", "linkhash")
            .env("LINKHASH_RELEASE_STORAGE_PATH", &releases_path)
            .env("LINKHASH_RELEASE_HARAR_URL", &origin)
            .env("LINKHASH_RELEASE_TRANSPARENCY_URL", &origin)
            .env("LINKHASH_RELEASE_INTERNAL_URL", &origin)
            .env(
                "HARAR_RELEASE_PUBLIC_KEYS",
                json!({RELEASE_ID: BASE64.encode(release.verifying_key().as_bytes())}).to_string(),
            )
            .env(
                "HARAR_FRESHNESS_PUBLIC_KEYS",
                json!({FRESHNESS_ID: BASE64.encode(freshness.verifying_key().as_bytes())})
                    .to_string(),
            )
            .env("LINKHASH_RELEASE_ANCHOR_SET_PATH", &linkhash_anchor_path)
            .env(
                "LINKHASH_RELEASE_ANCHOR_SET_SIGNATURE_PATH",
                &linkhash_anchor_sig_path,
            )
            .env(
                "TANA_RELEASE_TEST_ROOT_PUBLIC_KEY",
                BASE64.encode(root_a.verifying_key().as_bytes()),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the real Linkhash API binary");
        wait_ready(&origin);
        let transport = LinkhashProducerTransport {
            http: HttpReleaseTransport::new(&origin, Duration::from_secs(3)).unwrap(),
            anchor_set,
            anchor_signatures,
        };
        Self {
            root,
            server,
            transport,
            artifact_path,
            expected_binary: binary,
            root_key: root_a.verifying_key(),
            release_key: release.verifying_key(),
            freshness_key: freshness.verifying_key(),
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
            state_dir: None,
        }
    }

    fn trust(&self, suffix: &str) -> TrustStore {
        TrustStore::with_testing_keys(
            self.root.path().join(suffix),
            ROOT_A_ID,
            self.root_key,
            RELEASE_ID,
            self.release_key,
            FRESHNESS_ID,
            self.freshness_key,
        )
        .unwrap()
    }
}

struct LinkhashProducerTransport {
    http: HttpReleaseTransport,
    anchor_set: Vec<u8>,
    anchor_signatures: Vec<u8>,
}

impl ReleaseTransport for LinkhashProducerTransport {
    fn fetch_anchor_set(&self, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        bounded_clone(&self.anchor_set, max_bytes)
    }

    fn fetch_anchor_signatures(&self, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        bounded_clone(&self.anchor_signatures, max_bytes)
    }

    fn fetch_latest_statement(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.http
            .fetch_latest_statement(name, channel, platform, max_bytes)
    }

    fn fetch_latest_signature(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.http.fetch_latest_signature(name, channel, platform)
    }

    fn fetch_manifest(
        &self,
        release: ReleaseCoordinates<'_>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.http.fetch_manifest(release, max_bytes)
    }

    fn fetch_manifest_signature(
        &self,
        release: ReleaseCoordinates<'_>,
    ) -> Result<Vec<u8>, TransportError> {
        self.http.fetch_manifest_signature(release)
    }

    fn fetch_artifact(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.http.fetch_artifact(release, artifact, max_bytes)
    }

    fn fetch_artifact_signature(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.http.fetch_artifact_signature(release, artifact)
    }
}

#[test]
#[ignore = "requires LINKHASH_REAL_BINARY built from the signed-release producer branch"]
fn client_verifies_real_linkhash_producer_across_process_boundary() {
    let fixture = Fixture::start();
    let request = fixture.request("valid");
    let install_path = request.install_path.clone();
    let mut trust = fixture.trust("trust-valid");
    let installed = verify_and_install(
        request,
        &fixture.transport,
        &AtomicInstaller::default(),
        &mut trust,
    )
    .unwrap();
    assert_eq!(installed.version().to_string(), "1.8.0");
    assert_eq!(fs::read(install_path).unwrap(), fixture.expected_binary);
}

#[test]
#[ignore = "requires LINKHASH_REAL_BINARY built from the signed-release producer branch"]
fn real_linkhash_process_artifact_tamper_never_reaches_install_path() {
    let fixture = Fixture::start();
    let mut tampered = fs::read(&fixture.artifact_path).unwrap();
    tampered[2] ^= 0x80;
    fs::write(&fixture.artifact_path, tampered).unwrap();
    let request = fixture.request("tampered");
    let install_path = request.install_path.clone();
    let mut trust = fixture.trust("trust-tampered");
    let error = verify_and_install(
        request,
        &fixture.transport,
        &AtomicInstaller::default(),
        &mut trust,
    )
    .unwrap_err();
    assert!(matches!(error, UpdateError::Digest(_)));
    assert!(!install_path.exists());
}

fn initialize_linkhash(store: &Path, data: &Path, config: &Path) {
    let status = Command::new(linkhash_binary())
        .args(["server", "init"])
        .env("LINKHASH_STORE_PATH", store)
        .env("LINKHASH_DATA_DIR", data)
        .env("LINKHASH_CONFIG_PATH", config)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("run the real Linkhash store initializer");
    assert!(status.success(), "Linkhash store initialization failed");
}

fn linkhash_binary() -> PathBuf {
    env::var_os("LINKHASH_REAL_BINARY")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .expect("LINKHASH_REAL_BINARY must name the real linkhash binary from producer PR #136")
}

fn bounded_clone(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>, TransportError> {
    if bytes.len() > max_bytes {
        return Err(TransportError::new("release response exceeds byte limit"));
    }
    Ok(bytes.to_vec())
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
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if reqwest::blocking::get(format!("{origin}/healthz")).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("real Linkhash producer did not become ready");
}
