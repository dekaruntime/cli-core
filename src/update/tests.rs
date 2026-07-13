use std::{cell::RefCell, fs, io::Cursor, time::Duration};

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Timelike as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::*;

const RELEASE_KEY_ID: &str = "harar-release-test";
const FRESHNESS_KEY_ID: &str = "harar-freshness-test";
const MANIFEST_DOMAIN: &[u8] = b"tana.release-manifest.v1\n";
const ARTIFACT_DOMAIN: &[u8] = b"tana.release-artifact.v1\n";
const LATEST_DOMAIN: &[u8] = b"tana.latest-statement.v1\n";

struct Harness {
    root: TempDir,
    release_key: SigningKey,
    freshness_key: SigningKey,
}

impl Harness {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            release_key: SigningKey::from_bytes(&[7; 32]),
            freshness_key: SigningKey::from_bytes(&[9; 32]),
        }
    }

    fn install_path(&self) -> std::path::PathBuf {
        self.root.path().join("bin/deka")
    }

    fn trust(&self) -> TrustStore {
        TrustStore::with_test_keys(
            self.root.path().join("trust"),
            RELEASE_KEY_ID,
            self.release_key.verifying_key(),
            FRESHNESS_KEY_ID,
            self.freshness_key.verifying_key(),
        )
        .unwrap()
    }

    fn request(&self, selector: VersionSelector) -> UpdateRequest {
        UpdateRequest {
            name: CliName::new("deka").unwrap(),
            channel: ReleaseChannel::Stable,
            target: TargetTriple::new("x86_64-unknown-linux-musl").unwrap(),
            selector,
            install_path: self.install_path(),
        }
    }

    fn release(&self, version: &str, counter: u64, marker: &str) -> MockTransport {
        let exit_code = usize::from(marker == "unhealthy");
        let binary = format!("#!/bin/sh\n# {marker}\nexit {exit_code}\n").into_bytes();
        let artifact = zstd::stream::encode_all(Cursor::new(&binary), 7).unwrap();
        let artifact_name = format!("deka-{version}-x86_64-unknown-linux-musl.zst");
        let manifest = serde_json::to_vec(&json!({
            "schema": "tana.release-manifest.v1",
            "algorithm": "ed25519",
            "key_id": RELEASE_KEY_ID,
            "promotion_id": format!("prm_{version}"),
            "name": "deka",
            "channel": "stable",
            "version": version,
            "platform": "x86_64-unknown-linux-musl",
            "artifact": artifact_name,
            "compression": "zstd-single-file",
            "artifact_size": artifact.len(),
            "artifact_sha256": hex_sha(&artifact),
            "binary_size": binary.len(),
            "binary_sha256": hex_sha(&binary),
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
        let issued = Utc::now()
            .with_nanosecond(0)
            .unwrap()
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        let expires = (DateTime::parse_from_rfc3339(&issued)
            .unwrap()
            .with_timezone(&Utc)
            + ChronoDuration::hours(72))
        .to_rfc3339_opts(SecondsFormat::Secs, true);
        let latest = serde_json::to_vec(&json!({
            "schema": "tana.latest-statement.v1",
            "algorithm": "ed25519",
            "key_id": FRESHNESS_KEY_ID,
            "name": "deka",
            "channel": "stable",
            "platform": "x86_64-unknown-linux-musl",
            "version": version,
            "manifest": "release-manifest.json",
            "manifest_size": manifest.len(),
            "manifest_sha256": hex_sha(&manifest),
            "counter": counter,
            "issued_at": issued,
            "expires_at": expires
        }))
        .unwrap();
        MockTransport::new(
            latest.clone(),
            sign(&self.freshness_key, LATEST_DOMAIN, &latest),
            manifest.clone(),
            sign(&self.release_key, MANIFEST_DOMAIN, &manifest),
            artifact.clone(),
            sign(&self.release_key, ARTIFACT_DOMAIN, &artifact),
        )
    }
}

#[derive(Default)]
struct FetchCounts {
    latest: usize,
    latest_sig: usize,
    manifest: usize,
    manifest_sig: usize,
    artifact: usize,
    artifact_sig: usize,
}

struct MockTransport {
    latest: Vec<u8>,
    latest_sig: Vec<u8>,
    manifest: Vec<u8>,
    manifest_sig: Vec<u8>,
    artifact: Vec<u8>,
    artifact_sig: Vec<u8>,
    counts: RefCell<FetchCounts>,
    panic_on_fetch: bool,
}

impl MockTransport {
    fn new(
        latest: Vec<u8>,
        latest_sig: Vec<u8>,
        manifest: Vec<u8>,
        manifest_sig: Vec<u8>,
        artifact: Vec<u8>,
        artifact_sig: Vec<u8>,
    ) -> Self {
        Self {
            latest,
            latest_sig,
            manifest,
            manifest_sig,
            artifact,
            artifact_sig,
            counts: RefCell::new(FetchCounts::default()),
            panic_on_fetch: false,
        }
    }

    fn no_network() -> Self {
        Self {
            latest: vec![],
            latest_sig: vec![],
            manifest: vec![],
            manifest_sig: vec![],
            artifact: vec![],
            artifact_sig: vec![],
            counts: RefCell::new(FetchCounts::default()),
            panic_on_fetch: true,
        }
    }

    fn fetched_once(&self) -> bool {
        let counts = self.counts.borrow();
        [
            counts.latest,
            counts.latest_sig,
            counts.manifest,
            counts.manifest_sig,
            counts.artifact,
            counts.artifact_sig,
        ] == [1; 6]
    }

    fn fetched(&self, bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        assert!(!self.panic_on_fetch, "rollback attempted a network fetch");
        Ok(bytes.to_vec())
    }
}

impl ReleaseTransport for MockTransport {
    fn fetch_latest_statement(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().latest += 1;
        self.fetched(&self.latest)
    }

    fn fetch_latest_signature(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().latest_sig += 1;
        self.fetched(&self.latest_sig)
    }

    fn fetch_manifest(
        &self,
        _: ReleaseCoordinates<'_>,
        _: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().manifest += 1;
        self.fetched(&self.manifest)
    }

    fn fetch_manifest_signature(
        &self,
        _: ReleaseCoordinates<'_>,
    ) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().manifest_sig += 1;
        self.fetched(&self.manifest_sig)
    }

    fn fetch_artifact(
        &self,
        _: ReleaseCoordinates<'_>,
        _: &str,
        _: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().artifact += 1;
        self.fetched(&self.artifact)
    }

    fn fetch_artifact_signature(
        &self,
        _: ReleaseCoordinates<'_>,
        _: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.counts.borrow_mut().artifact_sig += 1;
        self.fetched(&self.artifact_sig)
    }
}

#[test]
fn valid_release_installs_exact_fetched_bytes_once() {
    let harness = Harness::new();
    let transport = harness.release("1.8.0", 1, "valid");
    let expected_binary = decode(&transport.artifact);
    let mut trust = harness.trust();
    let installed = verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &transport,
        &AtomicInstaller::new(Duration::from_secs(2)).unwrap(),
        &mut trust,
    )
    .unwrap();
    assert_eq!(fs::read(harness.install_path()).unwrap(), expected_binary);
    assert_eq!(installed.version().to_string(), "1.8.0");
    assert!(transport.fetched_once());
}

#[test]
fn tampered_artifact_is_rejected_and_never_installed() {
    let harness = Harness::new();
    let mut transport = harness.release("1.8.0", 1, "tamper");
    transport.artifact[3] ^= 0x80;
    let mut trust = harness.trust();
    let error = verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &transport,
        &AtomicInstaller::default(),
        &mut trust,
    )
    .unwrap_err();
    assert!(matches!(error, UpdateError::Digest(_)));
    assert!(!harness.install_path().exists());
}

#[test]
fn wrong_signature_is_rejected_and_never_installed() {
    let harness = Harness::new();
    let mut transport = harness.release("1.8.0", 1, "wrong-signature");
    transport.artifact_sig = vec![0x55; 64];
    let mut trust = harness.trust();
    let error = verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &transport,
        &AtomicInstaller::default(),
        &mut trust,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        UpdateError::BadSignature("release artifact")
    ));
    assert!(!harness.install_path().exists());
}

#[test]
fn downgrade_is_rejected_before_artifact_fetch() {
    let harness = Harness::new();
    let installer = AtomicInstaller::default();
    let mut trust = harness.trust();
    let current = harness.release("2.0.0", 2, "current");
    verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: true,
        }),
        &current,
        &installer,
        &mut trust,
    )
    .unwrap();

    let downgrade = harness.release("1.9.9", 3, "downgrade");
    let error = verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: true,
        }),
        &downgrade,
        &installer,
        &mut trust,
    )
    .unwrap_err();
    assert!(matches!(error, UpdateError::Freshness(_)));
    let counts = downgrade.counts.borrow();
    assert_eq!(counts.manifest, 0);
    assert_eq!(counts.artifact, 0);
}

#[test]
fn explicit_rollback_restores_verified_previous_without_network() {
    let harness = Harness::new();
    let installer = AtomicInstaller::default();
    let mut trust = harness.trust();
    let first = harness.release("1.8.0", 1, "first");
    let first_binary = decode(&first.artifact);
    verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &first,
        &installer,
        &mut trust,
    )
    .unwrap();
    let second = harness.release("1.9.0", 2, "second");
    verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &second,
        &installer,
        &mut trust,
    )
    .unwrap();

    let rolled_back = verify_and_install(
        harness.request(VersionSelector::Rollback),
        &MockTransport::no_network(),
        &installer,
        &mut trust,
    )
    .unwrap();
    assert!(rolled_back.rolled_back());
    assert_eq!(rolled_back.version().to_string(), "1.8.0");
    assert_eq!(fs::read(harness.install_path()).unwrap(), first_binary);
}

#[test]
fn failed_health_check_atomically_restores_verified_previous() {
    let harness = Harness::new();
    let installer = AtomicInstaller::default();
    let mut trust = harness.trust();
    let first = harness.release("1.8.0", 1, "healthy");
    let first_binary = decode(&first.artifact);
    verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &first,
        &installer,
        &mut trust,
    )
    .unwrap();
    let unhealthy = harness.release("1.9.0", 2, "unhealthy");
    let error = verify_and_install(
        harness.request(VersionSelector::Latest {
            allow_major_upgrade: false,
        }),
        &unhealthy,
        &installer,
        &mut trust,
    )
    .unwrap_err();
    assert!(matches!(error, UpdateError::Health(_)));
    assert_eq!(fs::read(harness.install_path()).unwrap(), first_binary);
}

fn sign(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    key.sign(&input).to_bytes().to_vec()
}

fn hex_sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode(artifact: &[u8]) -> Vec<u8> {
    zstd::stream::decode_all(Cursor::new(artifact)).unwrap()
}
