use std::{fs, path::Path};

use semver::Version;
use tempfile::TempDir;

use super::*;
use crate::{CliName, ReleaseChannel, TargetTriple, VersionSelector};

#[test]
fn pre_swap_recovery_keeps_current_and_never_restores_stale_prev() {
    let root = tempfile::tempdir().unwrap();
    let request = request(
        &root,
        VersionSelector::Latest {
            allow_major_upgrade: false,
        },
    );
    let paths = setup(&request);
    let current = receipt("2.0.0", healthy_binary("current"), 2);
    write_executable(&request.install_path, healthy_binary("current"));
    atomic_private_write(
        &paths.state_dir,
        paths.current_receipt_name(),
        &serde_json::to_vec(&current).unwrap(),
    )
    .unwrap();

    let stale = receipt("1.0.0", healthy_binary("stale"), 1);
    write_executable(&paths.previous_binary, healthy_binary("stale"));
    atomic_private_write(
        &paths.state_dir,
        paths.previous_receipt_name(),
        &serde_json::to_vec(&stale).unwrap(),
    )
    .unwrap();
    write_executable(&paths.transition_previous, healthy_binary("current"));
    let candidate = receipt("3.0.0", healthy_binary("candidate"), 3);
    let transition = PendingTransition::new(TransitionKind::Update, candidate, Some(current));
    atomic_private_write(
        &paths.state_dir,
        paths.pending_receipt_name(),
        &serde_json::to_vec(&transition).unwrap(),
    )
    .unwrap();

    assert!(AtomicInstaller::default()
        .recover(&request)
        .unwrap()
        .is_none());
    assert_eq!(
        fs::read(&request.install_path).unwrap(),
        healthy_binary("current")
    );
    assert_eq!(
        fs::read(&paths.previous_binary).unwrap(),
        healthy_binary("stale")
    );
    assert!(!paths.pending_receipt.exists());
    assert!(!paths.transition_previous.exists());
}

#[test]
fn post_swap_unhealthy_recovery_restores_only_transition_receipt_bytes() {
    let root = tempfile::tempdir().unwrap();
    let request = request(
        &root,
        VersionSelector::Latest {
            allow_major_upgrade: false,
        },
    );
    let paths = setup(&request);
    let previous = receipt("2.0.0", healthy_binary("previous"), 2);
    write_executable(&paths.transition_previous, healthy_binary("previous"));
    let candidate_bytes = unhealthy_binary("candidate");
    let candidate = receipt("3.0.0", &candidate_bytes, 3);
    write_executable(&request.install_path, &candidate_bytes);
    let transition =
        PendingTransition::new(TransitionKind::Update, candidate, Some(previous.clone()));
    atomic_private_write(
        &paths.state_dir,
        paths.pending_receipt_name(),
        &serde_json::to_vec(&transition).unwrap(),
    )
    .unwrap();

    assert!(AtomicInstaller::default()
        .recover(&request)
        .unwrap()
        .is_none());
    assert_eq!(
        fs::read(&request.install_path).unwrap(),
        healthy_binary("previous")
    );
    assert!(verified_file(&request.install_path, &previous).unwrap());
    assert!(!paths.pending_receipt.exists());
    let quarantine = paths.state_dir.join("failed-candidate.bin");
    assert_eq!(fs::read(quarantine).unwrap(), candidate_bytes);
}

fn setup(request: &UpdateRequest) -> InstallPaths {
    fs::create_dir_all(request.install_path.parent().unwrap()).unwrap();
    let paths = InstallPaths::new(request).unwrap();
    ensure_private_state_dir(&paths.state_dir).unwrap();
    paths
}

fn request(root: &TempDir, selector: VersionSelector) -> UpdateRequest {
    UpdateRequest {
        name: CliName::new("deka").unwrap(),
        channel: ReleaseChannel::Stable,
        target: TargetTriple::new("x86_64-unknown-linux-musl").unwrap(),
        selector,
        install_path: root.path().join("bin/deka"),
        state_dir: None,
    }
}

fn receipt(version: &str, binary: &[u8], counter: u64) -> Receipt {
    Receipt {
        schema: "tana.install-receipt.v1".into(),
        name: "deka".into(),
        channel: "stable".into(),
        platform: "x86_64-unknown-linux-musl".into(),
        version: Version::parse(version).unwrap(),
        binary_sha256: sha256_hex(binary),
        artifact_sha256: "a".repeat(64),
        release_key_id: "release-test".into(),
        freshness_key_id: Some("freshness-test".into()),
        anchor_generation: counter,
        latest_counter: Some(counter),
        latest_statement_sha256: Some("b".repeat(64)),
        promotion_id: format!("prm_{counter}"),
    }
}

fn healthy_binary(marker: &str) -> &'static [u8] {
    match marker {
        "current" => b"#!/bin/sh\n# current\nexit 0\n",
        "stale" => b"#!/bin/sh\n# stale\nexit 0\n",
        "previous" => b"#!/bin/sh\n# previous\nexit 0\n",
        "candidate" => b"#!/bin/sh\n# candidate\nexit 0\n",
        _ => unreachable!(),
    }
}

fn unhealthy_binary(_: &str) -> Vec<u8> {
    b"#!/bin/sh\n# unhealthy candidate\nexit 1\n".to_vec()
}

fn write_executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
