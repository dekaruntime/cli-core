use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt as _;
use semver::Version;
use serde::{Deserialize, Serialize};

use super::{
    default_health_timeout, display_path,
    schema::{LatestStatement, ReleaseManifest},
    sha256_hex, sha256_reader,
    trust::atomic_private_write,
    CliName, InstalledRelease, UpdateError, UpdateRequest, VerifiedArtifact,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    schema: String,
    name: String,
    channel: String,
    platform: String,
    version: Version,
    binary_sha256: String,
    artifact_sha256: String,
    release_key_id: String,
    freshness_key_id: Option<String>,
    anchor_generation: u64,
    latest_counter: Option<u64>,
    latest_statement_sha256: Option<String>,
    promotion_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingTransition {
    schema: String,
    kind: TransitionKind,
    candidate: Receipt,
    previous: Option<Receipt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TransitionKind {
    Update,
    Rollback,
}

impl PendingTransition {
    fn new(kind: TransitionKind, candidate: Receipt, previous: Option<Receipt>) -> Self {
        Self {
            schema: "tana.install-transition.v1".into(),
            kind,
            candidate,
            previous,
        }
    }

    fn validate(&self, request: &UpdateRequest) -> Result<(), UpdateError> {
        if self.schema != "tana.install-transition.v1"
            || !self.candidate.matches_request(request)
            || self
                .previous
                .as_ref()
                .is_some_and(|receipt| !receipt.matches_request(request))
        {
            return Err(UpdateError::Freshness(
                "pending transition identity/schema is invalid".into(),
            ));
        }
        if self.kind == TransitionKind::Update {
            let Some(previous) = &self.previous else {
                return Ok(());
            };
            if self.candidate.anchor_generation < previous.anchor_generation
                || matches!(
                    (self.candidate.latest_counter, previous.latest_counter),
                    (Some(candidate), Some(prior)) if candidate < prior
                )
            {
                return Err(UpdateError::Freshness(
                    "pending transition lowers trust generation/counter".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Receipt {
    pub(super) fn new(
        request: &UpdateRequest,
        manifest: &ReleaseManifest,
        latest: Option<&(LatestStatement, Vec<u8>)>,
        anchor_generation: u64,
    ) -> Self {
        Self {
            schema: "tana.install-receipt.v1".into(),
            name: request.name.as_str().into(),
            channel: request.channel.as_str().into(),
            platform: request.target.as_str().into(),
            version: Version::parse(&manifest_version(manifest))
                .expect("validated manifest version remains SemVer"),
            binary_sha256: manifest.binary_sha256.clone(),
            artifact_sha256: manifest.artifact_sha256.clone(),
            release_key_id: manifest.key_id.clone(),
            freshness_key_id: latest.map(|(statement, _)| statement.key_id.clone()),
            anchor_generation,
            latest_counter: latest.map(|(statement, _)| statement.counter),
            latest_statement_sha256: latest.map(|(_, bytes)| sha256_hex(bytes)),
            promotion_id: manifest.promotion_id.clone(),
        }
    }

    fn installed(&self, rolled_back: bool) -> InstalledRelease {
        InstalledRelease {
            name: self.name.clone(),
            channel: self.channel.clone(),
            platform: self.platform.clone(),
            version: self.version.clone(),
            binary_sha256: self.binary_sha256.clone(),
            artifact_sha256: self.artifact_sha256.clone(),
            promotion_id: self.promotion_id.clone(),
            rolled_back,
        }
    }

    fn matches_request(&self, request: &UpdateRequest) -> bool {
        self.name == request.name.as_str()
            && self.channel == request.channel.as_str()
            && self.platform == request.target.as_str()
    }
}

// Accessing the validated version through a private helper avoids exposing any
// manifest field outside the verification/install modules.
fn manifest_version(manifest: &ReleaseManifest) -> String {
    manifest.version_text.clone()
}

/// Atomic replacement policy. The actual install method is private and accepts
/// only the opaque [`VerifiedArtifact`] capability.
pub struct AtomicInstaller {
    health_timeout: Duration,
}

impl Default for AtomicInstaller {
    fn default() -> Self {
        Self {
            health_timeout: default_health_timeout(),
        }
    }
}

impl AtomicInstaller {
    pub fn new(health_timeout: Duration) -> Result<Self, UpdateError> {
        if health_timeout.is_zero() || health_timeout > Duration::from_secs(300) {
            return Err(UpdateError::InvalidRequest(
                "health timeout must be between 1ns and 300 seconds".into(),
            ));
        }
        Ok(Self { health_timeout })
    }

    pub(super) fn recover(
        &self,
        request: &UpdateRequest,
    ) -> Result<Option<InstalledRelease>, UpdateError> {
        let paths = InstallPaths::new(&request.install_path)?;
        let Some(pending) = read_optional_transition(&paths.pending_receipt)? else {
            return Ok(None);
        };
        pending.validate(request)?;
        if verified_file(&request.install_path, &pending.candidate)?
            && self.health_check(&request.install_path).is_ok()
        {
            self.finalize_transition(&paths, &pending)?;
            return Ok(Some(
                pending
                    .candidate
                    .installed(pending.kind == TransitionKind::Rollback),
            ));
        }
        if let Some(previous) = &pending.previous {
            if verified_file(&request.install_path, previous)? {
                // The process stopped before the swap. The official path is
                // still the locally receipted current generation.
                self.discard_transition(&paths)?;
                return Ok(None);
            }
        }
        self.reject_candidate(&paths, &request.install_path, &pending)?;
        append_receipt(&paths.failed_log, &pending.candidate)?;
        Ok(None)
    }

    /// Private by construction: no caller outside this module can invoke the
    /// swap, and its only argument is the verified capability.
    pub(super) fn install(
        &self,
        artifact: VerifiedArtifact,
    ) -> Result<InstalledRelease, UpdateError> {
        let (staged, install_path, receipt) = artifact.into_parts();
        let paths = InstallPaths::new(&install_path)?;
        ensure_private_state_dir(&paths.state_dir)?;
        reject_symlink(&install_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            staged
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        staged.as_file().sync_all()?;

        let previous = self.stage_current(&paths, &install_path)?;
        let transition = PendingTransition::new(TransitionKind::Update, receipt.clone(), previous);
        atomic_private_write(
            &paths.state_dir,
            paths.pending_receipt_name(),
            &serde_json::to_vec(&transition)?,
        )?;
        sync_directory(&paths.parent)?;

        staged
            .persist(&install_path)
            .map_err(|error| UpdateError::Io(error.error))?;
        sync_directory(&paths.parent)?;

        if let Err(error) = self.health_check(&install_path) {
            self.reject_candidate(&paths, &install_path, &transition)?;
            append_receipt(&paths.failed_log, &receipt)?;
            return Err(UpdateError::Health(error));
        }
        self.finalize_transition(&paths, &transition)?;
        Ok(receipt.installed(false))
    }

    pub(super) fn rollback(
        &self,
        request: &UpdateRequest,
    ) -> Result<InstalledRelease, UpdateError> {
        let install_path = &request.install_path;
        let paths = InstallPaths::new(install_path)?;
        let previous = read_optional_receipt(&paths.previous_receipt)?
            .ok_or_else(|| UpdateError::Rollback("no retained previous receipt".into()))?;
        let current = read_optional_receipt(&paths.current_receipt)?
            .ok_or_else(|| UpdateError::Rollback("current receipt is missing".into()))?;
        if !previous.matches_request(request) || !current.matches_request(request) {
            return Err(UpdateError::Rollback(
                "retained receipt identity differs from rollback request".into(),
            ));
        }
        if !verified_file(&paths.previous_binary, &previous)?
            || !verified_file(install_path, &current)?
        {
            return Err(UpdateError::Rollback(
                "current or previous binary failed receipt verification".into(),
            ));
        }

        remove_if_exists(&paths.rollback_candidate)?;
        link_or_verified_copy(
            &paths.previous_binary,
            &paths.rollback_candidate,
            &previous.binary_sha256,
        )?;
        let staged_current = self.stage_current(&paths, install_path)?;
        if staged_current.as_ref() != Some(&current) {
            return Err(UpdateError::Rollback(
                "current receipt changed while staging rollback".into(),
            ));
        }
        let transition =
            PendingTransition::new(TransitionKind::Rollback, previous.clone(), Some(current));
        atomic_private_write(
            &paths.state_dir,
            paths.pending_receipt_name(),
            &serde_json::to_vec(&transition)?,
        )?;
        fs::rename(&paths.rollback_candidate, install_path)?;
        sync_directory(&paths.parent)?;

        if let Err(error) = self.health_check(install_path) {
            self.reject_candidate(&paths, install_path, &transition)?;
            append_receipt(&paths.failed_log, &previous)?;
            return Err(UpdateError::Health(format!(
                "rollback target failed self-test: {error}"
            )));
        }
        self.finalize_transition(&paths, &transition)?;
        Ok(previous.installed(true))
    }

    fn stage_current(
        &self,
        paths: &InstallPaths,
        install_path: &Path,
    ) -> Result<Option<Receipt>, UpdateError> {
        remove_if_exists(&paths.transition_previous)?;
        if !install_path.exists() {
            return Ok(None);
        }
        let current = read_optional_receipt(&paths.current_receipt)?.ok_or_else(|| {
            UpdateError::Digest(format!(
                "refusing to replace {} without a verified current receipt",
                display_path(install_path)
            ))
        })?;
        if !verified_file(install_path, &current)? {
            return Err(UpdateError::Digest(
                "current installation differs from its verified receipt".into(),
            ));
        }
        link_or_verified_copy(
            install_path,
            &paths.transition_previous,
            &current.binary_sha256,
        )?;
        sync_directory(&paths.parent)?;
        Ok(Some(current))
    }

    fn reject_candidate(
        &self,
        paths: &InstallPaths,
        install_path: &Path,
        transition: &PendingTransition,
    ) -> Result<(), UpdateError> {
        if let Some(previous) = &transition.previous {
            let (recovery_path, consumed_previous_slot) =
                if verified_file(&paths.transition_previous, previous)? {
                    (&paths.transition_previous, false)
                } else if verified_file(&paths.previous_binary, previous)? {
                    (&paths.previous_binary, true)
                } else {
                    // Even with corrupt recovery material, never leave the rejected
                    // candidate at the official executable path.
                    quarantine_candidate(paths, install_path)?;
                    return Err(UpdateError::Rollback(
                        "transition previous binary differs from its receipt".into(),
                    ));
                };
            quarantine_candidate(paths, install_path)?;
            fs::rename(recovery_path, install_path)?;
            if consumed_previous_slot {
                remove_if_exists(&paths.previous_receipt)?;
            }
            atomic_private_write(
                &paths.state_dir,
                paths.current_receipt_name(),
                &serde_json::to_vec(previous)?,
            )?;
        } else {
            quarantine_candidate(paths, install_path)?;
            remove_if_exists(&paths.current_receipt)?;
        }
        remove_if_exists(&paths.pending_receipt)?;
        remove_if_exists(&paths.rollback_candidate)?;
        sync_directory(&paths.parent)?;
        sync_directory(&paths.state_dir)?;
        Ok(())
    }

    fn finalize_transition(
        &self,
        paths: &InstallPaths,
        transition: &PendingTransition,
    ) -> Result<(), UpdateError> {
        if let Some(previous) = &transition.previous {
            if verified_file(&paths.transition_previous, previous)? {
                fs::rename(&paths.transition_previous, &paths.previous_binary)?;
            } else if !verified_file(&paths.previous_binary, previous)? {
                return Err(UpdateError::Rollback(
                    "cannot receipt an unverified previous generation".into(),
                ));
            }
            atomic_private_write(
                &paths.state_dir,
                paths.previous_receipt_name(),
                &serde_json::to_vec(previous)?,
            )?;
        } else {
            remove_if_exists(&paths.previous_binary)?;
            remove_if_exists(&paths.previous_receipt)?;
        }
        atomic_private_write(
            &paths.state_dir,
            paths.current_receipt_name(),
            &serde_json::to_vec(&transition.candidate)?,
        )?;
        append_receipt(&paths.receipt_log, &transition.candidate)?;
        remove_if_exists(&paths.rollback_candidate)?;
        remove_if_exists(&paths.pending_receipt)?;
        sync_directory(&paths.parent)?;
        sync_directory(&paths.state_dir)?;
        Ok(())
    }

    fn discard_transition(&self, paths: &InstallPaths) -> Result<(), UpdateError> {
        remove_if_exists(&paths.transition_previous)?;
        remove_if_exists(&paths.rollback_candidate)?;
        remove_if_exists(&paths.pending_receipt)?;
        sync_directory(&paths.state_dir)
    }

    fn health_check(&self, install_path: &Path) -> Result<(), String> {
        let mut child = Command::new(install_path)
            .arg("--self-test")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not execute --self-test: {error}"))?;
        let deadline = Instant::now() + self.health_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(format!("--self-test exited with {status}")),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("--self-test exceeded {:?}", self.health_timeout));
                }
                Err(error) => return Err(format!("could not wait for --self-test: {error}")),
            }
        }
    }
}

pub(super) struct InstallLock {
    file: File,
}

impl InstallLock {
    pub(super) fn acquire(name: &CliName, install_path: &Path) -> Result<Self, UpdateError> {
        let paths = InstallPaths::new(install_path)?;
        ensure_private_state_dir(&paths.state_dir)?;
        let lock_path = paths.state_dir.join(format!("{}.lock", name.as_str()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        file.lock_exclusive()?;
        Ok(Self { file })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

struct InstallPaths {
    parent: PathBuf,
    state_dir: PathBuf,
    current_receipt: PathBuf,
    previous_binary: PathBuf,
    previous_receipt: PathBuf,
    transition_previous: PathBuf,
    rollback_candidate: PathBuf,
    pending_receipt: PathBuf,
    receipt_log: PathBuf,
    failed_log: PathBuf,
}

impl InstallPaths {
    fn new(install_path: &Path) -> Result<Self, UpdateError> {
        let parent = install_path
            .parent()
            .ok_or_else(|| UpdateError::InvalidRequest("install path has no parent".into()))?
            .to_path_buf();
        let file_name = install_path
            .file_name()
            .ok_or_else(|| UpdateError::InvalidRequest("install path has no filename".into()))?
            .to_os_string();
        let stem = file_name.to_string_lossy().into_owned();
        let state_dir = parent.join(format!(".{stem}.tana-update"));
        Ok(Self {
            parent: parent.clone(),
            current_receipt: state_dir.join("current-receipt.json"),
            previous_binary: parent.join(format!("{stem}.prev")),
            previous_receipt: state_dir.join("previous-receipt.json"),
            transition_previous: parent.join(format!(".{stem}.transition-previous")),
            rollback_candidate: parent.join(format!(".{stem}.rollback-candidate")),
            pending_receipt: state_dir.join("pending-receipt.json"),
            receipt_log: state_dir.join("receipts.jsonl"),
            failed_log: state_dir.join("failed-receipts.jsonl"),
            state_dir,
        })
    }

    fn current_receipt_name(&self) -> &str {
        "current-receipt.json"
    }

    fn previous_receipt_name(&self) -> &str {
        "previous-receipt.json"
    }

    fn pending_receipt_name(&self) -> &str {
        "pending-receipt.json"
    }
}

fn verified_file(path: &Path, receipt: &Receipt) -> Result<bool, UpdateError> {
    reject_symlink(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(sha256_reader(file)? == receipt.binary_sha256)
}

fn link_or_verified_copy(source: &Path, target: &Path, digest: &str) -> Result<(), UpdateError> {
    match fs::hard_link(source, target) {
        Ok(()) => {}
        Err(_) => {
            fs::copy(source, target)?;
            File::open(target)?.sync_all()?;
        }
    }
    if sha256_reader(File::open(target)?)? != digest {
        remove_if_exists(target)?;
        return Err(UpdateError::Digest(
            "previous-generation backup hash mismatch".into(),
        ));
    }
    Ok(())
}

fn read_optional_receipt(path: &Path) -> Result<Option<Receipt>, UpdateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| UpdateError::Schema(format!("invalid receipt: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_optional_transition(path: &Path) -> Result<Option<PendingTransition>, UpdateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| UpdateError::Schema(format!("invalid pending transition: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn quarantine_candidate(paths: &InstallPaths, install_path: &Path) -> Result<(), UpdateError> {
    if !install_path.exists() {
        return Ok(());
    }
    let quarantine = paths.state_dir.join("failed-candidate.bin");
    remove_if_exists(&quarantine)?;
    fs::rename(install_path, &quarantine)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o600))?;
    }
    File::open(&quarantine)?.sync_all()?;
    Ok(())
}

fn append_receipt(path: &Path, receipt: &Receipt) -> Result<(), UpdateError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let mut bytes = serde_json::to_vec(receipt)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_private_state_dir(path: &Path) -> Result<(), UpdateError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), UpdateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(UpdateError::Digest(format!(
            "refusing symlink installation path {}",
            display_path(path)
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_if_exists(path: &Path) -> Result<(), UpdateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> Result<(), UpdateError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "install_recovery_tests.rs"]
mod recovery_tests;
