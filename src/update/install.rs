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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
        let Some(pending) = read_optional_receipt(&paths.pending_receipt)? else {
            return Ok(None);
        };
        if !pending.matches_request(request) {
            return Err(UpdateError::Freshness(
                "pending receipt identity differs from update request".into(),
            ));
        }
        if verified_file(&request.install_path, &pending)?
            && self.health_check(&request.install_path).is_ok()
        {
            atomic_private_write(
                &paths.state_dir,
                paths.current_receipt_name(),
                &serde_json::to_vec(&pending)?,
            )?;
            append_receipt(&paths.receipt_log, &pending)?;
            remove_if_exists(&paths.pending_receipt)?;
            sync_directory(&paths.state_dir)?;
            return Ok(Some(pending.installed(false)));
        }
        if self.restore_previous(&paths, &request.install_path)? {
            append_receipt(&paths.failed_log, &pending)?;
        }
        remove_if_exists(&paths.pending_receipt)?;
        sync_directory(&paths.state_dir)?;
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

        atomic_private_write(
            &paths.state_dir,
            paths.pending_receipt_name(),
            &serde_json::to_vec(&receipt)?,
        )?;

        self.back_up_current(&paths, &install_path)?;
        sync_directory(&paths.parent)?;

        staged
            .persist(&install_path)
            .map_err(|error| UpdateError::Io(error.error))?;
        sync_directory(&paths.parent)?;

        if let Err(error) = self.health_check(&install_path) {
            append_receipt(&paths.failed_log, &receipt)?;
            let restored = self.restore_previous(&paths, &install_path)?;
            remove_if_exists(&paths.pending_receipt)?;
            sync_directory(&paths.state_dir)?;
            if !restored {
                return Err(UpdateError::Health(format!(
                    "{error}; no verified previous generation was available"
                )));
            }
            return Err(UpdateError::Health(error));
        }

        atomic_private_write(
            &paths.state_dir,
            paths.current_receipt_name(),
            &serde_json::to_vec(&receipt)?,
        )?;
        append_receipt(&paths.receipt_log, &receipt)?;
        remove_if_exists(&paths.pending_receipt)?;
        sync_directory(&paths.state_dir)?;
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

        let saved_current = paths.parent.join(format!(
            ".{}.rollback-current",
            paths.file_name.to_string_lossy()
        ));
        remove_if_exists(&saved_current)?;
        link_or_verified_copy(install_path, &saved_current, &current.binary_sha256)?;
        fs::rename(&paths.previous_binary, install_path)?;
        fs::rename(&saved_current, &paths.previous_binary)?;
        sync_directory(&paths.parent)?;

        if let Err(error) = self.health_check(install_path) {
            let failed_previous = paths.parent.join(format!(
                ".{}.rollback-failed",
                paths.file_name.to_string_lossy()
            ));
            remove_if_exists(&failed_previous)?;
            fs::rename(install_path, &failed_previous)?;
            fs::rename(&paths.previous_binary, install_path)?;
            remove_if_exists(&failed_previous)?;
            sync_directory(&paths.parent)?;
            return Err(UpdateError::Health(format!(
                "rollback target failed self-test: {error}"
            )));
        }

        atomic_private_write(
            &paths.state_dir,
            paths.current_receipt_name(),
            &serde_json::to_vec(&previous)?,
        )?;
        atomic_private_write(
            &paths.state_dir,
            paths.previous_receipt_name(),
            &serde_json::to_vec(&current)?,
        )?;
        append_receipt(&paths.receipt_log, &previous)?;
        Ok(previous.installed(true))
    }

    fn back_up_current(
        &self,
        paths: &InstallPaths,
        install_path: &Path,
    ) -> Result<(), UpdateError> {
        if !install_path.exists() {
            remove_if_exists(&paths.previous_binary)?;
            remove_if_exists(&paths.previous_receipt)?;
            return Ok(());
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
        let temporary = paths.parent.join(format!(
            ".{}.prev-pending",
            paths.file_name.to_string_lossy()
        ));
        remove_if_exists(&temporary)?;
        link_or_verified_copy(install_path, &temporary, &current.binary_sha256)?;
        fs::rename(&temporary, &paths.previous_binary)?;
        atomic_private_write(
            &paths.state_dir,
            paths.previous_receipt_name(),
            &serde_json::to_vec(&current)?,
        )?;
        sync_directory(&paths.parent)?;
        Ok(())
    }

    fn restore_previous(
        &self,
        paths: &InstallPaths,
        install_path: &Path,
    ) -> Result<bool, UpdateError> {
        let Some(previous) = read_optional_receipt(&paths.previous_receipt)? else {
            return Ok(false);
        };
        if !verified_file(&paths.previous_binary, &previous)? {
            return Err(UpdateError::Rollback(
                "previous binary differs from its stored receipt".into(),
            ));
        }
        fs::rename(&paths.previous_binary, install_path)?;
        atomic_private_write(
            &paths.state_dir,
            paths.current_receipt_name(),
            &serde_json::to_vec(&previous)?,
        )?;
        remove_if_exists(&paths.previous_receipt)?;
        sync_directory(&paths.parent)?;
        Ok(true)
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
    file_name: std::ffi::OsString,
    state_dir: PathBuf,
    current_receipt: PathBuf,
    previous_binary: PathBuf,
    previous_receipt: PathBuf,
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
            file_name,
            current_receipt: state_dir.join("current-receipt.json"),
            previous_binary: parent.join(format!("{stem}.prev")),
            previous_receipt: state_dir.join("previous-receipt.json"),
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
