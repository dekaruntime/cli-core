//! Canonical signed-release verification and installation.
//!
//! The only operation exposed to callers is [`verify_and_install`]. Downloaded
//! bytes cannot be passed to the installer: its input is an opaque,
//! non-`Clone` capability created only after every cryptographic and on-disk
//! verification succeeds.

mod install;
mod schema;
mod trust;
mod verified;

#[cfg(test)]
mod tests;

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use semver::Version;
use thiserror::Error;

use self::{
    install::InstallLock,
    schema::{LatestStatement, ReleaseManifest},
};

pub use install::AtomicInstaller;
pub use trust::TrustStore;
pub use verified::VerifiedArtifact;

const MAX_LATEST_BYTES: usize = 16 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024 * 1024;

/// A validated registered CLI name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliName(String);

impl CliName {
    pub fn new(value: impl Into<String>) -> Result<Self, UpdateError> {
        let value = value.into();
        validate_segment("CLI name", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A release channel recognized by the signed-release protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseChannel {
    Stable,
    Beta,
    Nightly,
}

impl ReleaseChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }
}

/// A validated Rust target triple used as the immutable release platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetTriple(String);

impl TargetTriple {
    pub fn new(value: impl Into<String>) -> Result<Self, UpdateError> {
        let value = value.into();
        validate_segment("target triple", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionSelector {
    /// Follow the authenticated live latest statement.
    Latest {
        /// Crossing a SemVer major requires an explicit operator decision.
        allow_major_upgrade: bool,
    },
    /// Install one immutable tuple without consulting mutable latest.
    Exact(Version),
    /// Restore the locally retained, previously verified generation.
    Rollback,
}

#[derive(Debug)]
pub struct UpdateRequest {
    pub name: CliName,
    pub channel: ReleaseChannel,
    pub target: TargetTriple,
    pub selector: VersionSelector,
    pub install_path: PathBuf,
}

/// Coordinates passed to the hostile transport. The core derives every member
/// path from validated signed identity fields.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseCoordinates<'a> {
    name: &'a str,
    channel: &'a str,
    version: &'a str,
    platform: &'a str,
}

impl ReleaseCoordinates<'_> {
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn channel(&self) -> &str {
        self.channel
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn platform(&self) -> &str {
        self.platform
    }
}

/// Hostile byte transport. Implementations must fetch each requested object at
/// most once and return owned bytes; the core independently enforces bounds.
pub trait ReleaseTransport {
    fn fetch_latest_statement(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError>;

    fn fetch_latest_signature(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
    ) -> Result<Vec<u8>, TransportError>;

    fn fetch_manifest(
        &self,
        release: ReleaseCoordinates<'_>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError>;

    fn fetch_manifest_signature(
        &self,
        release: ReleaseCoordinates<'_>,
    ) -> Result<Vec<u8>, TransportError>;

    fn fetch_artifact(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError>;

    fn fetch_artifact_signature(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
    ) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug, Error)]
#[error("release transport failed: {0}")]
pub struct TransportError(String);

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct InstalledRelease {
    name: String,
    channel: String,
    platform: String,
    version: Version,
    binary_sha256: String,
    artifact_sha256: String,
    promotion_id: String,
    rolled_back: bool,
}

impl InstalledRelease {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn rolled_back(&self) -> bool {
        self.rolled_back
    }
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid update request: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("{object} exceeded the {limit}-byte limit ({actual} bytes)")]
    ResponseTooLarge {
        object: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("invalid {0} detached signature length; expected 64 raw bytes")]
    SignatureLength(&'static str),
    #[error("{0} signature was not made by an active pinned Harar key")]
    BadSignature(&'static str),
    #[error("invalid signed document: {0}")]
    Schema(String),
    #[error("release freshness policy rejected the candidate: {0}")]
    Freshness(String),
    #[error("release digest mismatch: {0}")]
    Digest(String),
    #[error("release decompression rejected the artifact: {0}")]
    Decompression(String),
    #[error("update filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("installed candidate failed health check: {0}")]
    Health(String),
    #[error("rollback is unavailable: {0}")]
    Rollback(String),
}

impl From<serde_json::Error> for UpdateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Schema(error.to_string())
    }
}

/// Verify one immutable signed release chain and atomically install precisely
/// the bytes that were verified. This is the only production update operation.
pub fn verify_and_install(
    request: UpdateRequest,
    transport: &dyn ReleaseTransport,
    installer: &AtomicInstaller,
    trust: &mut TrustStore,
) -> Result<InstalledRelease, UpdateError> {
    validate_install_path(&request.install_path)?;
    let _lock = InstallLock::acquire(&request.name, &request.install_path)?;
    trust.reload()?;
    if let Some(recovered) = installer.recover(&request)? {
        return Ok(recovered);
    }

    if request.selector == VersionSelector::Rollback {
        return installer.rollback(&request);
    }

    let accepted = match &request.selector {
        VersionSelector::Latest {
            allow_major_upgrade,
        } => {
            let bytes = bounded(
                "latest statement",
                transport.fetch_latest_statement(
                    request.name.as_str(),
                    request.channel.as_str(),
                    request.target.as_str(),
                    MAX_LATEST_BYTES,
                )?,
                MAX_LATEST_BYTES,
            )?;
            let signature = bounded(
                "latest signature",
                transport.fetch_latest_signature(
                    request.name.as_str(),
                    request.channel.as_str(),
                    request.target.as_str(),
                )?,
                64,
            )?;
            let verified_key = trust.verify_latest(&bytes, &signature)?;
            let statement = LatestStatement::parse_and_validate(&bytes, &request, &verified_key)?;
            trust.check_latest(&statement, &bytes, *allow_major_upgrade)?;
            Some((statement, bytes))
        }
        VersionSelector::Exact(version) => {
            trust.check_exact(&request, version)?;
            None
        }
        VersionSelector::Rollback => unreachable!("rollback handled before network access"),
    };

    let version = accepted
        .as_ref()
        .map(|(statement, _)| statement.version.clone())
        .or_else(|| match &request.selector {
            VersionSelector::Exact(version) => Some(version.clone()),
            _ => None,
        })
        .expect("non-rollback selector has a version");
    let version_text = version.to_string();
    let release = ReleaseCoordinates {
        name: request.name.as_str(),
        channel: request.channel.as_str(),
        version: &version_text,
        platform: request.target.as_str(),
    };

    let manifest_bytes = bounded(
        "release manifest",
        transport.fetch_manifest(release, MAX_MANIFEST_BYTES)?,
        MAX_MANIFEST_BYTES,
    )?;
    if let Some((statement, _)) = &accepted {
        statement.verify_manifest_binding(&manifest_bytes)?;
    }
    let manifest_signature = bounded(
        "manifest signature",
        transport.fetch_manifest_signature(release)?,
        64,
    )?;
    let release_key = trust.verify_manifest(&manifest_bytes, &manifest_signature)?;
    let manifest =
        ReleaseManifest::parse_and_validate(&manifest_bytes, &request, &version, &release_key)?;

    let artifact_limit = usize::try_from(manifest.artifact_size)
        .unwrap_or(usize::MAX)
        .min(MAX_ARTIFACT_BYTES);
    let artifact_bytes = bounded(
        "release artifact",
        transport.fetch_artifact(release, &manifest.artifact, artifact_limit)?,
        artifact_limit,
    )?;
    let artifact_signature = bounded(
        "artifact signature",
        transport.fetch_artifact_signature(release, &manifest.artifact)?,
        64,
    )?;

    let receipt = install::Receipt::new(&request, &manifest, accepted.as_ref(), trust.generation());
    let artifact = VerifiedArtifact::verify(
        request.install_path.clone(),
        manifest,
        artifact_bytes,
        artifact_signature,
        trust,
        receipt,
    )?;

    if let Some((statement, statement_bytes)) = &accepted {
        trust.accept_latest(statement, statement_bytes)?;
    }
    installer.install(artifact)
}

fn bounded(object: &'static str, bytes: Vec<u8>, limit: usize) -> Result<Vec<u8>, UpdateError> {
    if bytes.len() > limit {
        return Err(UpdateError::ResponseTooLarge {
            object,
            limit,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn validate_segment(label: &str, value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b'/' | b'\\' | b'%' | b'?' | b'#' | b':' | b'@')
        })
    {
        return Err(UpdateError::InvalidRequest(format!(
            "{label} is not a safe single path segment"
        )));
    }
    Ok(())
}

fn validate_install_path(path: &Path) -> Result<(), UpdateError> {
    if !path.is_absolute() || path.file_name().is_none() || path.parent().is_none() {
        return Err(UpdateError::InvalidRequest(
            "install_path must be an absolute executable path".into(),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn sha256_reader(mut reader: impl std::io::Read) -> Result<String, std::io::Error> {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn display_path(path: &Path) -> impl fmt::Display + '_ {
    path.display()
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(10)
}
