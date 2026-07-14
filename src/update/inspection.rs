use semver::Version;

use super::{
    bounded, install::InstallLock, schema::LatestStatement, validate_install_path, AtomicInstaller,
    ReleaseTransport, TrustStore, UpdateError, UpdateRequest, MAX_ANCHOR_SET_BYTES,
    MAX_ANCHOR_SIGNATURE_BYTES, MAX_LATEST_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalInstallation {
    pub version: Version,
    pub binary_sha256: String,
    pub release_key_id: String,
    pub anchor_generation: u64,
    pub health_ok: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInstallationStatus {
    pub local: LocalInstallation,
    pub latest_version: Version,
    pub update_available: bool,
}

/// Verifies the receipted local binary and health probe, then authenticates the
/// current signed freshness statement. It never downloads or installs an
/// artifact and uses the same trust floor and lock as an update.
pub fn inspect_signed_installation(
    request: UpdateRequest,
    transport: &dyn ReleaseTransport,
    installer: &AtomicInstaller,
    trust: &mut TrustStore,
) -> Result<SignedInstallationStatus, UpdateError> {
    validate_install_path(&request.install_path)?;
    let _lock = InstallLock::acquire(&request)?;
    trust.reload()?;
    let local = installer.inspect(&request)?;

    let anchor_set = bounded(
        "anchor set",
        transport.fetch_anchor_set(MAX_ANCHOR_SET_BYTES)?,
        MAX_ANCHOR_SET_BYTES,
    )?;
    let anchor_signatures = bounded(
        "anchor signatures",
        transport.fetch_anchor_signatures(MAX_ANCHOR_SIGNATURE_BYTES)?,
        MAX_ANCHOR_SIGNATURE_BYTES,
    )?;
    trust.accept_anchor_set(&anchor_set, &anchor_signatures)?;

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
    // A monitor may report a newer major, but it must not persist that version
    // as the update floor and thereby bypass explicit major-update approval.
    trust.check_latest(&statement, &bytes, true)?;
    let latest_version = statement.version.clone();
    Ok(SignedInstallationStatus {
        update_available: latest_version > local.version,
        latest_version,
        local,
    })
}
