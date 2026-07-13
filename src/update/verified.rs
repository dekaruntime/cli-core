use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use sha2::Digest as _;
use tempfile::{Builder, NamedTempFile};

use super::{install::Receipt, schema::ReleaseManifest, sha256_reader, TrustStore, UpdateError};

/// A verified installation capability. It has no public constructor, is not
/// cloneable, exposes no bytes or path, and is consumed by the private atomic
/// install primitive.
///
/// Unverified bytes cannot be promoted into this capability:
///
/// ```compile_fail
/// use tana_cli_core::VerifiedArtifact;
/// let _candidate = VerifiedArtifact {};
/// ```
pub struct VerifiedArtifact {
    staged_binary: NamedTempFile,
    install_path: PathBuf,
    receipt: Receipt,
}

impl VerifiedArtifact {
    pub(super) fn verify(
        install_path: PathBuf,
        manifest: ReleaseManifest,
        mut artifact_bytes: Vec<u8>,
        artifact_signature: Vec<u8>,
        trust: &TrustStore,
        receipt: Receipt,
    ) -> Result<Self, UpdateError> {
        manifest.touch_fields_for_closed_schema();
        if artifact_bytes.len() as u64 != manifest.artifact_size {
            return Err(UpdateError::Digest(format!(
                "artifact size is {}, manifest requires {}",
                artifact_bytes.len(),
                manifest.artifact_size
            )));
        }
        let parent = install_path.parent().ok_or_else(|| {
            UpdateError::InvalidRequest("install path has no parent directory".into())
        })?;
        fs::create_dir_all(parent)?;

        // Prefix the owned response allocation in place. The artifact remains
        // one buffer: the exact fetched bytes are the suffix used for hashing,
        // disk staging, and zstd parsing, while Ed25519 sees prefix || suffix.
        artifact_bytes.reserve(super::trust::ARTIFACT_DOMAIN.len());
        artifact_bytes.splice(0..0, super::trust::ARTIFACT_DOMAIN.iter().copied());
        let artifact = &artifact_bytes[super::trust::ARTIFACT_DOMAIN.len()..];

        // The hostile response is written exactly once into an owner-only,
        // same-filesystem object while hashing those same buffer bytes.
        let mut compressed = private_temp(parent, ".tana-artifact-")?;
        let write_hash = write_and_hash(compressed.as_file_mut(), artifact)?;
        compressed.as_file().sync_all()?;
        if write_hash != manifest.artifact_sha256 {
            return Err(UpdateError::Digest(
                "artifact SHA-256 differs from signed manifest".into(),
            ));
        }

        // Re-hash through the still-open descriptor before decompression. This
        // detects disk/write corruption and makes the fetched-buffer -> staged
        // object boundary explicit.
        compressed.as_file_mut().seek(SeekFrom::Start(0))?;
        let disk_hash = sha256_reader(compressed.as_file_mut())?;
        if disk_hash != write_hash {
            return Err(UpdateError::Digest(
                "artifact changed between write and on-disk verification".into(),
            ));
        }
        trust.verify_artifact_message(&manifest.key_id, &artifact_bytes, &artifact_signature)?;

        let frame_size = zstd_safe::find_frame_compressed_size(artifact)
            .map_err(|error| UpdateError::Decompression(error.to_string()))?;
        if frame_size != artifact.len() {
            return Err(UpdateError::Decompression(
                "artifact must contain exactly one zstd frame with no trailing data".into(),
            ));
        }
        drop(artifact_bytes);

        compressed.as_file_mut().seek(SeekFrom::Start(0))?;
        let mut decoder = zstd::stream::read::Decoder::new(compressed.as_file_mut())
            .map_err(|error| UpdateError::Decompression(error.to_string()))?;
        let mut binary = private_temp(parent, ".tana-binary-")?;
        let mut digest = sha2::Sha256::new();
        let mut written = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = decoder
                .read(&mut buffer)
                .map_err(|error| UpdateError::Decompression(error.to_string()))?;
            if read == 0 {
                break;
            }
            written = written
                .checked_add(read as u64)
                .ok_or_else(|| UpdateError::Decompression("binary size overflow".into()))?;
            if written > manifest.binary_size {
                return Err(UpdateError::Decompression(format!(
                    "binary exceeded signed size {}",
                    manifest.binary_size
                )));
            }
            digest.update(&buffer[..read]);
            binary.as_file_mut().write_all(&buffer[..read])?;
        }
        if written != manifest.binary_size {
            return Err(UpdateError::Digest(format!(
                "binary size is {written}, manifest requires {}",
                manifest.binary_size
            )));
        }
        let decompressed_hash = format!("{:x}", digest.finalize());
        if decompressed_hash != manifest.binary_sha256 {
            return Err(UpdateError::Digest(
                "decompressed binary SHA-256 differs from signed manifest".into(),
            ));
        }
        binary.as_file().sync_all()?;

        let descriptor_identity = file_identity(binary.as_file())?;
        binary.as_file_mut().seek(SeekFrom::Start(0))?;
        let rehashed = sha256_reader(binary.as_file_mut())?;
        if rehashed != decompressed_hash {
            return Err(UpdateError::Digest(
                "decompressed binary changed during on-disk re-hash".into(),
            ));
        }
        if descriptor_identity != file_identity(binary.as_file())? {
            return Err(UpdateError::Digest(
                "decompressed binary descriptor identity changed".into(),
            ));
        }
        let path_identity = path_identity(binary.path())?;
        if descriptor_identity != path_identity {
            return Err(UpdateError::Digest(
                "decompressed binary path no longer names the verified inode".into(),
            ));
        }
        binary.as_file_mut().seek(SeekFrom::Start(0))?;
        Ok(Self {
            staged_binary: binary,
            install_path,
            receipt,
        })
    }

    pub(super) fn into_parts(self) -> (NamedTempFile, PathBuf, Receipt) {
        (self.staged_binary, self.install_path, self.receipt)
    }
}

fn private_temp(parent: &std::path::Path, prefix: &str) -> Result<NamedTempFile, UpdateError> {
    let file = Builder::new().prefix(prefix).tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn write_and_hash(file: &mut File, bytes: &[u8]) -> Result<String, UpdateError> {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    for chunk in bytes.chunks(64 * 1024) {
        file.write_all(chunk)?;
        digest.update(chunk);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64), UpdateError> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn path_identity(path: &std::path::Path) -> Result<(u64, u64), UpdateError> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_: &File) -> Result<(u64, u64), UpdateError> {
    Ok((0, 0))
}

#[cfg(not(unix))]
fn path_identity(_: &std::path::Path) -> Result<(u64, u64), UpdateError> {
    Ok((0, 0))
}
