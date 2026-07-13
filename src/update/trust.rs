use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::{schema::LatestStatement, sha256_hex, UpdateError, UpdateRequest};

const MANIFEST_DOMAIN: &[u8] = b"tana.release-manifest.v1\n";
pub(super) const ARTIFACT_DOMAIN: &[u8] = b"tana.release-artifact.v1\n";
const LATEST_DOMAIN: &[u8] = b"tana.latest-statement.v1\n";

// Compile-time trust anchors. These values are deliberately review-gated in
// tana#722: changing any byte requires Sami's out-of-band fingerprint review.
const HARAR_RELEASE_PUBLIC_KEY: [u8; 32] = [
    49, 200, 51, 252, 70, 230, 84, 255, 45, 19, 39, 128, 208, 236, 28, 1, 182, 147, 176, 124, 191,
    197, 18, 190, 202, 27, 90, 145, 29, 170, 192, 142,
];
const HARAR_FRESHNESS_PUBLIC_KEY: [u8; 32] = [
    71, 144, 230, 106, 28, 64, 52, 115, 103, 182, 1, 11, 16, 235, 21, 221, 126, 250, 144, 82, 166,
    2, 59, 57, 105, 217, 97, 222, 123, 159, 240, 223,
];
const HARAR_RELEASE_KEY_ID: &str = "harar-release-2026-q3";
const HARAR_FRESHNESS_KEY_ID: &str = "harar-freshness-2026-q3";
const COMPILED_ANCHOR_GENERATION: u64 = 1;

#[derive(Clone)]
struct Anchor {
    key_id: String,
    key: VerifyingKey,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedTrust {
    generation: u64,
    latest: Vec<LatestFloor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LatestFloor {
    name: String,
    channel: String,
    platform: String,
    counter: u64,
    statement_sha256: String,
    version: Version,
}

/// Owner-only persistent monotonic trust state plus compiled Harar anchors.
pub struct TrustStore {
    directory: PathBuf,
    state: PersistedTrust,
    release_keys: Vec<Anchor>,
    freshness_keys: Vec<Anchor>,
}

impl TrustStore {
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, UpdateError> {
        Self::open_with_key_material(
            directory.into(),
            [(
                HARAR_RELEASE_KEY_ID.to_owned(),
                VerifyingKey::from_bytes(&HARAR_RELEASE_PUBLIC_KEY).map_err(|error| {
                    UpdateError::Schema(format!("compiled release anchor is invalid: {error}"))
                })?,
            )],
            [(
                HARAR_FRESHNESS_KEY_ID.to_owned(),
                VerifyingKey::from_bytes(&HARAR_FRESHNESS_PUBLIC_KEY).map_err(|error| {
                    UpdateError::Schema(format!("compiled freshness anchor is invalid: {error}"))
                })?,
            )],
        )
    }

    fn open_with_key_material(
        directory: PathBuf,
        release_keys: impl IntoIterator<Item = (String, VerifyingKey)>,
        freshness_keys: impl IntoIterator<Item = (String, VerifyingKey)>,
    ) -> Result<Self, UpdateError> {
        create_private_directory(&directory)?;
        let mut store = Self {
            directory,
            state: PersistedTrust::default(),
            release_keys: release_keys
                .into_iter()
                .map(|(key_id, key)| Anchor { key_id, key })
                .collect(),
            freshness_keys: freshness_keys
                .into_iter()
                .map(|(key_id, key)| Anchor { key_id, key })
                .collect(),
        };
        if store.release_keys.is_empty() || store.freshness_keys.is_empty() {
            return Err(UpdateError::Schema(
                "compiled release and freshness anchors are required".into(),
            ));
        }
        store.reload()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(super) fn with_test_keys(
        directory: PathBuf,
        release_key_id: &str,
        release_key: VerifyingKey,
        freshness_key_id: &str,
        freshness_key: VerifyingKey,
    ) -> Result<Self, UpdateError> {
        Self::open_with_key_material(
            directory,
            [(release_key_id.to_owned(), release_key)],
            [(freshness_key_id.to_owned(), freshness_key)],
        )
    }

    pub(super) fn reload(&mut self) -> Result<(), UpdateError> {
        let path = self.directory.join("trust-state.json");
        self.state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                UpdateError::Schema(format!("persisted trust state is invalid: {error}"))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PersistedTrust {
                generation: COMPILED_ANCHOR_GENERATION,
                latest: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        if self.state.generation < COMPILED_ANCHOR_GENERATION {
            return Err(UpdateError::Freshness(
                "persisted anchor generation is below the compiled floor".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn generation(&self) -> u64 {
        self.state.generation
    }

    pub(super) fn verify_latest(
        &self,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<String, UpdateError> {
        verify_any(
            &self.freshness_keys,
            LATEST_DOMAIN,
            bytes,
            signature,
            "latest statement",
        )
    }

    pub(super) fn verify_manifest(
        &self,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<String, UpdateError> {
        verify_any(
            &self.release_keys,
            MANIFEST_DOMAIN,
            bytes,
            signature,
            "release manifest",
        )
    }

    pub(super) fn verify_artifact_message(
        &self,
        key_id: &str,
        domain_separated_message: &[u8],
        signature: &[u8],
    ) -> Result<(), UpdateError> {
        if !domain_separated_message.starts_with(ARTIFACT_DOMAIN) {
            return Err(UpdateError::BadSignature("release artifact"));
        }
        let anchor = self
            .release_keys
            .iter()
            .find(|anchor| anchor.key_id == key_id)
            .ok_or(UpdateError::BadSignature("release artifact"))?;
        verify_signed_message(
            anchor,
            domain_separated_message,
            signature,
            "release artifact",
        )
    }

    pub(super) fn check_latest(
        &self,
        statement: &LatestStatement,
        bytes: &[u8],
        allow_major_upgrade: bool,
    ) -> Result<(), UpdateError> {
        statement.touch_fields_for_closed_schema();
        let (name, channel, platform) = statement.identity_key();
        let Some(floor) = self.floor(name, channel, platform) else {
            return Ok(());
        };
        let statement_hash = sha256_hex(bytes);
        if statement.counter < floor.counter {
            return Err(UpdateError::Freshness(format!(
                "counter {} is below persisted counter {}",
                statement.counter, floor.counter
            )));
        }
        if statement.counter == floor.counter {
            if statement_hash != floor.statement_sha256 {
                return Err(UpdateError::Freshness(
                    "equal latest counter arrived with different signed bytes".into(),
                ));
            }
            return Ok(());
        }
        if statement.version <= floor.version {
            return Err(UpdateError::Freshness(format!(
                "higher counter selected non-advancing version {} (floor {})",
                statement.version, floor.version
            )));
        }
        if statement.version.major != floor.version.major && !allow_major_upgrade {
            return Err(UpdateError::Freshness(format!(
                "major upgrade {} -> {} requires explicit confirmation",
                floor.version, statement.version
            )));
        }
        Ok(())
    }

    pub(super) fn check_exact(
        &self,
        request: &UpdateRequest,
        version: &Version,
    ) -> Result<(), UpdateError> {
        if self.state.latest.iter().any(|floor| {
            floor.name == request.name.as_str()
                && floor.channel == request.channel.as_str()
                && floor.platform == request.target.as_str()
                && version < &floor.version
        }) {
            return Err(UpdateError::Freshness(format!(
                "exact version {version} is below a persisted signed version floor"
            )));
        }
        Ok(())
    }

    pub(super) fn accept_latest(
        &mut self,
        statement: &LatestStatement,
        bytes: &[u8],
    ) -> Result<(), UpdateError> {
        let (name, channel, platform) = statement.identity_key();
        let replacement = LatestFloor {
            name: name.to_owned(),
            channel: channel.to_owned(),
            platform: platform.to_owned(),
            counter: statement.counter,
            statement_sha256: sha256_hex(bytes),
            version: statement.version.clone(),
        };
        match self.state.latest.iter_mut().find(|floor| {
            floor.name == name && floor.channel == channel && floor.platform == platform
        }) {
            Some(floor) if replacement.counter > floor.counter => *floor = replacement,
            Some(_) => return Ok(()),
            None => self.state.latest.push(replacement),
        }
        self.persist()
    }

    fn floor(&self, name: &str, channel: &str, platform: &str) -> Option<&LatestFloor> {
        self.state.latest.iter().find(|floor| {
            floor.name == name && floor.channel == channel && floor.platform == platform
        })
    }

    fn persist(&self) -> Result<(), UpdateError> {
        let bytes = serde_json::to_vec(&self.state)?;
        atomic_private_write(&self.directory, "trust-state.json", &bytes)
    }
}

fn verify_any(
    anchors: &[Anchor],
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8],
    label: &'static str,
) -> Result<String, UpdateError> {
    if signature.len() != 64 {
        return Err(UpdateError::SignatureLength(label));
    }
    anchors
        .iter()
        .find(|anchor| verify_one(anchor, domain, bytes, signature, label).is_ok())
        .map(|anchor| anchor.key_id.clone())
        .ok_or(UpdateError::BadSignature(label))
}

fn verify_one(
    anchor: &Anchor,
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8],
    label: &'static str,
) -> Result<(), UpdateError> {
    let mut signed = Vec::with_capacity(domain.len() + bytes.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(bytes);
    verify_signed_message(anchor, &signed, signature, label)
}

fn verify_signed_message(
    anchor: &Anchor,
    signed: &[u8],
    signature: &[u8],
    label: &'static str,
) -> Result<(), UpdateError> {
    let signature =
        Signature::from_slice(signature).map_err(|_| UpdateError::SignatureLength(label))?;
    anchor
        .key
        .verify_strict(signed, &signature)
        .map_err(|_| UpdateError::BadSignature(label))
}

fn create_private_directory(path: &Path) -> Result<(), UpdateError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn atomic_private_write(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), UpdateError> {
    let temporary = directory.join(format!(".{name}.pending"));
    let final_path = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &final_path)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}
