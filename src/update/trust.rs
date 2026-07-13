use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};

use super::{
    schema::LatestStatement,
    sha256_hex,
    trust_anchor::{AnchorSet, KeyRole, KeyStatus, OnlineKey, RootAnchor},
    UpdateError, UpdateRequest,
};

const MANIFEST_DOMAIN: &[u8] = b"tana.release-manifest.v1\n";
pub(super) const ARTIFACT_DOMAIN: &[u8] = b"tana.release-artifact.v1\n";
const LATEST_DOMAIN: &[u8] = b"tana.latest-statement.v1\n";

// PLACEHOLDER TRUST MATERIAL — NOT PRODUCTION HARAR KEYS.
// Sami must replace and verify every root/online fingerprint out of band before
// merge. A registry response can rotate/revoke online keys, never these roots.
const PLACEHOLDER_HARAR_ROOT_A: [u8; 32] = [
    102, 190, 126, 51, 44, 122, 69, 51, 50, 189, 157, 10, 127, 125, 176, 85, 245, 197, 239, 26, 6,
    173, 166, 109, 152, 179, 159, 182, 129, 12, 71, 58,
];
const PLACEHOLDER_HARAR_ROOT_B: [u8; 32] = [
    145, 162, 138, 11, 116, 56, 21, 147, 164, 217, 70, 149, 121, 32, 137, 38, 175, 200, 173, 130,
    200, 131, 155, 118, 68, 53, 155, 158, 186, 154, 75, 58,
];
const PLACEHOLDER_HARAR_RELEASE_KEY: [u8; 32] = [
    49, 200, 51, 252, 70, 230, 84, 255, 45, 19, 39, 128, 208, 236, 28, 1, 182, 147, 176, 124, 191,
    197, 18, 190, 202, 27, 90, 145, 29, 170, 192, 142,
];
const PLACEHOLDER_HARAR_FRESHNESS_KEY: [u8; 32] = [
    71, 144, 230, 106, 28, 64, 52, 115, 103, 182, 1, 11, 16, 235, 21, 221, 126, 250, 144, 82, 166,
    2, 59, 57, 105, 217, 97, 222, 123, 159, 240, 223,
];
const RELEASE_KEY_ID: &str = "PLACEHOLDER-harar-release-2026-q3";
const FRESHNESS_KEY_ID: &str = "PLACEHOLDER-harar-freshness-2026-q3";
const COMPILED_ANCHOR_GENERATION: u64 = 1;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedTrust {
    generation: u64,
    #[serde(default)]
    anchor_set_sha256: String,
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

/// Owner-only monotonic trust state rooted in compiled offline Harar anchors.
pub struct TrustStore {
    directory: PathBuf,
    state: PersistedTrust,
    roots: Vec<RootAnchor>,
    anchors: AnchorSet,
    anchor_bytes_sha256: String,
}

impl TrustStore {
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, UpdateError> {
        let roots = vec![
            root("PLACEHOLDER-harar-root-a", PLACEHOLDER_HARAR_ROOT_A)?,
            root("PLACEHOLDER-harar-root-b", PLACEHOLDER_HARAR_ROOT_B)?,
        ];
        let anchors = AnchorSet::compiled(
            COMPILED_ANCHOR_GENERATION,
            &roots,
            vec![
                online(
                    KeyRole::Release,
                    RELEASE_KEY_ID,
                    PLACEHOLDER_HARAR_RELEASE_KEY,
                )?,
                online(
                    KeyRole::Freshness,
                    FRESHNESS_KEY_ID,
                    PLACEHOLDER_HARAR_FRESHNESS_KEY,
                )?,
            ],
        );
        Self::open_with_material(directory.into(), roots, anchors)
    }

    fn open_with_material(
        directory: PathBuf,
        roots: Vec<RootAnchor>,
        anchors: AnchorSet,
    ) -> Result<Self, UpdateError> {
        create_private_directory(&directory)?;
        let anchor_bytes_sha256 = sha256_hex(&serde_json::to_vec(&anchors)?);
        let mut store = Self {
            directory,
            state: PersistedTrust::default(),
            roots,
            anchors,
            anchor_bytes_sha256,
        };
        store.reload()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(super) fn with_test_keys(
        directory: PathBuf,
        root_key: VerifyingKey,
        release_key_id: &str,
        release_key: VerifyingKey,
        freshness_key_id: &str,
        freshness_key: VerifyingKey,
    ) -> Result<Self, UpdateError> {
        let roots = vec![RootAnchor {
            key_id: "harar-root-test",
            key: root_key,
        }];
        let anchors = AnchorSet::compiled(
            1,
            &roots,
            vec![
                online_key(KeyRole::Release, release_key_id, release_key),
                online_key(KeyRole::Freshness, freshness_key_id, freshness_key),
            ],
        );
        Self::open_with_material(directory, roots, anchors)
    }

    pub(super) fn reload(&mut self) -> Result<(), UpdateError> {
        let path = self.directory.join("trust-state.json");
        self.state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                UpdateError::Schema(format!("persisted trust state is invalid: {error}"))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PersistedTrust {
                generation: COMPILED_ANCHOR_GENERATION,
                anchor_set_sha256: self.anchor_bytes_sha256.clone(),
                latest: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        if self.state.generation < COMPILED_ANCHOR_GENERATION {
            return Err(UpdateError::Freshness(
                "persisted anchor generation is below the compiled floor".into(),
            ));
        }

        let set_path = self.directory.join("anchor-set.json");
        let sig_path = self.directory.join("anchor-set.sig.json");
        match (fs::read(set_path), fs::read(sig_path)) {
            (Ok(bytes), Ok(signatures)) => {
                let set =
                    AnchorSet::parse_and_verify(&bytes, &signatures, &self.roots, Utc::now())?;
                let digest = sha256_hex(&bytes);
                if set.generation < self.state.generation
                    || (set.generation == self.state.generation
                        && !self.state.anchor_set_sha256.is_empty()
                        && digest != self.state.anchor_set_sha256)
                {
                    return Err(UpdateError::Freshness(
                        "persisted anchor set is stale or equivocated".into(),
                    ));
                }
                self.state.generation = set.generation;
                self.state.anchor_set_sha256 = digest.clone();
                self.anchors = set;
                self.anchor_bytes_sha256 = digest;
            }
            (Err(a), Err(b))
                if a.kind() == std::io::ErrorKind::NotFound
                    && b.kind() == std::io::ErrorKind::NotFound =>
            {
                if self.state.generation > COMPILED_ANCHOR_GENERATION {
                    return Err(UpdateError::Freshness(
                        "rotated anchor state is missing its signed document".into(),
                    ));
                }
            }
            _ => {
                return Err(UpdateError::Schema(
                    "persisted anchor set/signature pair is incomplete".into(),
                ))
            }
        }
        Ok(())
    }

    pub(super) fn accept_anchor_set(
        &mut self,
        bytes: &[u8],
        signatures: &[u8],
    ) -> Result<(), UpdateError> {
        let set = AnchorSet::parse_and_verify(bytes, signatures, &self.roots, Utc::now())?;
        let digest = sha256_hex(bytes);
        if set.generation < self.state.generation {
            return Err(UpdateError::Freshness(format!(
                "anchor generation {} is below persisted generation {}",
                set.generation, self.state.generation
            )));
        }
        if set.generation == self.state.generation && digest != self.anchor_bytes_sha256 {
            return Err(UpdateError::Freshness(
                "equal anchor generation arrived with different signed bytes".into(),
            ));
        }
        if set.generation > self.state.generation {
            atomic_private_write(&self.directory, "anchor-set.json", bytes)?;
            atomic_private_write(&self.directory, "anchor-set.sig.json", signatures)?;
            self.state.generation = set.generation;
            self.state.anchor_set_sha256 = digest.clone();
            self.persist()?;
        }
        self.anchors = set;
        self.anchor_bytes_sha256 = digest;
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
        self.verify_any(
            KeyRole::Freshness,
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
        self.verify_any(
            KeyRole::Release,
            MANIFEST_DOMAIN,
            bytes,
            signature,
            "release manifest",
        )
    }

    pub(super) fn verify_artifact_message(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), UpdateError> {
        if !message.starts_with(ARTIFACT_DOMAIN) {
            return Err(UpdateError::BadSignature("release artifact"));
        }
        let key = self
            .anchors
            .active_key(KeyRole::Release, key_id, Utc::now())?;
        verify_message(&key, message, signature, "release artifact")
    }

    fn verify_any(
        &self,
        role: KeyRole,
        domain: &[u8],
        bytes: &[u8],
        signature: &[u8],
        label: &'static str,
    ) -> Result<String, UpdateError> {
        let mut message = Vec::with_capacity(domain.len() + bytes.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(bytes);
        self.anchors
            .keys
            .iter()
            .filter(|entry| entry.role == role)
            .find_map(|entry| {
                let key = self
                    .anchors
                    .active_key(role, &entry.key_id, Utc::now())
                    .ok()?;
                verify_message(&key, &message, signature, label)
                    .ok()
                    .map(|()| entry.key_id.clone())
            })
            .ok_or(UpdateError::BadSignature(label))
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
            name: name.into(),
            channel: channel.into(),
            platform: platform.into(),
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
        atomic_private_write(
            &self.directory,
            "trust-state.json",
            &serde_json::to_vec(&self.state)?,
        )
    }
}

fn root(key_id: &'static str, bytes: [u8; 32]) -> Result<RootAnchor, UpdateError> {
    Ok(RootAnchor {
        key_id,
        key: VerifyingKey::from_bytes(&bytes).map_err(|error| {
            UpdateError::Schema(format!("compiled placeholder root is invalid: {error}"))
        })?,
    })
}

fn online(role: KeyRole, key_id: &str, bytes: [u8; 32]) -> Result<OnlineKey, UpdateError> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
        UpdateError::Schema(format!(
            "compiled placeholder online key is invalid: {error}"
        ))
    })?;
    Ok(online_key(role, key_id, key))
}

fn online_key(role: KeyRole, key_id: &str, key: VerifyingKey) -> OnlineKey {
    OnlineKey {
        role,
        key_id: key_id.into(),
        public_key_base64: BASE64.encode(key.as_bytes()),
        not_before: "2026-01-01T00:00:00Z".parse().expect("fixed timestamp"),
        not_after: "2030-01-01T00:00:00Z".parse().expect("fixed timestamp"),
        status: KeyStatus::Active,
    }
}

fn verify_message(
    key: &VerifyingKey,
    message: &[u8],
    signature: &[u8],
    label: &'static str,
) -> Result<(), UpdateError> {
    let signature =
        Signature::from_slice(signature).map_err(|_| UpdateError::SignatureLength(label))?;
    key.verify_strict(message, &signature)
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
