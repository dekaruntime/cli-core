use std::{collections::HashSet, fmt};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use semver::Version;
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};

use super::{sha256_hex, UpdateError, UpdateRequest};

#[derive(Clone, Debug)]
pub(super) struct LatestStatement {
    schema: String,
    algorithm: String,
    pub(super) key_id: String,
    name: String,
    channel: String,
    platform: String,
    version_text: String,
    manifest: String,
    pub(super) manifest_size: u64,
    pub(super) manifest_sha256: String,
    pub(super) counter: u64,
    issued_at: String,
    expires_at: String,
    pub(super) version: Version,
}

impl LatestStatement {
    pub(super) fn parse_and_validate(
        bytes: &[u8],
        request: &UpdateRequest,
        verified_key: &str,
    ) -> Result<Self, UpdateError> {
        reject_duplicate_keys(bytes)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: String,
            algorithm: String,
            key_id: String,
            name: String,
            channel: String,
            platform: String,
            version: String,
            manifest: String,
            manifest_size: u64,
            manifest_sha256: String,
            counter: u64,
            issued_at: String,
            expires_at: String,
        }
        let wire: Wire = serde_json::from_slice(bytes)?;
        if wire.schema != "tana.latest-statement.v1" || wire.algorithm != "ed25519" {
            return Err(schema("latest schema or algorithm literal is invalid"));
        }
        if wire.key_id != verified_key {
            return Err(schema(
                "latest key_id differs from the pinned freshness key that verified its bytes",
            ));
        }
        if wire.name != request.name.as_str()
            || wire.channel != request.channel.as_str()
            || wire.platform != request.target.as_str()
            || wire.manifest != "release-manifest.json"
        {
            return Err(schema("latest identity does not match the update request"));
        }
        if wire.manifest_size == 0 || wire.manifest_size > super::MAX_MANIFEST_BYTES as u64 {
            return Err(schema("latest manifest_size is outside the allowed range"));
        }
        validate_lower_hex("manifest_sha256", &wire.manifest_sha256, 64)?;
        if wire.counter == 0 {
            return Err(schema("latest counter must be positive"));
        }
        let version = strict_version(&wire.version)?;
        let issued_at = strict_timestamp("issued_at", &wire.issued_at)?;
        let expires_at = strict_timestamp("expires_at", &wire.expires_at)?;
        if expires_at != issued_at + Duration::hours(72) {
            return Err(schema("latest expires_at must equal issued_at + 72 hours"));
        }
        let now = Utc::now();
        if issued_at > now + Duration::minutes(5) {
            return Err(UpdateError::Freshness(
                "latest statement is issued too far in the future".into(),
            ));
        }
        if expires_at <= now {
            return Err(UpdateError::Freshness(
                "latest statement has expired".into(),
            ));
        }
        Ok(Self {
            schema: wire.schema,
            algorithm: wire.algorithm,
            key_id: wire.key_id,
            name: wire.name,
            channel: wire.channel,
            platform: wire.platform,
            version_text: wire.version,
            manifest: wire.manifest,
            manifest_size: wire.manifest_size,
            manifest_sha256: wire.manifest_sha256,
            counter: wire.counter,
            issued_at: wire.issued_at,
            expires_at: wire.expires_at,
            version,
        })
    }

    pub(super) fn verify_manifest_binding(&self, bytes: &[u8]) -> Result<(), UpdateError> {
        if bytes.len() as u64 != self.manifest_size {
            return Err(UpdateError::Digest(format!(
                "manifest size is {}, signed latest requires {}",
                bytes.len(),
                self.manifest_size
            )));
        }
        if sha256_hex(bytes) != self.manifest_sha256 {
            return Err(UpdateError::Digest(
                "manifest SHA-256 differs from signed latest".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn identity_key(&self) -> (&str, &str, &str) {
        (&self.name, &self.channel, &self.platform)
    }

    pub(super) fn touch_fields_for_closed_schema(&self) {
        let _ = (
            &self.schema,
            &self.algorithm,
            &self.version_text,
            &self.manifest,
            &self.issued_at,
            &self.expires_at,
        );
    }
}

#[derive(Clone, Debug)]
pub(super) struct ReleaseManifest {
    schema: String,
    algorithm: String,
    pub(super) key_id: String,
    pub(super) promotion_id: String,
    name: String,
    channel: String,
    pub(super) version_text: String,
    platform: String,
    pub(super) artifact: String,
    compression: String,
    pub(super) artifact_size: u64,
    pub(super) artifact_sha256: String,
    pub(super) binary_size: u64,
    pub(super) binary_sha256: String,
    source_repo: String,
    source_git_sha: String,
    build_recipe_sha256: String,
    toolchain_digest: String,
    provenance_digest: String,
    builders: Vec<ManifestBuilder>,
    promoted_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBuilder {
    builder_id: String,
    run_id: String,
    attestation_sha256: String,
}

impl ReleaseManifest {
    pub(super) fn parse_and_validate(
        bytes: &[u8],
        request: &UpdateRequest,
        requested_version: &Version,
        verified_key: &str,
    ) -> Result<Self, UpdateError> {
        reject_duplicate_keys(bytes)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: String,
            algorithm: String,
            key_id: String,
            promotion_id: String,
            name: String,
            channel: String,
            version: String,
            platform: String,
            artifact: String,
            compression: String,
            artifact_size: u64,
            artifact_sha256: String,
            binary_size: u64,
            binary_sha256: String,
            source_repo: String,
            source_git_sha: String,
            build_recipe_sha256: String,
            toolchain_digest: String,
            provenance_digest: String,
            builders: Vec<ManifestBuilder>,
            promoted_at: String,
        }
        let wire: Wire = serde_json::from_slice(bytes)?;
        if wire.schema != "tana.release-manifest.v1"
            || wire.algorithm != "ed25519"
            || wire.compression != "zstd-single-file"
        {
            return Err(schema(
                "manifest schema, algorithm, or compression literal is invalid",
            ));
        }
        if wire.key_id != verified_key {
            return Err(schema(
                "manifest key_id differs from the pinned release key that verified its bytes",
            ));
        }
        if wire.name != request.name.as_str()
            || wire.channel != request.channel.as_str()
            || wire.platform != request.target.as_str()
        {
            return Err(schema(
                "manifest identity does not match the update request",
            ));
        }
        let version = strict_version(&wire.version)?;
        if &version != requested_version {
            return Err(schema("manifest version differs from the selected version"));
        }
        let expected_artifact = format!(
            "{}-{}-{}.zst",
            request.name.as_str(),
            version,
            request.target.as_str()
        );
        validate_artifact_name(&wire.artifact)?;
        if wire.artifact != expected_artifact {
            return Err(schema(
                "artifact basename is not derived from signed identity",
            ));
        }
        if wire.artifact_size == 0
            || wire.artifact_size > super::MAX_ARTIFACT_BYTES as u64
            || wire.binary_size == 0
            || wire.binary_size > super::MAX_ARTIFACT_BYTES as u64
        {
            return Err(schema("manifest sizes are outside the allowed range"));
        }
        validate_lower_hex("artifact_sha256", &wire.artifact_sha256, 64)?;
        validate_lower_hex("binary_sha256", &wire.binary_sha256, 64)?;
        validate_nonempty_segment("promotion_id", &wire.promotion_id)?;
        validate_repo(&wire.source_repo)?;
        validate_lower_hex("source_git_sha", &wire.source_git_sha, 40)?;
        validate_lower_hex("build_recipe_sha256", &wire.build_recipe_sha256, 64)?;
        validate_prefixed_digest("toolchain_digest", &wire.toolchain_digest)?;
        validate_prefixed_digest("provenance_digest", &wire.provenance_digest)?;
        strict_timestamp("promoted_at", &wire.promoted_at)?;
        if wire.builders.len() != 2 {
            return Err(schema("manifest must contain exactly two builders"));
        }
        for builder in &wire.builders {
            validate_nonempty_segment("builder_id", &builder.builder_id)?;
            validate_nonempty_segment("run_id", &builder.run_id)?;
            validate_lower_hex("attestation_sha256", &builder.attestation_sha256, 64)?;
        }
        if wire.builders[0].builder_id >= wire.builders[1].builder_id
            || wire.builders[0].run_id == wire.builders[1].run_id
        {
            return Err(schema(
                "manifest builders must have sorted distinct identities and run IDs",
            ));
        }
        Ok(Self {
            schema: wire.schema,
            algorithm: wire.algorithm,
            key_id: wire.key_id,
            promotion_id: wire.promotion_id,
            name: wire.name,
            channel: wire.channel,
            version_text: wire.version,
            platform: wire.platform,
            artifact: wire.artifact,
            compression: wire.compression,
            artifact_size: wire.artifact_size,
            artifact_sha256: wire.artifact_sha256,
            binary_size: wire.binary_size,
            binary_sha256: wire.binary_sha256,
            source_repo: wire.source_repo,
            source_git_sha: wire.source_git_sha,
            build_recipe_sha256: wire.build_recipe_sha256,
            toolchain_digest: wire.toolchain_digest,
            provenance_digest: wire.provenance_digest,
            builders: wire.builders,
            promoted_at: wire.promoted_at,
        })
    }

    pub(super) fn touch_fields_for_closed_schema(&self) {
        let _ = (
            &self.schema,
            &self.algorithm,
            &self.name,
            &self.channel,
            &self.version_text,
            &self.platform,
            &self.compression,
            &self.source_repo,
            &self.source_git_sha,
            &self.build_recipe_sha256,
            &self.toolchain_digest,
            &self.provenance_digest,
            &self.builders,
            &self.promoted_at,
        );
    }
}

fn strict_version(value: &str) -> Result<Version, UpdateError> {
    if value.starts_with('v') {
        return Err(schema("version must not have a leading v"));
    }
    let parsed =
        Version::parse(value).map_err(|error| schema(format!("invalid SemVer: {error}")))?;
    if parsed.to_string() != value {
        return Err(schema("version is not normalized strict SemVer"));
    }
    Ok(parsed)
}

fn strict_timestamp(label: &str, value: &str) -> Result<DateTime<Utc>, UpdateError> {
    if value.len() != 20 || !value.ends_with('Z') {
        return Err(schema(format!(
            "{label} must be UTC RFC3339 whole seconds ending in Z"
        )));
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|error| schema(format!("invalid {label}: {error}")))?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != value {
        return Err(schema(format!("{label} is not strict UTC RFC3339")));
    }
    Ok(parsed)
}

fn validate_lower_hex(label: &str, value: &str, len: usize) -> Result<(), UpdateError> {
    if value.len() != len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(schema(format!(
            "{label} must be exactly {len} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_prefixed_digest(label: &str, value: &str) -> Result<(), UpdateError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| schema(format!("{label} must start with sha256:")))?;
    validate_lower_hex(label, digest, 64)
}

fn validate_artifact_name(value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.contains("..")
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b'/' | b'\\' | b'%' | b':' | b'?' | b'#' | b'@')
        })
    {
        return Err(schema("artifact is not a safe derived basename"));
    }
    Ok(())
}

fn validate_nonempty_segment(label: &str, value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.bytes().any(|byte| {
            byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b'%' | b':' | b'?' | b'#')
        })
    {
        return Err(schema(format!("{label} is not a safe identifier")));
    }
    Ok(())
}

fn validate_repo(value: &str) -> Result<(), UpdateError> {
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(schema("source_repo must be owner/repository"));
    }
    validate_nonempty_segment("source repository owner", owner)?;
    validate_nonempty_segment("source repository name", repo)
}

fn schema(message: impl Into<String>) -> UpdateError {
    UpdateError::Schema(message.into())
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), UpdateError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    NoDuplicates.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

struct NoDuplicates;

impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicatesVisitor)
    }
}

struct NoDuplicatesVisitor;

impl<'de> Visitor<'de> for NoDuplicatesVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            map.next_value_seed(NoDuplicates)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(NoDuplicates)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
}
