use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{sha256_hex, UpdateError};

pub(super) const ANCHOR_DOMAIN: &[u8] = b"tana.anchor-set.v1\n";

#[derive(Clone)]
pub(super) struct RootAnchor {
    pub key_id: String,
    pub key: VerifyingKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum KeyRole {
    Release,
    Freshness,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OnlineKey {
    pub role: KeyRole,
    pub key_id: String,
    pub public_key_base64: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub status: KeyStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublishedRoot {
    key_id: String,
    public_key_base64: String,
    fingerprint_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnchorSet {
    schema: String,
    pub generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    threshold: u8,
    roots: Vec<PublishedRoot>,
    pub keys: Vec<OnlineKey>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AnchorSignatures {
    schema: String,
    signatures: Vec<RootSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootSignature {
    key_id: String,
    algorithm: String,
    signature_base64: String,
}

impl AnchorSet {
    pub(super) fn compiled(generation: u64, roots: &[RootAnchor], keys: Vec<OnlineKey>) -> Self {
        Self {
            schema: "tana.anchor-set.v1".into(),
            generation,
            issued_at: "2026-01-01T00:00:00Z".parse().expect("fixed timestamp"),
            expires_at: "2030-01-01T00:00:00Z".parse().expect("fixed timestamp"),
            threshold: 1,
            roots: roots
                .iter()
                .map(|root| PublishedRoot {
                    key_id: root.key_id.clone(),
                    public_key_base64: BASE64.encode(root.key.as_bytes()),
                    fingerprint_sha256: sha256_hex(root.key.as_bytes()),
                })
                .collect(),
            keys,
        }
    }

    pub fn parse_and_verify(
        bytes: &[u8],
        signature_bytes: &[u8],
        roots: &[RootAnchor],
        trusted_threshold: u8,
        now: DateTime<Utc>,
    ) -> Result<Self, UpdateError> {
        let set: Self = serde_json::from_slice(bytes)
            .map_err(|error| UpdateError::Schema(format!("invalid anchor set: {error}")))?;
        if set.schema != "tana.anchor-set.v1" || set.generation == 0 {
            return Err(UpdateError::Schema(
                "anchor set schema/generation is invalid".into(),
            ));
        }
        if set.issued_at > now || set.expires_at <= now || set.issued_at >= set.expires_at {
            return Err(UpdateError::Freshness(
                "anchor set is not currently valid".into(),
            ));
        }
        if set.threshold == 0
            || usize::from(set.threshold) > roots.len()
            || trusted_threshold == 0
            || usize::from(trusted_threshold) > roots.len()
        {
            return Err(UpdateError::Schema("anchor threshold is invalid".into()));
        }
        set.validate_roots(roots)?;
        set.validate_keys()?;

        let signatures: AnchorSignatures = serde_json::from_slice(signature_bytes)
            .map_err(|error| UpdateError::Schema(format!("invalid anchor signatures: {error}")))?;
        if signatures.schema != "tana.anchor-signatures.v1" {
            return Err(UpdateError::Schema(
                "anchor signature schema is invalid".into(),
            ));
        }
        let mut message = Vec::with_capacity(ANCHOR_DOMAIN.len() + bytes.len());
        message.extend_from_slice(ANCHOR_DOMAIN);
        message.extend_from_slice(bytes);
        let mut valid = HashSet::new();
        for item in signatures.signatures {
            if item.algorithm != "ed25519" || valid.contains(&item.key_id) {
                continue;
            }
            let Some(root) = roots.iter().find(|root| root.key_id == item.key_id) else {
                continue;
            };
            let Ok(raw) = BASE64.decode(item.signature_base64) else {
                continue;
            };
            let Ok(signature) = Signature::from_slice(&raw) else {
                continue;
            };
            if root.key.verify_strict(&message, &signature).is_ok() {
                valid.insert(item.key_id);
            }
        }
        if valid.len() < usize::from(trusted_threshold) {
            return Err(UpdateError::BadSignature("anchor set"));
        }
        Ok(set)
    }

    pub(super) fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn active_key(
        &self,
        role: KeyRole,
        key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifyingKey, UpdateError> {
        let entry = self
            .keys
            .iter()
            .find(|entry| entry.role == role && entry.key_id == key_id)
            .ok_or(UpdateError::BadSignature(role.label()))?;
        if entry.status != KeyStatus::Active || now < entry.not_before || now >= entry.not_after {
            return Err(UpdateError::BadSignature(role.label()));
        }
        decode_key(&entry.public_key_base64)
    }

    fn validate_roots(&self, roots: &[RootAnchor]) -> Result<(), UpdateError> {
        if self.roots.len() != roots.len() {
            return Err(UpdateError::Schema(
                "anchor set root list differs from compiled roots".into(),
            ));
        }
        for root in roots {
            let published = self
                .roots
                .iter()
                .find(|published| published.key_id == root.key_id)
                .ok_or_else(|| UpdateError::Schema("compiled root is absent".into()))?;
            let raw = BASE64
                .decode(&published.public_key_base64)
                .map_err(|_| UpdateError::Schema("root public key is not base64".into()))?;
            if raw.as_slice() != root.key.as_bytes()
                || published.fingerprint_sha256 != sha256_hex(&raw)
            {
                return Err(UpdateError::Schema(
                    "published root does not match compiled root/fingerprint".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_keys(&self) -> Result<(), UpdateError> {
        if self.keys.is_empty() {
            return Err(UpdateError::Schema("anchor set has no online keys".into()));
        }
        let mut identities = HashSet::new();
        for key in &self.keys {
            if key.key_id.is_empty()
                || !identities.insert((key.role, key.key_id.as_str()))
                || key.not_before >= key.not_after
            {
                return Err(UpdateError::Schema(
                    "anchor set contains an invalid/duplicate online key".into(),
                ));
            }
            decode_key(&key.public_key_base64)?;
        }
        Ok(())
    }
}

/// Exact public anchor bytes and detached root signatures for initial provisioning.
pub struct BootstrapAnchorSet {
    pub anchor_set: Vec<u8>,
    pub signatures: Vec<u8>,
}

/// Build generation 1 using the verifier's closed schema and sign its exact bytes.
///
/// This is intentionally a narrow ceremony API used by `harar-anchor-init`; private
/// key file handling remains in that one-shot binary and key bytes are never logged.
pub fn build_bootstrap_anchor_set(
    root_a: &SigningKey,
    root_b: &SigningKey,
    release: &SigningKey,
    freshness: &SigningKey,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<BootstrapAnchorSet, UpdateError> {
    if issued_at >= expires_at {
        return Err(UpdateError::Schema(
            "anchor validity window must be positive".into(),
        ));
    }
    let roots = vec![
        RootAnchor {
            key_id: "harar-root-a".into(),
            key: root_a.verifying_key(),
        },
        RootAnchor {
            key_id: "harar-root-b".into(),
            key: root_b.verifying_key(),
        },
    ];
    let mut set = AnchorSet::compiled(
        1,
        &roots,
        vec![
            OnlineKey {
                role: KeyRole::Release,
                key_id: "harar-release-2026-preMVP".into(),
                public_key_base64: BASE64.encode(release.verifying_key().as_bytes()),
                not_before: issued_at,
                not_after: expires_at,
                status: KeyStatus::Active,
            },
            OnlineKey {
                role: KeyRole::Freshness,
                key_id: "harar-freshness-2026-preMVP".into(),
                public_key_base64: BASE64.encode(freshness.verifying_key().as_bytes()),
                not_before: issued_at,
                not_after: expires_at,
                status: KeyStatus::Active,
            },
        ],
    );
    set.issued_at = issued_at;
    set.expires_at = expires_at;
    let anchor_set = serde_json::to_vec(&set)?;
    let mut message = Vec::with_capacity(ANCHOR_DOMAIN.len() + anchor_set.len());
    message.extend_from_slice(ANCHOR_DOMAIN);
    message.extend_from_slice(&anchor_set);
    let signatures = serde_json::to_vec(&AnchorSignatures {
        schema: "tana.anchor-signatures.v1".into(),
        signatures: vec![
            RootSignature {
                key_id: "harar-root-a".into(),
                algorithm: "ed25519".into(),
                signature_base64: BASE64.encode(root_a.sign(&message).to_bytes()),
            },
            RootSignature {
                key_id: "harar-root-b".into(),
                algorithm: "ed25519".into(),
                signature_base64: BASE64.encode(root_b.sign(&message).to_bytes()),
            },
        ],
    })?;
    Ok(BootstrapAnchorSet {
        anchor_set,
        signatures,
    })
}

impl KeyRole {
    fn label(self) -> &'static str {
        match self {
            Self::Release => "release key",
            Self::Freshness => "freshness key",
        }
    }
}

fn decode_key(encoded: &str) -> Result<VerifyingKey, UpdateError> {
    let raw = BASE64
        .decode(encoded)
        .map_err(|_| UpdateError::Schema("online public key is not base64".into()))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| UpdateError::Schema("online public key is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| UpdateError::Schema(format!("online public key is invalid: {error}")))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    use super::*;

    #[test]
    fn bootstrap_builder_emits_bytes_accepted_by_the_verifier() {
        let root_a = SigningKey::from_bytes(&[51; 32]);
        let root_b = SigningKey::from_bytes(&[52; 32]);
        let release = SigningKey::from_bytes(&[53; 32]);
        let freshness = SigningKey::from_bytes(&[54; 32]);
        let issued_at = "2026-07-13T12:00:00Z".parse().unwrap();
        let expires_at = "2027-07-13T12:00:00Z".parse().unwrap();
        let output = build_bootstrap_anchor_set(
            &root_a, &root_b, &release, &freshness, issued_at, expires_at,
        )
        .unwrap();
        let roots = [
            RootAnchor {
                key_id: "harar-root-a".into(),
                key: root_a.verifying_key(),
            },
            RootAnchor {
                key_id: "harar-root-b".into(),
                key: root_b.verifying_key(),
            },
        ];
        let parsed = AnchorSet::parse_and_verify(
            &output.anchor_set,
            &output.signatures,
            &roots,
            1,
            "2026-08-01T00:00:00Z".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.generation, 1);
        assert!(parsed
            .keys
            .iter()
            .any(|key| key.key_id == "harar-release-2026-preMVP"));
        assert!(parsed
            .keys
            .iter()
            .any(|key| key.key_id == "harar-freshness-2026-preMVP"));
    }

    #[test]
    fn unknown_root_signer_does_not_help_meet_rotation_threshold() {
        let trusted_a = SigningKey::from_bytes(&[41; 32]);
        let trusted_b = SigningKey::from_bytes(&[42; 32]);
        let unknown = SigningKey::from_bytes(&[43; 32]);
        let online = SigningKey::from_bytes(&[44; 32]);
        let roots = [
            RootAnchor {
                key_id: "trusted-root-a".into(),
                key: trusted_a.verifying_key(),
            },
            RootAnchor {
                key_id: "trusted-root-b".into(),
                key: trusted_b.verifying_key(),
            },
        ];
        let mut set = AnchorSet::compiled(
            2,
            &roots,
            vec![OnlineKey {
                role: KeyRole::Release,
                key_id: "release-test".into(),
                public_key_base64: BASE64.encode(online.verifying_key().as_bytes()),
                not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
                not_after: "2030-01-01T00:00:00Z".parse().unwrap(),
                status: KeyStatus::Active,
            }],
        );
        set.threshold = 2;
        let bytes = serde_json::to_vec(&set).unwrap();
        let mut message = ANCHOR_DOMAIN.to_vec();
        message.extend_from_slice(&bytes);
        let signatures = serde_json::to_vec(&json!({
            "schema": "tana.anchor-signatures.v1",
            "signatures": [
                {
                    "key_id": "trusted-root-a",
                    "algorithm": "ed25519",
                    "signature_base64": BASE64.encode(trusted_a.sign(&message).to_bytes())
                },
                {
                    "key_id": "attacker-controlled-root",
                    "algorithm": "ed25519",
                    "signature_base64": BASE64.encode(unknown.sign(&message).to_bytes())
                }
            ]
        }))
        .unwrap();

        let error = AnchorSet::parse_and_verify(&bytes, &signatures, &roots, 2, Utc::now())
            .expect_err("one trusted plus one unknown signature must not satisfy 2-of-2");
        assert!(matches!(error, UpdateError::BadSignature("anchor set")));
    }
}
