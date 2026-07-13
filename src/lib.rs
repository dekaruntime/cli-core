//! Shared primitives for Tana Rust CLIs.
//!
//! Security-sensitive operations live behind high-level, shared primitives so
//! individual CLIs cannot accidentally weaken their invariants.

pub mod pulse_client;
pub mod token_file;
mod update;
pub mod whoami;

pub use token_file::{SecretToken, TokenStore};
pub use update::{
    verify_and_install, AtomicInstaller, CliName, HttpReleaseTransport, InstalledRelease,
    ReleaseChannel, ReleaseCoordinates, ReleaseTransport, TargetTriple, TransportError, TrustStore,
    UpdateError, UpdateRequest, VerifiedArtifact, VersionSelector,
};
pub use whoami::{Identity, LinkhashClient, Principal};
