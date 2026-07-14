//! Shared primitives for Tana Rust CLIs.
//!
//! Security-sensitive operations live behind high-level, shared primitives so
//! individual CLIs cannot accidentally weaken their invariants.

pub mod cli;
pub mod pulse_client;
pub mod token_file;
mod update;
pub mod whoami;

pub use cli::{
    AuthSpec, CliCoreError, CliPaths, HealthProbe, HealthStatus, LoginOptions, MonitorReport,
    ProductSpec, SelfAction, SelfOutcome, SetupAction, SetupContext, SetupError, SetupOptions,
    SetupPlan, SetupReport, SetupStep, SharedCli,
};
pub use token_file::{SecretToken, TokenFileError, TokenStore};
pub use update::{
    build_bootstrap_anchor_set, inspect_signed_installation, verify_and_install, AtomicInstaller,
    BootstrapAnchorSet, CliName, HttpReleaseTransport, InstalledRelease, LocalInstallation,
    ReleaseChannel, ReleaseCoordinates, ReleaseTransport, SignedInstallationStatus, TargetTriple,
    TransportError, TrustStore, UpdateError, UpdateRequest, VerifiedArtifact, VersionSelector,
};
pub use whoami::{Identity, LinkhashClient, Principal, WhoamiError};
