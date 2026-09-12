//! Shared primitives for Tana Rust CLIs.
//!
//! Security-sensitive operations live behind high-level, shared primitives so
//! individual CLIs cannot accidentally weaken their invariants.

#[cfg(feature = "registry")]
pub mod registry;

#[cfg(feature = "native")]
pub mod cli;
#[cfg(feature = "native")]
pub mod pulse_client;
#[cfg(feature = "native")]
pub mod token_file;
#[cfg(feature = "native")]
mod update;
#[cfg(feature = "native")]
pub mod whoami;

#[cfg(feature = "registry")]
pub use registry::{
    Args, BuildError, CommandSpec, Context, ContextError, DispatchError, EnvContext, Extensions,
    FlagSpec, ParamSpec, ParseError, ParseErrorKind, ParseOutcome, Registry, RegistryBuilder,
    SubcommandSpec,
};

#[cfg(feature = "native")]
pub use cli::{
    AuthSpec, CliCoreError, CliPaths, HealthProbe, HealthStatus, LoginOptions, MonitorReport,
    ProductSpec, SelfAction, SelfOutcome, SetupAction, SetupContext, SetupError, SetupOptions,
    SetupPlan, SetupReport, SetupStep, SharedCli,
};
#[cfg(feature = "native")]
pub use token_file::{SecretToken, TokenFileError, TokenStore};
#[cfg(feature = "native")]
pub use update::{
    build_bootstrap_anchor_set, inspect_signed_installation, verify_and_install, AtomicInstaller,
    BootstrapAnchorSet, CliName, HttpReleaseTransport, InstalledRelease, LocalInstallation,
    ReleaseChannel, ReleaseCoordinates, ReleaseTransport, SignedInstallationStatus, TargetTriple,
    TransportError, TrustStore, UpdateError, UpdateRequest, VerifiedArtifact, VersionSelector,
};
#[cfg(feature = "native")]
pub use whoami::{validate_linkhash_origin, Identity, LinkhashClient, Principal, WhoamiError};
