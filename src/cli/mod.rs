//! High-level integration surface shared by every Tana Rust CLI.

mod auth;
mod self_service;
mod setup;

use std::{path::PathBuf, time::Duration};

use semver::Version;
use thiserror::Error;

use crate::{CliName, ReleaseChannel, TokenFileError, UpdateError, WhoamiError};

pub use auth::{AuthSpec, LoginOptions};
pub use self_service::{HealthStatus, MonitorReport, SelfAction, SelfOutcome};
pub use setup::{
    SetupAction, SetupContext, SetupError, SetupOptions, SetupPlan, SetupReport, SetupStep,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthProbe {
    argv: &'static [&'static str],
}

impl HealthProbe {
    pub const fn argv(argv: &'static [&'static str]) -> Self {
        Self { argv }
    }

    fn owned_argv(&self) -> Vec<String> {
        self.argv.iter().map(|value| (*value).to_owned()).collect()
    }
}

#[derive(Clone, Debug)]
pub struct ProductSpec {
    pub name: CliName,
    pub version: &'static str,
    pub default_channel: ReleaseChannel,
    pub release_origin: &'static str,
    pub install_name: &'static str,
    pub health: HealthProbe,
    pub auth: Option<AuthSpec>,
}

impl ProductSpec {
    pub fn new(
        name: &'static str,
        version: &'static str,
        release_origin: &'static str,
        health: HealthProbe,
    ) -> Result<Self, CliCoreError> {
        Version::parse(version).map_err(|error| CliCoreError::Configuration(error.to_string()))?;
        if health.argv.is_empty() {
            return Err(CliCoreError::Configuration(
                "health probe argv must not be empty".into(),
            ));
        }
        Ok(Self {
            name: CliName::new(name)?,
            version,
            default_channel: ReleaseChannel::Stable,
            release_origin,
            install_name: name,
            health,
            auth: None,
        })
    }

    pub fn with_auth(mut self, auth: AuthSpec) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn with_install_name(mut self, install_name: &'static str) -> Self {
        self.install_name = install_name;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliPaths {
    pub bin_dir: PathBuf,
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl CliPaths {
    pub fn from_xdg() -> Result<Self, CliCoreError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| CliCoreError::Configuration("HOME is not set".into()))?;
        Ok(Self {
            bin_dir: env_path("XDG_BIN_HOME").unwrap_or_else(|| home.join(".local/bin")),
            config_dir: env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            state_dir: env_path("XDG_STATE_HOME").unwrap_or_else(|| home.join(".local/state")),
        })
    }

    pub fn install_path(&self, product: &ProductSpec) -> PathBuf {
        self.bin_dir.join(product.install_name)
    }

    pub fn trust_dir(&self) -> PathBuf {
        self.config_dir.join("tana/trust")
    }

    pub fn token_path(&self) -> PathBuf {
        self.config_dir.join("tana/token")
    }

    pub fn setup_state_path(&self, product: &ProductSpec) -> PathBuf {
        self.state_dir
            .join("tana/setup")
            .join(format!("{}.json", product.name.as_str()))
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[derive(Debug)]
pub struct SharedCli {
    pub product: ProductSpec,
    pub paths: CliPaths,
    timeout: Duration,
}

impl SharedCli {
    pub fn from_xdg(product: ProductSpec) -> Result<Self, CliCoreError> {
        Ok(Self::with_paths(product, CliPaths::from_xdg()?))
    }

    pub fn with_paths(product: ProductSpec, paths: CliPaths) -> Self {
        Self {
            product,
            paths,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, CliCoreError> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(CliCoreError::Configuration(
                "timeout must be between 1ns and 300 seconds".into(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum CliCoreError {
    #[error("shared CLI configuration is invalid: {0}")]
    Configuration(String),
    #[error(transparent)]
    Update(#[from] UpdateError),
    #[error(transparent)]
    Token(#[from] TokenFileError),
    #[error(transparent)]
    Identity(#[from] WhoamiError),
    #[error(transparent)]
    Setup(#[from] SetupError),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("Ruba emission failed: {0}")]
    Ruba(String),
}

impl CliCoreError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Update(UpdateError::Transport(_)) => 40,
            Self::Update(
                UpdateError::Health(_)
                | UpdateError::LocalState(_)
                | UpdateError::Rollback(_)
                | UpdateError::Io(_),
            ) => 20,
            Self::Update(_) => 30,
            Self::Ruba(_) => 40,
            _ => 1,
        }
    }
}

pub(crate) fn detect_target() -> Result<crate::TargetTriple, CliCoreError> {
    let target = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else {
        return Err(CliCoreError::Configuration(
            "this OS/architecture has no signed release target".into(),
        ));
    };
    Ok(crate::TargetTriple::new(target)?)
}
