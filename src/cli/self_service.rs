use std::{fmt, time::Duration};

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    inspect_signed_installation, verify_and_install, AtomicInstaller, HttpReleaseTransport,
    InstalledRelease, TrustStore, UpdateRequest, VersionSelector,
};

use super::{detect_target, CliCoreError, SharedCli};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelfAction {
    Update {
        check_only: bool,
        exact: Option<Version>,
        allow_major: bool,
    },
    Monitor {
        emit_to_ruba: bool,
        json: bool,
    },
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MonitorReport {
    pub name: String,
    pub installed_version: Version,
    pub installed_digest: String,
    pub latest_version: Option<Version>,
    pub update_available: bool,
    pub health: HealthStatus,
    pub key_id: String,
    pub anchor_generation: u64,
    pub checked_at: DateTime<Utc>,
}

impl fmt::Display for MonitorReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} ({}) — health: {:?}, latest: {}, update available: {}",
            self.name,
            self.installed_version,
            self.installed_digest,
            self.health,
            self.latest_version
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unavailable".into()),
            self.update_available
        )
    }
}

#[derive(Debug)]
pub enum SelfOutcome {
    Updated(InstalledRelease),
    Checked(MonitorReport),
    Monitored { report: MonitorReport, json: bool },
    RolledBack(InstalledRelease),
}

impl SelfOutcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Checked(report) | Self::Monitored { report, .. }
                if report.health == HealthStatus::Failed =>
            {
                20
            }
            Self::Checked(report) if report.update_available => 10,
            _ => 0,
        }
    }

    pub fn print(&self) -> Result<(), CliCoreError> {
        match self {
            Self::Checked(report)
            | Self::Monitored {
                report,
                json: false,
            } => {
                println!("{report}");
            }
            Self::Monitored { report, json: true } => println!(
                "{}",
                serde_json::to_string(report)
                    .map_err(|error| CliCoreError::Configuration(error.to_string()))?
            ),
            Self::Updated(release) => println!(
                "installed {} {} ({})",
                release.name(),
                release.version(),
                release.binary_sha256()
            ),
            Self::RolledBack(release) => println!(
                "rolled back {} to {} ({})",
                release.name(),
                release.version(),
                release.binary_sha256()
            ),
        }
        Ok(())
    }
}

impl SharedCli {
    pub fn run_self(&self, action: SelfAction) -> Result<SelfOutcome, CliCoreError> {
        if matches!(
            action,
            SelfAction::Update {
                check_only: true,
                exact: Some(_),
                ..
            }
        ) {
            return Err(CliCoreError::Configuration(
                "--check and an exact version cannot be combined".into(),
            ));
        }
        let transport = HttpReleaseTransport::new(self.product.release_origin, self.timeout)
            .map_err(crate::UpdateError::from)?;
        let health = self.product.health.owned_argv();
        let installer =
            AtomicInstaller::with_health_probe(self.timeout.min(Duration::from_secs(300)), health)?;
        let mut trust = TrustStore::open(self.paths.trust_dir())?;
        let target = detect_target()?;
        let install_path = self.paths.install_path(&self.product);

        match action {
            SelfAction::Update {
                check_only: true, ..
            } => Ok(SelfOutcome::Checked(self.monitor_report(
                &transport,
                &installer,
                &mut trust,
                target,
                install_path,
            )?)),
            SelfAction::Monitor {
                emit_to_ruba: should_emit,
                json,
            } => {
                let report =
                    self.monitor_report(&transport, &installer, &mut trust, target, install_path)?;
                if should_emit {
                    self.emit_monitor_report(&report)?;
                }
                Ok(SelfOutcome::Monitored { report, json })
            }
            SelfAction::Update {
                exact, allow_major, ..
            } => {
                let selector = exact.map_or(
                    VersionSelector::Latest {
                        allow_major_upgrade: allow_major,
                    },
                    VersionSelector::Exact,
                );
                let installed = verify_and_install(
                    self.request(target, install_path, selector),
                    &transport,
                    &installer,
                    &mut trust,
                )?;
                Ok(SelfOutcome::Updated(installed))
            }
            SelfAction::Rollback => {
                let installed = verify_and_install(
                    self.request(target, install_path, VersionSelector::Rollback),
                    &transport,
                    &installer,
                    &mut trust,
                )?;
                Ok(SelfOutcome::RolledBack(installed))
            }
        }
    }

    pub fn emit_monitor_report(&self, report: &MonitorReport) -> Result<(), CliCoreError> {
        emit_to_ruba(report, self.timeout)
    }

    fn request(
        &self,
        target: crate::TargetTriple,
        install_path: std::path::PathBuf,
        selector: VersionSelector,
    ) -> UpdateRequest {
        UpdateRequest {
            name: self.product.name.clone(),
            channel: self.product.default_channel,
            target,
            selector,
            install_path,
            state_dir: Some(
                self.paths
                    .state_dir
                    .join("tana/releases")
                    .join(self.product.name.as_str()),
            ),
        }
    }

    fn monitor_report(
        &self,
        transport: &HttpReleaseTransport,
        installer: &AtomicInstaller,
        trust: &mut TrustStore,
        target: crate::TargetTriple,
        install_path: std::path::PathBuf,
    ) -> Result<MonitorReport, CliCoreError> {
        let status = inspect_signed_installation(
            self.request(
                target,
                install_path,
                VersionSelector::Latest {
                    allow_major_upgrade: true,
                },
            ),
            transport,
            installer,
            trust,
        )?;
        Ok(MonitorReport {
            name: self.product.name.as_str().into(),
            installed_version: status.local.version,
            installed_digest: status.local.binary_sha256,
            latest_version: Some(status.latest_version),
            update_available: status.update_available,
            health: if status.local.health_ok {
                HealthStatus::Healthy
            } else {
                HealthStatus::Failed
            },
            key_id: status.local.release_key_id,
            anchor_generation: status.local.anchor_generation,
            checked_at: Utc::now(),
        })
    }
}

fn emit_to_ruba(report: &MonitorReport, timeout: Duration) -> Result<(), CliCoreError> {
    let origin =
        std::env::var("RUBA_URL").map_err(|_| CliCoreError::Ruba("RUBA_URL is not set".into()))?;
    let token = std::env::var("RUBA_SOURCE_TOKEN")
        .map_err(|_| CliCoreError::Ruba("RUBA_SOURCE_TOKEN is not set".into()))?;
    let endpoint = ruba_endpoint(&origin)?;
    let body = serde_json::json!({
        "source_id": format!("cli.{}", report.name),
        "events": [{
            "kind": "cli.self.monitor",
            "ts": report.checked_at.timestamp_millis(),
            "payload": {
                "actor": format!("cli.{}", report.name),
                "name": report.name,
                "installed_version": report.installed_version,
                "installed_digest": report.installed_digest,
                "latest_version": report.latest_version,
                "update_available": report.update_available,
                "health": report.health,
                "key_id": report.key_id,
                "anchor_generation": report.anchor_generation,
                "checked_at": report.checked_at,
            },
        }],
    });
    let response = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .and_then(|client| client.post(endpoint).bearer_auth(token).json(&body).send())
        .map_err(|error| CliCoreError::Ruba(error.to_string()))?;
    if !response.status().is_success() {
        return Err(CliCoreError::Ruba(format!(
            "Ruba returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

fn ruba_endpoint(origin: &str) -> Result<reqwest::Url, CliCoreError> {
    let mut url = reqwest::Url::parse(origin)
        .map_err(|error| CliCoreError::Ruba(format!("RUBA_URL is invalid: {error}")))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliCoreError::Ruba(
            "RUBA_URL must not contain credentials, a query, or a fragment".into(),
        ));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CliCoreError::Ruba(
            "RUBA_URL must use HTTPS (HTTP is allowed only for loopback)".into(),
        ));
    }
    url.set_path(&format!("{}/v1/push", url.path().trim_end_matches('/')));
    Ok(url)
}
