use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CliCoreError, CliPaths, ProductSpec, SharedCli};

#[derive(Clone, Debug)]
pub struct SetupContext<'a> {
    pub product: &'a ProductSpec,
    pub paths: &'a CliPaths,
}

pub trait SetupPlan {
    fn steps(&self) -> &[SetupStep];
    fn validate(&self, context: &SetupContext<'_>) -> Result<(), SetupError>;
}

#[derive(Clone, Debug)]
pub struct SetupStep {
    pub id: &'static str,
    pub description: &'static str,
    pub action: SetupAction,
}

#[derive(Clone, Debug)]
pub enum SetupAction {
    EnsureDirectory {
        path: PathBuf,
    },
    WriteFile {
        path: PathBuf,
        contents: String,
        secret: bool,
    },
    Run {
        program: PathBuf,
        argv: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SetupOptions {
    pub non_interactive: bool,
    pub assume_yes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupReport {
    pub completed: Vec<String>,
    pub skipped: Vec<String>,
    pub state_path: PathBuf,
}

impl SetupReport {
    pub fn print(&self) {
        println!(
            "setup complete: {} applied, {} already current",
            self.completed.len(),
            self.skipped.len()
        );
    }
}

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("setup plan is invalid: {0}")]
    Invalid(String),
    #[error("setup was declined")]
    Declined,
    #[error("setup I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("setup command {program} failed with {status}")]
    Command { program: String, status: String },
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SetupState {
    schema: String,
    completed: BTreeSet<String>,
}

impl SharedCli {
    pub fn setup<P: SetupPlan>(
        &self,
        plan: &P,
        options: SetupOptions,
    ) -> Result<SetupReport, CliCoreError> {
        validate_steps(plan.steps())?;
        let context = SetupContext {
            product: &self.product,
            paths: &self.paths,
        };
        let state_path = self.paths.setup_state_path(&self.product);
        let mut state = read_state(&state_path)?;
        let mut report = SetupReport {
            completed: Vec::new(),
            skipped: Vec::new(),
            state_path: state_path.clone(),
        };
        for step in plan.steps() {
            if state.completed.contains(step.id) && step_is_current(step)? {
                report.skipped.push(step.id.into());
                continue;
            }
            confirm(step, options)?;
            apply_step(step)?;
            state.completed.insert(step.id.into());
            write_state(&state_path, &state)?;
            report.completed.push(step.id.into());
        }
        plan.validate(&context)?;
        Ok(report)
    }
}

fn validate_steps(steps: &[SetupStep]) -> Result<(), SetupError> {
    let mut ids = BTreeSet::new();
    for step in steps {
        if step.id.is_empty()
            || !step
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !ids.insert(step.id)
        {
            return Err(SetupError::Invalid(format!(
                "step IDs must be unique safe identifiers: {}",
                step.id
            )));
        }
    }
    Ok(())
}

fn confirm(step: &SetupStep, options: SetupOptions) -> Result<(), SetupError> {
    if options.assume_yes {
        return Ok(());
    }
    if options.non_interactive {
        return Err(SetupError::Invalid(format!(
            "non-interactive setup requires assume_yes for step {}",
            step.id
        )));
    }
    eprint!("{} [y/N] ", step.description);
    io::stderr().flush().map_err(|source| SetupError::Io {
        path: PathBuf::from("<stderr>"),
        source,
    })?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|source| SetupError::Io {
            path: PathBuf::from("<stdin>"),
            source,
        })?;
    if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(SetupError::Declined)
    }
}

fn step_is_current(step: &SetupStep) -> Result<bool, SetupError> {
    match &step.action {
        SetupAction::EnsureDirectory { path } => Ok(path.is_dir()),
        SetupAction::WriteFile { path, contents, .. } => match fs::read(path) {
            Ok(bytes) => Ok(bytes == contents.as_bytes()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(io_error(path, source)),
        },
        SetupAction::Run { .. } => Ok(true),
    }
}

fn apply_step(step: &SetupStep) -> Result<(), SetupError> {
    match &step.action {
        SetupAction::EnsureDirectory { path } => {
            fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
        }
        SetupAction::WriteFile {
            path,
            contents,
            secret,
        } => {
            atomic_write(path, contents.as_bytes(), *secret)?;
        }
        SetupAction::Run { program, argv } => {
            let status = Command::new(program)
                .args(argv)
                .status()
                .map_err(|source| io_error(program, source))?;
            if !status.success() {
                return Err(SetupError::Command {
                    program: program.display().to_string(),
                    status: status.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<SetupState, SetupError> {
    match fs::read(path) {
        Ok(bytes) => {
            let state: SetupState = serde_json::from_slice(&bytes)
                .map_err(|error| SetupError::Invalid(format!("invalid setup state: {error}")))?;
            if state.schema != "tana.cli-setup.v1" {
                return Err(SetupError::Invalid("unknown setup state schema".into()));
            }
            Ok(state)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SetupState {
            schema: "tana.cli-setup.v1".into(),
            completed: BTreeSet::new(),
        }),
        Err(source) => Err(io_error(path, source)),
    }
}

fn write_state(path: &Path, state: &SetupState) -> Result<(), SetupError> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| SetupError::Invalid(format!("serialize setup state: {error}")))?;
    atomic_write(path, &bytes, true)
}

fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<(), SetupError> {
    let parent = path
        .parent()
        .ok_or_else(|| SetupError::Invalid("setup path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| SetupError::Invalid("setup path has no filename".into()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|source| io_error(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| io_error(&temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| io_error(path, source))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn io_error(path: &Path, source: io::Error) -> SetupError {
    SetupError::Io {
        path: path.to_path_buf(),
        source,
    }
}
