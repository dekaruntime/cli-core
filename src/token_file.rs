use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const TOKEN_FILE_MODE: u32 = 0o600;

#[derive(Clone, Eq, PartialEq)]
pub struct SecretToken(String);

impl SecretToken {
    pub fn new(value: impl Into<String>) -> Result<Self, TokenFileError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(TokenFileError::InvalidToken("token is empty"));
        }
        if trimmed.as_bytes().iter().any(|b| b.is_ascii_control()) {
            return Err(TokenFileError::InvalidToken(
                "token contains control characters",
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_path() -> Result<PathBuf, TokenFileError> {
        let home = std::env::var_os("HOME").ok_or(TokenFileError::HomeNotSet)?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("tana")
            .join("token"))
    }

    pub fn default_store() -> Result<Self, TokenFileError> {
        Ok(Self::new(Self::default_path()?))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_token(&self) -> Result<Option<SecretToken>, TokenFileError> {
        match fs::metadata(&self.path) {
            Ok(metadata) => {
                validate_file_mode(&self.path, &metadata)?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(TokenFileError::Io {
                    path: self.path.clone(),
                    source: err,
                })
            }
        }

        let raw = fs::read_to_string(&self.path).map_err(|source| TokenFileError::Io {
            path: self.path.clone(),
            source,
        })?;
        SecretToken::new(raw).map(Some)
    }

    pub fn write_token(&self, token: &SecretToken) -> Result<(), TokenFileError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| TokenFileError::InvalidPath(self.path.clone()))?;
        fs::create_dir_all(parent).map_err(|source| TokenFileError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

        let tmp_path = self.temp_path();
        let write_result = write_token_file(&tmp_path, token).and_then(|file| {
            file.sync_all().map_err(|source| TokenFileError::Io {
                path: tmp_path.clone(),
                source,
            })?;
            drop(file);
            fs::rename(&tmp_path, &self.path).map_err(|source| TokenFileError::Io {
                path: self.path.clone(),
                source,
            })?;
            sync_dir(parent)?;
            Ok(())
        });

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }

        write_result
    }

    fn temp_path(&self) -> PathBuf {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = self
            .path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("token");
        self.path
            .with_file_name(format!(".{name}.{pid}.{nanos}.tmp"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenFileError {
    #[error("HOME is not set")]
    HomeNotSet,
    #[error("invalid token path: {0}")]
    InvalidPath(PathBuf),
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),
    #[error("refusing to read token file {path}: expected mode 0600, got {mode:o}")]
    InsecureMode { path: PathBuf, mode: u32 },
    #[error("token path {0} is not a regular file")]
    NotRegularFile(PathBuf),
    #[error("token file operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn write_token_file(path: &Path, token: &SecretToken) -> Result<File, TokenFileError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(TOKEN_FILE_MODE);

    let mut file = options.open(path).map_err(|source| TokenFileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(token.expose_secret().as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|source| TokenFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(TOKEN_FILE_MODE))
        .map_err(|source| TokenFileError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(file)
}

fn validate_file_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), TokenFileError> {
    if !metadata.is_file() {
        return Err(TokenFileError::NotRegularFile(path.to_path_buf()));
    }

    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode != TOKEN_FILE_MODE {
            return Err(TokenFileError::InsecureMode {
                path: path.to_path_buf(),
                mode,
            });
        }
    }

    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), TokenFileError> {
    match File::open(path) {
        Ok(dir) => dir.sync_all().map_err(|source| TokenFileError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(source) => Err(TokenFileError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_token_debug_is_redacted() {
        let token = SecretToken::new("tg_usr_secretvalue").unwrap();
        let rendered = format!("{token:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("secretvalue"));
    }

    #[test]
    fn read_missing_token_returns_none() {
        let temp = tempfile::tempdir().unwrap();
        let store = TokenStore::new(temp.path().join("token"));
        assert!(store.read_token().unwrap().is_none());
    }

    #[test]
    fn write_then_read_roundtrips_and_uses_0600() {
        let temp = tempfile::tempdir().unwrap();
        let store = TokenStore::new(temp.path().join("config").join("tana").join("token"));
        let token = SecretToken::new("tg_usr_roundtrip").unwrap();

        store.write_token(&token).unwrap();

        let read = store.read_token().unwrap().unwrap();
        assert_eq!(read.expose_secret(), "tg_usr_roundtrip");

        #[cfg(unix)]
        {
            let mode = fs::metadata(store.path()).unwrap().mode() & 0o777;
            assert_eq!(mode, TOKEN_FILE_MODE);
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_insecure_mode() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("token");
        fs::write(&path, "tg_usr_insecure\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let store = TokenStore::new(path);
        let err = store.read_token().unwrap_err();
        assert!(matches!(
            err,
            TokenFileError::InsecureMode { mode: 0o644, .. }
        ));
    }
}
