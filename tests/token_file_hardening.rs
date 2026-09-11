use std::fs;
use std::sync::Arc;
use std::thread;

use deka_cli_core::{token_file::TokenFileError, SecretToken, TokenStore};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
#[test]
fn write_replaces_world_readable_existing_token_with_private_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("token");
    fs::write(&path, "tg_usr_old\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let store = TokenStore::new(&path);
    let token = SecretToken::new("tg_usr_replacement").unwrap();
    store.write_token(&token).unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "tg_usr_replacement\n");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        store.read_token().unwrap().unwrap().expose_secret(),
        "tg_usr_replacement"
    );
}

#[cfg(unix)]
#[test]
fn concurrent_writes_leave_a_complete_private_token_and_no_temp_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config").join("tana").join("token");
    let store = Arc::new(TokenStore::new(&path));
    let expected = (0..16)
        .map(|i| format!("tg_usr_concurrent_{i}"))
        .collect::<Vec<_>>();

    let mut handles = Vec::new();
    for value in expected.iter().cloned() {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let token = SecretToken::new(value).unwrap();
            store.write_token(&token).unwrap();
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.ends_with('\n'));
    let final_token = raw.trim_end_matches('\n');
    assert!(expected.iter().any(|candidate| candidate == final_token));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        store.read_token().unwrap().unwrap().expose_secret(),
        final_token
    );

    let token_dir = path.parent().unwrap();
    let temp_files = fs::read_dir(token_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".token.") && name.ends_with(".tmp"))
        .collect::<Vec<_>>();
    assert!(temp_files.is_empty(), "leftover temp files: {temp_files:?}");
}

#[cfg(unix)]
#[test]
fn read_rejects_directory_token_paths() {
    let temp = tempfile::tempdir().unwrap();
    let directory_path = temp.path().join("token-dir");
    fs::create_dir(&directory_path).unwrap();
    let directory_store = TokenStore::new(&directory_path);
    assert!(format!("{:?}", directory_store.read_token().unwrap_err()).contains("NotRegularFile"));
}

#[cfg(unix)]
#[test]
fn read_rejects_world_readable_token_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("token");
    fs::write(&path, "tg_usr_world_readable\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let store = TokenStore::new(&path);
    let err = store.read_token().unwrap_err();

    assert!(matches!(
        err,
        TokenFileError::InsecureMode { mode: 0o644, .. }
    ));
}

#[cfg(unix)]
#[test]
fn read_rejects_malformed_token_files_without_leaking_secret() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("token");
    fs::write(&path, "tg_usr_malformed_secret\nsecond_line\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let store = TokenStore::new(&path);
    let err = store.read_token().unwrap_err();
    let rendered = err.to_string();

    assert!(matches!(err, TokenFileError::InvalidToken(_)));
    assert!(!rendered.contains("tg_usr_malformed_secret"));
    assert!(!rendered.contains("second_line"));
}

#[test]
fn token_core_does_not_put_secrets_on_subprocess_argv() {
    let token_file = include_str!("../src/token_file.rs");
    let whoami = include_str!("../src/whoami.rs");

    assert!(!token_file.contains("Command::new"));
    assert!(!whoami.contains("Command::new"));
    assert!(!token_file.contains("std::process::Command"));
    assert!(!whoami.contains("std::process::Command"));
    assert!(!token_file.contains("tokio::process::Command"));
    assert!(!whoami.contains("tokio::process::Command"));
}
