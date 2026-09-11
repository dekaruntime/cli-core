use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
    time::Duration,
};

use deka_cli_core::{
    AuthSpec, CliPaths, HealthProbe, HealthStatus, LoginOptions, MonitorReport, ProductSpec,
    SecretToken, SelfOutcome, SetupAction, SetupContext, SetupError, SetupOptions, SetupPlan,
    SetupStep, SharedCli, TokenStore,
};

struct FixturePlan {
    steps: Vec<SetupStep>,
}

impl SetupPlan for FixturePlan {
    fn steps(&self) -> &[SetupStep] {
        &self.steps
    }

    fn validate(&self, _context: &SetupContext<'_>) -> Result<(), SetupError> {
        Ok(())
    }
}

fn product(auth_origin: &'static str) -> ProductSpec {
    ProductSpec::new(
        "gild",
        "1.2.3",
        "https://linkha.sh",
        HealthProbe::argv(&["--self-test"]),
    )
    .unwrap()
    .with_auth(AuthSpec::new(auth_origin))
}

fn paths(root: &std::path::Path) -> CliPaths {
    CliPaths {
        bin_dir: root.join("bin"),
        config_dir: root.join("config"),
        state_dir: root.join("state"),
    }
}

#[test]
fn setup_is_resumable_idempotent_and_keeps_secrets_private() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("product/config.json");
    let secret = temp.path().join("product/credential");
    let plan = FixturePlan {
        steps: vec![
            SetupStep {
                id: "config",
                description: "write config",
                action: SetupAction::WriteFile {
                    path: config.clone(),
                    contents: "{\"enabled\":true}\n".into(),
                    secret: false,
                },
            },
            SetupStep {
                id: "credential",
                description: "write credential",
                action: SetupAction::WriteFile {
                    path: secret.clone(),
                    contents: "do-not-log-this\n".into(),
                    secret: true,
                },
            },
        ],
    };
    let shared = SharedCli::with_paths(product("http://127.0.0.1:1"), paths(temp.path()));
    let options = SetupOptions {
        non_interactive: true,
        assume_yes: true,
    };

    let first = shared.setup(&plan, options).unwrap();
    let second = shared.setup(&plan, options).unwrap();

    assert_eq!(first.completed, vec!["config", "credential"]);
    assert_eq!(second.skipped, vec!["config", "credential"]);
    assert_eq!(fs::read_to_string(config).unwrap(), "{\"enabled\":true}\n");
    assert_eq!(fs::read_to_string(&secret).unwrap(), "do-not-log-this\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn login_validates_before_atomic_storage_and_logout_is_idempotent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
    thread::spawn(move || {
        for request_number in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 4096];
            let count = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]);
            assert!(request.contains("authorization: Bearer tg_usr_shared"));
            let body = if request_number < 2 {
                assert!(request.starts_with("GET /api/v1/whoami HTTP/1.1"));
                r#"{"ok":true,"principal":{"identity":{"id":"samira","kind":"agent","handle":"samira"},"token_id":41}}"#
            } else {
                assert!(request.starts_with("DELETE /api/tokens/41 HTTP/1.1"));
                r#"{"status":"revoked"}"#
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let shared = SharedCli::with_paths(product(origin), paths(temp.path()));

    let identity = shared
        .login(LoginOptions::token(
            SecretToken::new("tg_usr_shared").unwrap(),
        ))
        .unwrap();
    assert_eq!(identity.id, "samira");
    let token_path = temp.path().join("config/tana/token");
    assert!(token_path.exists());
    shared.logout().unwrap();
    shared.logout().unwrap();
    assert!(!token_path.exists());
}

#[test]
fn logout_keeps_local_token_when_server_revocation_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
    thread::spawn(move || {
        for request_number in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 4096];
            let count = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]);
            let (status, body) = if request_number == 0 {
                assert!(request.starts_with("GET /api/v1/whoami HTTP/1.1"));
                (
                    "200 OK",
                    r#"{"ok":true,"principal":{"identity":{"id":"samira"},"token_id":42}}"#,
                )
            } else {
                assert!(request.starts_with("DELETE /api/tokens/42 HTTP/1.1"));
                (
                    "503 Service Unavailable",
                    r#"{"error":"revocation unavailable"}"#,
                )
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(), body
            )
            .unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let shared = SharedCli::with_paths(product(origin), paths(temp.path()));
    let token_path = temp.path().join("config/tana/token");
    TokenStore::new(&token_path)
        .write_token(&SecretToken::new("tg_usr_shared").unwrap())
        .unwrap();

    let error = shared.logout().unwrap_err().to_string();

    assert!(error.contains("revocation unavailable"));
    assert!(token_path.exists());
}

#[test]
fn xdg_paths_have_one_shared_tana_namespace() {
    let root = PathBuf::from("/tmp/tana-cli-test");
    let paths = paths(&root);
    let product = product("http://127.0.0.1:1");
    assert_eq!(paths.install_path(&product), root.join("bin/gild"));
    assert_eq!(paths.trust_dir(), root.join("config/tana/trust"));
    assert_eq!(paths.token_path(), root.join("config/tana/token"));
    assert_eq!(
        paths.setup_state_path(&product),
        root.join("state/tana/setup/gild.json")
    );
}

#[test]
fn monitor_outcomes_use_the_stable_health_exit_code() {
    let outcome = SelfOutcome::Monitored {
        report: MonitorReport {
            name: "gild".into(),
            installed_version: semver::Version::parse("1.2.3").unwrap(),
            installed_digest: "a".repeat(64),
            latest_version: Some(semver::Version::parse("1.2.4").unwrap()),
            update_available: true,
            health: HealthStatus::Failed,
            key_id: "harar-release-test".into(),
            anchor_generation: 2,
            checked_at: chrono::Utc::now(),
        },
        json: true,
    };
    assert_eq!(outcome.exit_code(), 20);
}

#[test]
fn shared_auth_rejects_insecure_origin_before_storing_bearer() {
    let temp = tempfile::tempdir().unwrap();
    let shared =
        SharedCli::with_paths(product("http://linkhash.internal:9418"), paths(temp.path()));
    let error = shared
        .login(LoginOptions::token(
            SecretToken::new("tg_usr_must_not_be_sent").unwrap(),
        ))
        .unwrap_err()
        .to_string();
    assert!(error.contains("HTTPS"), "{error}");
    assert!(!temp.path().join("config/tana/token").exists());
}

#[test]
fn device_login_rejects_redirect_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = Box::leak(format!("http://{}", listener.local_addr().unwrap()).into_boxed_str());
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        let body = r#"{"device_code":"tg_device_redirect","user_code":"AAAAA-BBBBB","verification_uri":"https://example.com/verify","interval":1}"#;
        write!(
            stream,
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: https://example.com/stolen\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let shared = SharedCli::with_paths(product(origin), paths(temp.path()));
    let mut options = LoginOptions::device();
    options.timeout = Duration::from_secs(1);
    let error = shared.login(options).unwrap_err().to_string();
    assert!(error.contains("307"), "{error}");
    assert!(!temp.path().join("config/tana/token").exists());
}
