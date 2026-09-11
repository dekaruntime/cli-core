use crate::token_file::{SecretToken, TokenFileError, TokenStore};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_LINKHASH_URL: &str = "https://github.com";
const WHOAMI_PATH: &str = "/api/v1/whoami";

#[derive(Debug, Clone)]
pub struct LinkhashClient {
    base_url: reqwest::Url,
    http: reqwest::blocking::Client,
}

impl LinkhashClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, WhoamiError> {
        let base_url = validate_linkhash_origin(&base_url.into())?;

        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(WhoamiError::HttpClient)?;

        Ok(Self { base_url, http })
    }

    pub fn git_tana() -> Result<Self, WhoamiError> {
        Self::new(DEFAULT_LINKHASH_URL)
    }

    pub fn whoami(&self, token: &SecretToken) -> Result<Principal, WhoamiError> {
        let url = self.endpoint(WHOAMI_PATH)?;
        let response = self
            .http
            .get(url)
            .bearer_auth(token.expose_secret())
            .send()
            .map_err(WhoamiError::Request)?;

        let status = response.status();
        let body: serde_json::Value = response.json().map_err(WhoamiError::Decode)?;

        if !status.is_success() {
            let message = body
                .get("error")
                .and_then(|value| value.as_str())
                .unwrap_or("whoami request failed")
                .to_string();
            return Err(WhoamiError::Rejected {
                status: status.as_u16(),
                message,
            });
        }

        let envelope: WhoamiEnvelope = serde_json::from_value(body).map_err(WhoamiError::Json)?;
        if !envelope.ok {
            return Err(WhoamiError::Rejected {
                status: status.as_u16(),
                message: envelope
                    .error
                    .unwrap_or_else(|| "whoami rejected".to_string()),
            });
        }

        envelope.principal.ok_or(WhoamiError::MissingPrincipal)
    }

    pub fn whoami_from_store(&self, store: &TokenStore) -> Result<Principal, WhoamiError> {
        let token = store.read_token()?.ok_or(WhoamiError::NotLoggedIn)?;
        self.whoami(&token)
    }

    pub fn revoke(&self, token: &SecretToken, token_id: i64) -> Result<(), WhoamiError> {
        let url = self.endpoint(&format!("/api/tokens/{token_id}"))?;
        let response = self
            .http
            .delete(url)
            .bearer_auth(token.expose_secret())
            .send()
            .map_err(WhoamiError::Request)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let message = response
            .json::<serde_json::Value>()
            .ok()
            .and_then(|body| {
                body.get("error")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "token revocation failed".to_string());
        Err(WhoamiError::Rejected {
            status: status.as_u16(),
            message,
        })
    }

    fn endpoint(&self, path: &str) -> Result<reqwest::Url, WhoamiError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| WhoamiError::InvalidBaseUrl)
    }
}

pub fn validate_linkhash_origin(value: &str) -> Result<reqwest::Url, WhoamiError> {
    let mut url = reqwest::Url::parse(value.trim()).map_err(|_| WhoamiError::InvalidBaseUrl)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WhoamiError::InvalidBaseUrl);
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(WhoamiError::InsecureBaseUrl);
    }
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(WhoamiError::InvalidBaseUrl);
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub identity: Identity,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub repos: Vec<String>,
    #[serde(default)]
    pub token_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WhoamiEnvelope {
    ok: bool,
    principal: Option<Principal>,
    error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WhoamiError {
    #[error("invalid linkhash base URL")]
    InvalidBaseUrl,
    #[error("linkhash base URL must use HTTPS (HTTP is allowed only for loopback)")]
    InsecureBaseUrl,
    #[error("not logged in; token file is missing")]
    NotLoggedIn,
    #[error("token file error: {0}")]
    TokenFile(#[from] TokenFileError),
    #[error("failed to build HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("whoami request failed: {0}")]
    Request(reqwest::Error),
    #[error("failed to decode whoami response: {0}")]
    Decode(reqwest::Error),
    #[error("failed to parse whoami response: {0}")]
    Json(serde_json::Error),
    #[error("whoami response missing principal")]
    MissingPrincipal,
    #[error("linkhash rejected whoami request ({status}): {message}")]
    Rejected { status: u16, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let n = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            assert!(request.starts_with("GET /api/v1/whoami HTTP/1.1"));
            assert!(request.contains("authorization: Bearer tg_usr_test"));
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn whoami_resolves_principal_with_scopes() {
        let base = serve_once(
            "200 OK",
            r#"{"ok":true,"principal":{"identity":{"id":"sam","kind":"human","handle":"sam"},"scopes":["repo:read","packages:write"],"repos":["tana/deka"],"token_id":42}}"#,
        );
        let client = LinkhashClient::new(base).unwrap();
        let token = SecretToken::new("tg_usr_test").unwrap();

        let principal = client.whoami(&token).unwrap();

        assert_eq!(principal.identity.id, "sam");
        assert_eq!(principal.identity.handle.as_deref(), Some("sam"));
        assert_eq!(principal.scopes, vec!["repo:read", "packages:write"]);
        assert_eq!(principal.repos, vec!["tana/deka"]);
        assert_eq!(principal.token_id, Some(42));
    }

    #[test]
    fn whoami_from_store_reads_shared_token_file() {
        let base = serve_once(
            "200 OK",
            r#"{"ok":true,"principal":{"identity":{"id":"agent-khalid","kind":"agent"},"scopes":["repo:read"]}}"#,
        );
        let temp = tempfile::tempdir().unwrap();
        let store = TokenStore::new(temp.path().join("tana").join("token"));
        store
            .write_token(&SecretToken::new("tg_usr_test").unwrap())
            .unwrap();

        let principal = LinkhashClient::new(base)
            .unwrap()
            .whoami_from_store(&store)
            .unwrap();

        assert_eq!(principal.identity.id, "agent-khalid");
        assert_eq!(principal.scopes, vec!["repo:read"]);
    }

    #[test]
    fn whoami_reports_rejection_without_token_material() {
        let base = serve_once(
            "401 Unauthorized",
            r#"{"ok":false,"error":"invalid token"}"#,
        );
        let client = LinkhashClient::new(base).unwrap();
        let token = SecretToken::new("tg_usr_test").unwrap();

        let err = client.whoami(&token).unwrap_err().to_string();

        assert!(err.contains("invalid token"));
        assert!(!err.contains("tg_usr_test"));
    }

    #[test]
    fn whoami_from_store_requires_token() {
        let temp = tempfile::tempdir().unwrap();
        let store = TokenStore::new(temp.path().join("missing-token"));
        let client = LinkhashClient::new("http://127.0.0.1:1").unwrap();

        let err = client.whoami_from_store(&store).unwrap_err();

        assert!(matches!(err, WhoamiError::NotLoggedIn));
    }

    #[test]
    fn auth_origin_rejects_cleartext_and_url_metadata() {
        assert!(LinkhashClient::new("http://127.0.0.1:9418").is_ok());
        assert!(LinkhashClient::new("http://[::1]:9418").is_ok());
        assert!(LinkhashClient::new("https://git.tana.gg").is_ok());
        for invalid in [
            "http://linkhash.internal:9418",
            "https://user:secret@git.tana.gg",
            "https://git.tana.gg?token=secret",
            "https://git.tana.gg/#fragment",
        ] {
            assert!(LinkhashClient::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn whoami_rejects_redirect_without_forwarding_bearer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let body = r#"{"ok":true,"principal":{"identity":{"id":"attacker"}}}"#;
            stream
                .write_all(format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://example.com/stolen\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).as_bytes())
                .unwrap();
        });
        let client = LinkhashClient::new(base).unwrap();
        let error = client
            .whoami(&SecretToken::new("tg_usr_test").unwrap())
            .unwrap_err();
        assert!(matches!(error, WhoamiError::Rejected { status: 307, .. }));
    }
}
