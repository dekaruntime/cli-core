use crate::token_file::{SecretToken, TokenFileError, TokenStore};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_LINKHASH_URL: &str = "https://git.tana.gg";
const WHOAMI_PATH: &str = "/api/v1/whoami";

#[derive(Debug, Clone)]
pub struct LinkhashClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl LinkhashClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, WhoamiError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(WhoamiError::InvalidBaseUrl);
        }

        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(WhoamiError::HttpClient)?;

        Ok(Self { base_url, http })
    }

    pub fn git_tana() -> Result<Self, WhoamiError> {
        Self::new(DEFAULT_LINKHASH_URL)
    }

    pub fn whoami(&self, token: &SecretToken) -> Result<Principal, WhoamiError> {
        let url = format!("{}{}", self.base_url, WHOAMI_PATH);
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
}
