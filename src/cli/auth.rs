use std::{
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;

use crate::{Identity, LinkhashClient, SecretToken, TokenStore};

use super::{CliCoreError, SharedCli};

#[derive(Clone, Debug)]
pub struct AuthSpec {
    pub identity_origin: String,
    pub device_authorization_path: &'static str,
    pub device_token_path: &'static str,
}

impl AuthSpec {
    pub fn new(identity_origin: impl Into<String>) -> Self {
        Self {
            identity_origin: identity_origin.into(),
            device_authorization_path: "/api/v1/auth/device/code",
            device_token_path: "/api/v1/auth/device/token",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoginOptions {
    pub token: Option<SecretToken>,
    pub use_device_flow: bool,
    pub timeout: Duration,
}

impl LoginOptions {
    pub fn token(token: SecretToken) -> Self {
        Self {
            token: Some(token),
            use_device_flow: false,
            timeout: Duration::from_secs(300),
        }
    }

    pub fn device() -> Self {
        Self {
            token: None,
            use_device_flow: true,
            timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_poll_seconds")]
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    token: Option<String>,
    error: Option<String>,
}

fn default_poll_seconds() -> u64 {
    5
}

impl SharedCli {
    pub fn login(&self, options: LoginOptions) -> Result<Identity, CliCoreError> {
        let auth = self.product.auth.as_ref().ok_or_else(|| {
            CliCoreError::Configuration("this product has no auth service".into())
        })?;
        let token = match (options.token, options.use_device_flow) {
            (Some(token), false) => token,
            (None, true) => self.device_login(auth, options.timeout)?,
            _ => {
                return Err(CliCoreError::Configuration(
                    "select exactly one login method".into(),
                ))
            }
        };
        let client = LinkhashClient::new(&auth.identity_origin)?;
        let principal = client.whoami(&token)?;
        TokenStore::new(self.paths.token_path()).write_token(&token)?;
        Ok(principal.identity)
    }

    pub fn logout(&self) -> Result<(), CliCoreError> {
        let auth = self.product.auth.as_ref().ok_or_else(|| {
            CliCoreError::Configuration("this product has no auth service".into())
        })?;
        let store = TokenStore::new(self.paths.token_path());
        let Some(token) = store.read_token()? else {
            return Ok(());
        };
        let client = LinkhashClient::new(&auth.identity_origin)?;
        let token_id = client
            .whoami(&token)?
            .token_id
            .ok_or_else(|| CliCoreError::Auth("whoami response omitted token_id".into()))?;
        client.revoke(&token, token_id)?;
        store.remove_token()?;
        Ok(())
    }

    pub fn whoami(&self) -> Result<Identity, CliCoreError> {
        let auth = self.product.auth.as_ref().ok_or_else(|| {
            CliCoreError::Configuration("this product has no auth service".into())
        })?;
        let principal = LinkhashClient::new(&auth.identity_origin)?
            .whoami_from_store(&TokenStore::new(self.paths.token_path()))?;
        Ok(principal.identity)
    }

    fn device_login(
        &self,
        auth: &AuthSpec,
        timeout: Duration,
    ) -> Result<SecretToken, CliCoreError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| CliCoreError::Auth(error.to_string()))?;
        let authorization: DeviceAuthorization = client
            .post(endpoint(
                &auth.identity_origin,
                auth.device_authorization_path,
            ))
            .json(&serde_json::json!({"client_name": self.product.name.as_str()}))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|error| CliCoreError::Auth(error.to_string()))?;
        eprintln!(
            "Open {} and enter code {}",
            authorization.verification_uri, authorization.user_code
        );
        let deadline = Instant::now() + timeout;
        let interval = Duration::from_secs(authorization.interval.clamp(1, 30));
        while Instant::now() < deadline {
            let response = client
                .post(endpoint(&auth.identity_origin, auth.device_token_path))
                .json(&serde_json::json!({"device_code": authorization.device_code}))
                .send()
                .map_err(|error| CliCoreError::Auth(error.to_string()))?;
            let pending = matches!(response.status().as_u16(), 400 | 404 | 428);
            let body: DeviceTokenResponse = response
                .json()
                .map_err(|error| CliCoreError::Auth(error.to_string()))?;
            if let Some(token) = body.token {
                return SecretToken::new(token).map_err(CliCoreError::from);
            }
            if !pending && body.error.as_deref() != Some("authorization_pending") {
                return Err(CliCoreError::Auth(
                    body.error
                        .unwrap_or_else(|| "device authorization was rejected".into()),
                ));
            }
            thread::sleep(interval);
        }
        Err(CliCoreError::Auth("device authorization timed out".into()))
    }
}

fn endpoint(origin: &str, path: &str) -> String {
    format!("{}{}", origin.trim_end_matches('/'), path)
}
