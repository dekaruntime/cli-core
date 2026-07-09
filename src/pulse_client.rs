use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct PulseClient {
    base_url: String,
    bearer: Option<String>,
    http: Client,
}

impl PulseClient {
    pub fn new(base_url: impl Into<String>, bearer: Option<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            bearer,
            http,
        })
    }

    pub async fn with_token_file(
        base_url: impl Into<String>,
        token_file: Option<PathBuf>,
    ) -> Result<Self> {
        let bearer = match token_file {
            Some(path) => Some(
                tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("read token file {}", path.display()))?
                    .trim()
                    .to_string(),
            ),
            None => None,
        };
        Self::new(base_url, bearer)
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.authorize(self.http.get(self.url(path)))
    }

    pub fn post_json<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> RequestBuilder {
        self.authorize(self.http.post(self.url(path))).json(body)
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self.get(path).send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("GET {path} failed with {status}: {text}");
        }
        Ok(response.json().await?)
    }

    pub async fn post_json_expect_ok<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<()> {
        let response = self.post_json(path, body).send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("POST {path} failed with {status}: {text}");
        }
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.bearer {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }
}
