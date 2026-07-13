use std::{io::Read as _, time::Duration};

use reqwest::{blocking::Client, redirect::Policy, Url};

use super::{ReleaseCoordinates, ReleaseTransport, TransportError};

/// Production Linkhash transport. Redirects are rejected and every response is
/// bounded while it is read, before the verifier receives owned bytes.
pub struct HttpReleaseTransport {
    origin: Url,
    client: Client,
}

impl HttpReleaseTransport {
    pub fn new(origin: &str, timeout: Duration) -> Result<Self, TransportError> {
        let origin = Url::parse(origin)
            .map_err(|error| TransportError::new(format!("invalid release origin: {error}")))?;
        let loopback_http = origin.scheme() == "http"
            && matches!(origin.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if origin.scheme() != "https" && !loopback_http {
            return Err(TransportError::new("release origin must use https"));
        }
        if origin.cannot_be_a_base() || origin.query().is_some() || origin.fragment().is_some() {
            return Err(TransportError::new(
                "release origin must be an absolute URL without query/fragment",
            ));
        }
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| TransportError::new(error.to_string()))?;
        Ok(Self { origin, client })
    }

    fn fetch(&self, segments: &[&str], max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        let mut url = self.origin.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| TransportError::new("release origin cannot hold path segments"))?;
            path.pop_if_empty();
            path.extend(segments);
        }
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|error| TransportError::new(error.to_string()))?;
        if !response.status().is_success() {
            return Err(TransportError::new(format!(
                "release endpoint returned {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(TransportError::new("release response exceeds byte limit"));
        }
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
        response
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| TransportError::new(error.to_string()))?;
        if bytes.len() > max_bytes {
            return Err(TransportError::new("release response exceeds byte limit"));
        }
        Ok(bytes)
    }

    fn immutable_prefix<'a>(release: ReleaseCoordinates<'a>) -> [&'a str; 7] {
        [
            "api",
            "v1",
            "releases",
            release.name,
            release.channel,
            release.version,
            release.platform,
        ]
    }
}

impl ReleaseTransport for HttpReleaseTransport {
    fn fetch_anchor_set(&self, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        self.fetch(
            &["api", "v1", "releases", "trust", "anchor-set.json"],
            max_bytes,
        )
    }

    fn fetch_anchor_signatures(&self, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        self.fetch(
            &["api", "v1", "releases", "trust", "anchor-set.sig"],
            max_bytes,
        )
    }

    fn fetch_latest_statement(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        self.fetch(
            &[
                "api",
                "v1",
                "releases",
                name,
                channel,
                platform,
                "latest.json",
            ],
            max_bytes,
        )
    }

    fn fetch_latest_signature(
        &self,
        name: &str,
        channel: &str,
        platform: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.fetch(
            &[
                "api",
                "v1",
                "releases",
                name,
                channel,
                platform,
                "latest.sig",
            ],
            64,
        )
    }

    fn fetch_manifest(
        &self,
        release: ReleaseCoordinates<'_>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let mut path = Self::immutable_prefix(release).to_vec();
        path.push("release-manifest.json");
        self.fetch(&path, max_bytes)
    }

    fn fetch_manifest_signature(
        &self,
        release: ReleaseCoordinates<'_>,
    ) -> Result<Vec<u8>, TransportError> {
        let mut path = Self::immutable_prefix(release).to_vec();
        path.push("release-manifest.sig");
        self.fetch(&path, 64)
    }

    fn fetch_artifact(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let mut path = Self::immutable_prefix(release).to_vec();
        path.push(artifact);
        self.fetch(&path, max_bytes)
    }

    fn fetch_artifact_signature(
        &self,
        release: ReleaseCoordinates<'_>,
        artifact: &str,
    ) -> Result<Vec<u8>, TransportError> {
        let mut path = Self::immutable_prefix(release).to_vec();
        let signature_name = format!("{artifact}.sig");
        path.push(&signature_name);
        self.fetch(&path, 64)
    }
}
