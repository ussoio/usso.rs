//! Base session with shared HTTP client and header management.

use std::collections::HashMap;

use reqwest::blocking::Client;
use reqwest::Method;
use thiserror::Error;

use crate::core::Usso;
use crate::exceptions::USSOError;

/// Errors returned by session operations.
#[derive(Error, Debug)]
pub enum SessionError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("USSO error: {0}")]
    USSOError(USSOError),
}

/// Base session holding an HTTP client, headers, and credentials.
///
/// Used internally by [`UssoSession`](crate::session::sync::UssoSession) and
/// [`AsyncUssoSession`](crate::session::async_code::AsyncUssoSession).
pub struct BaseUssoSession {
    pub client: Client,
    pub usso: Usso,
    pub base_url: String,
    pub api_key: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub headers: HashMap<String, String>,
}

impl BaseUssoSession {
    /// Create a new `BaseUssoSession`.
    ///
    /// - `base_url` — the USSO server base URL
    /// - `api_key` — optional API key (sets `x-api-key` header)
    /// - `refresh_token` — optional refresh token
    pub fn new(
        base_url: &str,
        api_key: Option<String>,
        refresh_token: Option<String>,
    ) -> Self {
        let mut headers = HashMap::new();
        if let Some(ref key) = api_key {
            headers.insert("x-api-key".to_string(), key.clone());
        }
        BaseUssoSession {
            client: Client::new(),
            usso: Usso::new(None, None, None),
            base_url: base_url.to_string(),
            api_key,
            refresh_token,
            access_token: None,
            headers,
        }
    }

    /// Send an HTTP request with the configured headers.
    ///
    /// Returns the response body as a string.
    pub fn request(&self, method: Method, url: &str) -> Result<String, SessionError> {
        let mut req = self.client.request(method, url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let response = req.send().map_err(SessionError::HttpError)?;
        response.text().map_err(SessionError::HttpError)
    }
}
