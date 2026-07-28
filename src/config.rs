//! Configuration types for JWT and API key extraction.
//!
//! Provides [`AuthConfig`] as the top-level configuration, along with
//! [`HeaderConfig`] for JWT token extraction from HTTP headers/cookies and
//! [`APIHeaderConfig`] for API key header extraction.

use std::collections::HashMap;

/// Configuration for extracting JWT tokens from HTTP headers and cookies.
///
/// By default looks for a Bearer token in the `Authorization` header and
/// falls back to the `usso-access-token` cookie.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use usso::config::HeaderConfig;
///
/// let cfg = HeaderConfig::default();
/// let mut headers = HashMap::new();
/// headers.insert("Authorization".into(), "Bearer eyJ...".into());
/// let token = cfg.get_key_from_headers(&headers);
/// assert_eq!(token, Some("eyJ...".into()));
/// ```
#[derive(Debug, Clone)]
pub struct HeaderConfig {
    pub header_name: Option<String>,
    pub cookie_name: Option<String>,
}

impl Default for HeaderConfig {
    fn default() -> Self {
        HeaderConfig {
            header_name: Some("Authorization".to_string()),
            cookie_name: Some("usso-access-token".to_string()),
        }
    }
}

impl HeaderConfig {
    /// Extract a JWT from HTTP headers.
    ///
    /// If the configured header is `Authorization`, this strips the `Bearer `
    /// prefix automatically.
    pub fn get_key_from_headers(&self, headers: &HashMap<String, String>) -> Option<String> {
        let header_name = self.header_name.as_deref()?;
        let value = headers.get(header_name)?;
        if header_name.eq_ignore_ascii_case("Authorization") {
            let parts: Vec<&str> = value.splitn(2, ' ').collect();
            if parts.len() == 2 && parts[0].eq_ignore_ascii_case("bearer") {
                return Some(parts[1].to_string());
            }
        }
        Some(value.clone())
    }

    /// Extract a JWT from cookies by the configured cookie name.
    pub fn get_key_from_cookies(&self, cookies: &HashMap<String, String>) -> Option<String> {
        let cookie_name = self.cookie_name.as_deref()?;
        cookies.get(cookie_name).cloned()
    }

    /// Extract a JWT from headers first, falling back to cookies.
    pub fn get_key(&self, headers: &HashMap<String, String>, cookies: &HashMap<String, String>) -> Option<String> {
        self.get_key_from_headers(headers).or_else(|| self.get_key_from_cookies(cookies))
    }
}

/// Configuration for extracting API keys from HTTP headers.
///
/// By default looks for the `x-api-key` header and verifies against
/// `/api/sso/v1/apikeys/verify` on the USSO server.
#[derive(Debug, Clone)]
pub struct APIHeaderConfig {
    pub header_name: Option<String>,
    pub verify_endpoint: String,
}

impl Default for APIHeaderConfig {
    fn default() -> Self {
        APIHeaderConfig {
            header_name: Some("x-api-key".to_string()),
            verify_endpoint: String::new(),
        }
    }
}

impl APIHeaderConfig {
    /// Extract the API key value from headers.
    pub fn get_api_key(&self, headers: &HashMap<String, String>) -> Option<String> {
        let header_name = self.header_name.as_deref()?;
        headers.get(header_name).cloned()
    }
}

/// Top-level authentication configuration.
///
/// Combines JWKS URL, API key header config, JWT header config, and the
/// signing algorithm into a single structure used by [`UssoAuth`](crate::core::UssoAuth).
///
/// # Example
///
/// ```rust
/// use usso::config::AuthConfig;
///
/// let config = AuthConfig::new(Some("https://sso.usso.io/.well-known/jwks.json".into()));
/// ```
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwks_url: Option<String>,
    pub api_key_header: Option<APIHeaderConfig>,
    pub jwt_header: Option<HeaderConfig>,
    pub algorithm: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            jwks_url: None,
            api_key_header: Some(APIHeaderConfig::default()),
            jwt_header: Some(HeaderConfig::default()),
            algorithm: "RS256".to_string(),
        }
    }
}

impl AuthConfig {
    /// Create a new `AuthConfig` with the given JWKS URL and defaults for everything else.
    pub fn new(jwks_url: Option<String>) -> Self {
        AuthConfig {
            jwks_url,
            ..Default::default()
        }
    }

    /// Extract a JWT from headers or cookies using the configured [`HeaderConfig`].
    pub fn get_jwt(&self, headers: &HashMap<String, String>, cookies: &HashMap<String, String>) -> Option<String> {
        self.jwt_header.as_ref().and_then(|h| h.get_key(headers, cookies))
    }

    /// Extract an API key from headers using the configured [`APIHeaderConfig`].
    pub fn get_api_key(&self, headers: &HashMap<String, String>) -> Option<String> {
        self.api_key_header.as_ref().and_then(|h| h.get_api_key(headers))
    }
}
