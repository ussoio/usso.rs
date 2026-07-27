use std::collections::HashMap;

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

    pub fn get_key_from_cookies(&self, cookies: &HashMap<String, String>) -> Option<String> {
        let cookie_name = self.cookie_name.as_deref()?;
        cookies.get(cookie_name).cloned()
    }

    pub fn get_key(&self, headers: &HashMap<String, String>, cookies: &HashMap<String, String>) -> Option<String> {
        self.get_key_from_headers(headers).or_else(|| self.get_key_from_cookies(cookies))
    }
}

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
    pub fn get_api_key(&self, headers: &HashMap<String, String>) -> Option<String> {
        let header_name = self.header_name.as_deref()?;
        headers.get(header_name).cloned()
    }
}

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
    pub fn new(jwks_url: Option<String>) -> Self {
        AuthConfig {
            jwks_url,
            ..Default::default()
        }
    }

    pub fn get_jwt(&self, headers: &HashMap<String, String>, cookies: &HashMap<String, String>) -> Option<String> {
        self.jwt_header.as_ref().and_then(|h| h.get_key(headers, cookies))
    }

    pub fn get_api_key(&self, headers: &HashMap<String, String>) -> Option<String> {
        self.api_key_header.as_ref().and_then(|h| h.get_api_key(headers))
    }
}
