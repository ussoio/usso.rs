use base64::Engine;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::config::AuthConfig;
use crate::exceptions::USSOError;
use crate::jwks::{fetch_jwks_sync, get_jwk_keys};
use crate::schemas::{JWTConfig, Jwk, Jwks, UserData};

pub fn decode_token(
    key: &Jwk,
    token: &str,
    algorithms: &[Algorithm],
) -> Result<UserData, USSOError> {
    let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|_| USSOError::InvalidToken)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = algorithms.to_vec();
    match decode::<UserData>(token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(USSOError::ExpiredToken),
            _ => Err(USSOError::InvalidToken),
        },
    }
}

pub fn is_expired(token: &str) -> Result<bool, USSOError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(USSOError::InvalidToken);
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| USSOError::InvalidToken)?;
    let claims: HashMap<String, serde_json::Value> = serde_json::from_slice(&payload_bytes)
        .map_err(|_| USSOError::InvalidToken)?;

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 86400
        });

    Ok(exp
        < SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
}

pub fn decode_token_with_jwks(_jwk_url: &str, token: &str) -> Result<UserData, USSOError> {
    let jwk_keys = get_jwk_keys().map_err(|_| USSOError::Other("JWKS not initialized".to_string()))?;
    let header_data = jsonwebtoken::decode_header(token)
        .map_err(|_| USSOError::InvalidToken)?;
    let kid = header_data.kid.ok_or(USSOError::InvalidToken)?;
    let key = jwk_keys
        .match_kid(&kid)
        .ok_or(USSOError::InvalidToken)?;
    decode_token(key, token, &[Algorithm::RS256])
}

#[derive(Debug, Clone)]
pub struct Usso {
    jwt_configs: Vec<JWTConfig>,
}

impl Usso {
    pub fn new(jwt_config: Option<JWTConfig>, jwk_url: Option<String>, key: Option<Jwks>) -> Self {
        let jwt_configs = Self::initialize_configs(jwt_config, jwk_url, key);
        Usso { jwt_configs }
    }

    fn initialize_configs(
        jwt_config: Option<JWTConfig>,
        jwk_url: Option<String>,
        key: Option<Jwks>,
    ) -> Vec<JWTConfig> {
        if let Some(config) = jwt_config {
            vec![config]
        } else if let Some(url) = jwk_url {
            let res = fetch_jwks_sync(url.as_str()).ok();
            vec![JWTConfig::new(Some(url.clone()), res)]
        } else if let Some(keyset) = key {
            vec![JWTConfig::new(None, Some(keyset))]
        } else {
            vec![]
        }
    }

    pub fn user_data_from_token(&self, token: &str) -> Result<UserData, USSOError> {
        for config in &self.jwt_configs {
            if let Ok(user_data) = config.decode(token) {
                return Ok(user_data);
            }
        }
        Err(USSOError::Unauthorized)
    }
}

#[derive(Debug, Clone)]
pub struct UssoAuth {
    jwt_configs: Vec<AuthConfig>,
    from_usso_base_url: Option<String>,
}

impl UssoAuth {
    pub fn new(jwt_config: Option<AuthConfig>, from_usso_base_url: Option<String>) -> Self {
        let jwt_configs = match jwt_config {
            Some(config) => vec![config],
            None => vec![AuthConfig::new(
                from_usso_base_url
                    .as_ref()
                    .map(|url| format!("{}/.well-known/jwks.json", url.trim_end_matches('/'))),
            )],
        };
        UssoAuth {
            jwt_configs,
            from_usso_base_url,
        }
    }

    pub fn user_data_from_token(
        &self,
        token: &str,
        expected_token_type: Option<&str>,
    ) -> Result<UserData, USSOError> {
        for config in &self.jwt_configs {
            if let Some(jwks_url) = &config.jwks_url {
                if let Ok(jwks) = fetch_jwks_sync(jwks_url) {
                    let jwt_config = JWTConfig::new(Some(jwks_url.clone()), Some(jwks));
                    if let Ok(user_data) = jwt_config.decode(token) {
                        let token_type = user_data.token_type.as_deref().unwrap_or("access");
                        if let Some(expected) = expected_token_type {
                            if token_type != expected {
                                continue;
                            }
                        }
                        return Ok(user_data);
                    }
                }
            }
        }
        Err(USSOError::Unauthorized)
    }

    pub fn user_data_from_api_key(
        &self,
        api_key: &str,
        _headers: &HashMap<String, String>,
    ) -> Result<UserData, USSOError> {
        for config in &self.jwt_configs {
            if let Some(api_header) = &config.api_key_header {
                let url = if api_header.verify_endpoint.is_empty() {
                    format!(
                        "{}/api/sso/v1/apikeys/verify",
                        self.from_usso_base_url
                            .as_deref()
                            .unwrap_or("https://sso.usso.io")
                    )
                } else {
                    api_header.verify_endpoint.clone()
                };
                let client = reqwest::blocking::Client::new();
                let response = client
                    .post(&url)
                    .json(&serde_json::json!({"api_key": api_key}))
                    .send()
                    .map_err(|_| USSOError::Unauthorized)?;
                if response.status().is_success() {
                    let data: UserData = response
                        .json()
                        .map_err(|_| USSOError::Unauthorized)?;
                    return Ok(data);
                }
            }
        }
        Err(USSOError::Unauthorized)
    }

    pub fn detect_compact_token_type(token: &str) -> Option<&'static str> {
        let token = token.trim();
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 3 {
            Some("jwt")
        } else if parts.len() == 5 {
            Some("jwe")
        } else {
            None
        }
    }
}
