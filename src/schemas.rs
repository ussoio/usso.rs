use crate::exceptions::JwtError;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct UserData {
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub workspace_ids: Vec<String>,
    pub token_type: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub authentication_method: Option<String>,
    pub is_active: bool,
    pub jti: Option<String>,
    pub data: Option<serde_json::Value>,
    pub token: Option<String>,
}

impl UserData {
    pub fn from_json(value: &serde_json::Value) -> Self {
        serde_json::from_value(value.clone()).unwrap()
    }

    pub fn uid(&self) -> Uuid {
        Uuid::parse_str(&self.user_id).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct JWTConfig {
    pub jwk_url: Option<String>,
    pub keys: Option<Jwks>,
    pub algorithm: String,
    pub header: std::collections::HashMap<String, String>,
}

impl JWTConfig {
    pub fn new(jwk_url: Option<String>, keys: Option<Jwks>) -> Self {
        JWTConfig {
            jwk_url,
            keys,
            algorithm: "RS256".to_string(),
            header: std::collections::HashMap::new(),
        }
    }

    pub fn decode(&self, token: &str) -> Result<UserData, crate::exceptions::USSOError> {
        let header = JwtHeader::from_token(token).unwrap();
        match header.kid {
            Some(kid) => {
                if let Some(keyset) = &self.keys {
                    let key = keyset.match_kid(kid.as_str());
                    match key {
                        Some(key) => crate::core::decode_token(key, token, &[Algorithm::RS256]),
                        None => Err(crate::exceptions::USSOError::InvalidToken),
                    }
                } else {
                    Err(crate::exceptions::USSOError::Other(String::from(
                        "keyset is not set",
                    )))
                }
            }
            None => Err(crate::exceptions::USSOError::InvalidToken),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub r#use: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}
impl Jwks {
    pub fn match_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid == kid)
    }
}
#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
    pub host: Option<String>,
}
impl JwtHeader {
    // Function to decode and parse the JWT header from the JWT string
    pub fn from_token(jwt: &str) -> Result<JwtHeader, JwtError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        // Base64 URL decoding can fail, hence the error handling
        let header_base64 = parts[0];
        match STANDARD_NO_PAD.decode(header_base64) {
            Ok(header_bytes) => {
                // Convert bytes to string and return
                match serde_json::from_slice(&header_bytes) {
                    Ok(header_str) => Ok(header_str),
                    Err(_) => Err(JwtError::DecodingError(
                        "Invalid UTF-8 in header".to_string(),
                    )),
                }
            }
            Err(_) => Err(JwtError::DecodingError(
                "Failed to decode base64".to_string(),
            )),
        }
    }
}
