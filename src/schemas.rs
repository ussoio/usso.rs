use crate::exceptions::JwtError;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserData {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub jti: Option<String>,
    pub token_type: Option<String>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub workspace_id: Option<String>,
    pub workspace_ids: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub user_id: Option<String>,
    pub authentication_method: Option<String>,
    pub is_active: Option<bool>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub signing_level: Option<String>,
    pub data: Option<serde_json::Value>,
    pub token: Option<String>,
}

impl UserData {
    pub fn uid(&self) -> Option<Uuid> {
        let uid_str = self
            .user_id
            .as_deref()
            .or(self.sub.as_deref())?;
        let cleaned = uid_str.strip_prefix("u_").unwrap_or(uid_str);
        if (22..=24).contains(&cleaned.len()) {
            crate::utils::b64tools::b64_decode_uuid(cleaned).ok()
        } else {
            Uuid::parse_str(cleaned).ok()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
        let header = JwtHeader::from_token(token).map_err(|_| crate::exceptions::USSOError::InvalidToken)?;
        match header.kid {
            Some(kid) => {
                if let Some(keyset) = &self.keys {
                    let key = keyset.match_kid(kid.as_str());
                    match key {
                        Some(key) => crate::core::decode_token(key, token, &[jsonwebtoken::Algorithm::RS256]),
                        None => Err(crate::exceptions::USSOError::InvalidToken),
                    }
                } else {
                    Err(crate::exceptions::USSOError::Other("keyset is not set".to_string()))
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
    pub host: Option<String>,
}

impl JwtHeader {
    pub fn from_token(jwt: &str) -> Result<JwtHeader, JwtError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }
        let header_base64 = parts[0];
        match STANDARD_NO_PAD.decode(header_base64) {
            Ok(header_bytes) => match serde_json::from_slice(&header_bytes) {
                Ok(header_str) => Ok(header_str),
                Err(_) => Err(JwtError::DecodingError("Invalid UTF-8 in header".to_string())),
            },
            Err(_) => Err(JwtError::DecodingError("Failed to decode base64".to_string())),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserResponse {
    pub uid: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub is_deleted: Option<bool>,
    pub meta_data: Option<serde_json::Value>,
    pub tenant_id: Option<String>,
    pub name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub workspace_roles: Option<std::collections::HashMap<String, Vec<String>>>,
    pub workspace_ids: Option<Vec<String>>,
    pub is_active: Option<bool>,
    pub is_limited: Option<bool>,
    pub activation_status: Option<String>,
    pub avatar_url: Option<String>,
    pub custom_claims: Option<serde_json::Value>,
    pub identifiers: Option<Vec<UserIdentifierSchema>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserIdentifierSchema {
    pub uid: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub is_deleted: Option<bool>,
    pub meta_data: Option<serde_json::Value>,
    pub tenant_id: Option<String>,
    pub r#type: String,
    pub identifier: String,
    pub verified_at: Option<String>,
    pub is_primary: Option<bool>,
    pub is_active: Option<bool>,
}
