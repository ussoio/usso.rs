use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct JWTConfig {
    pub jwk_url: Option<String>,
    pub secret: Option<String>,
    pub algorithm: String,
    pub header: std::collections::HashMap<String, String>,
}

impl JWTConfig {
    pub fn new(jwk_url: Option<String>, secret: Option<String>) -> Self {
        JWTConfig {
            jwk_url,
            secret,
            algorithm: "RS256".to_string(),
            header: std::collections::HashMap::new(),
        }
    }

    pub fn decode(&self, token: &str) -> Result<UserData, crate::exceptions::USSOError> {
        if let Some(secret) = &self.secret {
            crate::core::decode_token(secret, token, &[Algorithm::RS256])
        } else {
            Err(crate::exceptions::USSOError::InvalidToken)
        }
    }
}
