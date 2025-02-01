use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::exceptions::USSOError;
use crate::schemas::{JWTConfig, UserData};


pub fn decode_token(key: &str, token: &str, algorithms: &[Algorithm]) -> Result<UserData, USSOError> {
    let decoding_key = DecodingKey::from_secret(key.as_bytes());
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = algorithms.to_vec();

    match decode::<UserData>(token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(_) => Err(USSOError::InvalidToken),
    }
}

pub fn is_expired(token: &str) -> Result<bool, USSOError> {
    let decoded = decode::<HashMap<String, serde_json::Value>>(
        token,
        &DecodingKey::from_secret(&[]),
        &Validation::default(),
    ).expect("wtf core");

    let exp = decoded.claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + 86400);

    Ok(exp < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)
}

pub struct Usso {
    jwt_configs: Vec<JWTConfig>,
}

impl Usso {
    pub fn new(jwt_config: Option<JWTConfig>, jwk_url: Option<String>, secret: Option<String>) -> Self {
        let jwt_configs = Self::initialize_configs(jwt_config, jwk_url, secret);
        Usso { jwt_configs }
    }

    fn initialize_configs(
        jwt_config: Option<JWTConfig>,
        jwk_url: Option<String>,
        secret: Option<String>,
    ) -> Vec<JWTConfig> {
        if let Some(config) = jwt_config {
            vec![config]
        } else if let Some(url) = jwk_url {
            vec![JWTConfig::new(Some(url), None)]
        } else if let Some(sec) = secret {
            vec![JWTConfig::new(None, Some(sec))]
        } else {
            panic!("Provide jwt_config, jwk_url, or secret");
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
