use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::exceptions::USSOError;
use crate::jwks::{fetch_jwks_sync, get_jwk_keys};
use crate::schemas::{JWTConfig, Jwk, Jwks, UserData};

pub fn decode_token(
    key: &Jwk,
    token: &str,
    algorithms: &[Algorithm],
) -> Result<UserData, USSOError> {
    let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e).unwrap();
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
    )
    .expect("error in decode");

    let exp = decoded
        .claims
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
    let jwk_keys = get_jwk_keys().expect("Can't get keys");
    let key = jwk_keys
        .match_kid(token)
        .expect("Can't find key with this kid in jwks");
    decode_token(key, token, &[Algorithm::RS256])
}
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
            let res = Some(fetch_jwks_sync(url.as_str()).unwrap());
            vec![JWTConfig::new(Some(url.clone()), res)]
        } else if let Some(keyset) = key {
            vec![JWTConfig::new(None, Some(keyset))]
        } else {
            panic!("Provide jwt_config, jwk_url, or keys");
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
