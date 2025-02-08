use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwksError {
    #[error("HTTP error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Invalid JWKS data: {0}")]
    InvalidJwksData(String),

    #[error("JWKS not initialized")]
    NotInitialized,
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

static JWKS_CACHE: OnceLock<Jwks> = OnceLock::new();

pub fn init_jwks(jwk_url: &str) -> Result<(), JwksError> {
    let jwks = fetch_jwks(jwk_url)?;
    JWKS_CACHE
        .set(jwks)
        .map_err(|_| JwksError::InvalidJwksData("Failed to set JWKS cache".into()))?;
    Ok(())
}

fn fetch_jwks(jwk_url: &str) -> Result<Jwks, JwksError> {
    let user_agent = format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    );

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_str(&user_agent).unwrap());

    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .build()?;

    let response = client.get(jwk_url).send()?.error_for_status()?;
    let jwks: Jwks = response.json()?;

    if jwks.keys.is_empty() {
        return Err(JwksError::InvalidJwksData("No keys found in JWKS".into()));
    }

    Ok(jwks)
}

pub fn get_jwk_keys() -> Result<&'static Jwks, JwksError> {
    JWKS_CACHE.get().ok_or(JwksError::NotInitialized)
}
