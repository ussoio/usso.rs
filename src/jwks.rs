use crate::{exceptions::JwksError, schemas::Jwks};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use std::sync::OnceLock;

static JWKS_CACHE: OnceLock<Jwks> = OnceLock::new();

pub fn init_jwks_sync(jwk_url: &str) -> Result<(), JwksError> {
    let jwks = fetch_jwks_sync(jwk_url)?;
    JWKS_CACHE
        .set(jwks)
        .map_err(|_| JwksError::InvalidJwksData("Failed to set JWKS cache".into()))?;
    Ok(())
}

pub fn fetch_jwks_sync(jwk_url: &str) -> Result<Jwks, JwksError> {
    let user_agent = format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&user_agent).expect("Invalid user agent header"),
    );

    // Build a blocking client.
    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .build()?;

    let response = client.get(jwk_url).send()?.error_for_status()?; // Ensures that non-200 responses are treated as errors

    let jwks: Jwks = response.json()?;

    if jwks.keys.is_empty() {
        return Err(JwksError::InvalidJwksData("No keys found in JWKS".into()));
    }

    Ok(jwks)
}

pub async fn init_jwks_async(jwk_url: &str) -> Result<(), JwksError> {
    let jwks = fetch_jwks_async(jwk_url).await?;
    JWKS_CACHE
        .set(jwks)
        .map_err(|_| JwksError::InvalidJwksData("Failed to set JWKS cache".into()))?;
    Ok(())
}

/// Fetches the JWKS from the provided URL using async I/O.
pub async fn fetch_jwks_async(jwk_url: &str) -> Result<Jwks, JwksError> {
    let user_agent = format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&user_agent).expect("Invalid user agent header"),
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let response = client.get(jwk_url).send().await?.error_for_status()?;

    let jwks: Jwks = response.json().await?;

    if jwks.keys.is_empty() {
        return Err(JwksError::InvalidJwksData("No keys found in JWKS".into()));
    }

    Ok(jwks)
}

pub fn get_jwk_keys() -> Result<&'static Jwks, JwksError> {
    JWKS_CACHE.get().ok_or(JwksError::NotInitialized)
}
