//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! Provides both synchronous and asynchronous functions to fetch JWKS from a
//! remote URL. Keys are cached globally in a [`OnceLock`] so that multiple
//! token validations reuse the same key set without redundant HTTP calls.
//!
//! # Example
//!
//! ```rust,no_run
//! use usso::jwks::init_jwks_sync;
//!
//! init_jwks_sync("https://sso.usso.io/website/jwks.json").unwrap();
//! let keys = usso::jwks::get_jwk_keys().unwrap();
//! println!("Loaded {} keys", keys.keys.len());
//! ```

use crate::{exceptions::JwksError, schemas::Jwks};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use std::sync::OnceLock;

static JWKS_CACHE: OnceLock<Jwks> = OnceLock::new();

/// Fetch JWKS from a URL and store it in the global cache (blocking).
///
/// Must be called before [`get_jwk_keys`] or [`decode_token_with_jwks`](crate::core::decode_token_with_jwks).
pub fn init_jwks_sync(jwk_url: &str) -> Result<(), JwksError> {
    let jwks = fetch_jwks_sync(jwk_url)?;
    JWKS_CACHE
        .set(jwks)
        .map_err(|_| JwksError::InvalidJwksData("Failed to set JWKS cache".into()))?;
    Ok(())
}

/// Fetch JWKS from the given URL (blocking) without caching.
///
/// Sets a `User-Agent` header identifying the crate name, version, and repository.
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

/// Fetch JWKS from a URL and store it in the global cache (async).
///
/// Must be called before [`get_jwk_keys`] or [`decode_token_with_jwks`](crate::core::decode_token_with_jwks).
pub async fn init_jwks_async(jwk_url: &str) -> Result<(), JwksError> {
    let jwks = fetch_jwks_async(jwk_url).await?;
    JWKS_CACHE
        .set(jwks)
        .map_err(|_| JwksError::InvalidJwksData("Failed to set JWKS cache".into()))?;
    Ok(())
}

/// Fetch JWKS from the given URL (async) without caching.
///
/// Sets a `User-Agent` header identifying the crate name, version, and repository.
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

/// Get a reference to the globally cached JWKS key set.
///
/// Returns `JwksError::NotInitialized` if [`init_jwks_sync`] or
/// [`init_jwks_async`] has not been called yet.
pub fn get_jwk_keys() -> Result<&'static Jwks, JwksError> {
    JWKS_CACHE.get().ok_or(JwksError::NotInitialized)
}
