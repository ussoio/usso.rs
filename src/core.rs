//! Core JWT decoding and authentication orchestration.
//!
//! Provides [`Usso`] for basic JWT validation and [`UssoAuth`] for more
//! advanced auth flows including token-type enforcement and API key verification.
//!
//! ## Algorithm support
//!
//! Token verification auto-detects the algorithm from the JWT header:
//! - **RSA**: RS256, RS384, RS512, PS256, PS384, PS512
//! - **ECDSA**: ES256, ES384 (via `jsonwebtoken`), **ES512** (manual P-521)
//! - **EdDSA**: Ed25519
//!
//! RSA and EC keys are parsed from JWK `n`/`e` and `crv`/`x`/`y` respectively.

use base64::Engine;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::config::AuthConfig;
use crate::exceptions::USSOError;
use crate::jwks::{fetch_jwks_sync, get_jwk_keys};
use crate::schemas::{JWTConfig, Jwk, Jwks, UserData};

/// Decode and validate a JWT, auto-detecting the algorithm from the token header.
///
/// Supports RSA (RS256/RS384/RS512/PS256/PS384/PS512), EC (ES256/ES384),
/// EdDSA via `jsonwebtoken` and ES512 via manual ECDSA P-521 verification.
pub fn decode_token(key: &Jwk, token: &str) -> Result<UserData, USSOError> {
    let header = crate::schemas::JwtHeader::from_token(token)
        .map_err(|_| USSOError::InvalidToken)?;

    match header.alg.as_str() {
        "ES512" => decode_es512_token(key, token),
        alg if matches!(
            alg,
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
        ) => decode_rsa_token(key, token, alg),
        alg if matches!(alg, "ES256" | "ES384") => decode_ec_token(key, token, alg),
        "EdDSA" => decode_eddsa_token(key, token),
        _ => Err(USSOError::InvalidToken),
    }
}

fn algorithm_from_str(s: &str) -> Option<Algorithm> {
    match s {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

fn decode_rsa_token(key: &Jwk, token: &str, alg: &str) -> Result<UserData, USSOError> {
    let n = key.n.as_deref().ok_or(USSOError::InvalidToken)?;
    let e = key.e.as_deref().ok_or(USSOError::InvalidToken)?;
    let decoding_key =
        DecodingKey::from_rsa_components(n, e).map_err(|_| USSOError::InvalidToken)?;
    let jsonwebtoken_alg = algorithm_from_str(alg).ok_or(USSOError::InvalidToken)?;
    let mut validation = Validation::new(jsonwebtoken_alg);
    validation.algorithms = vec![jsonwebtoken_alg];
    match decode::<UserData>(token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(USSOError::ExpiredToken),
            _ => Err(USSOError::InvalidToken),
        },
    }
}

fn decode_ec_token(key: &Jwk, token: &str, alg: &str) -> Result<UserData, USSOError> {
    let x_b64 = key.x.as_deref().ok_or(USSOError::InvalidToken)?;
    let y_b64 = key.y.as_deref().ok_or(USSOError::InvalidToken)?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| USSOError::InvalidToken)?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| USSOError::InvalidToken)?;
    let mut encoded = vec![0x04u8];
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);
    let decoding_key = DecodingKey::from_ec_der(&encoded);
    let jsonwebtoken_alg = algorithm_from_str(alg).ok_or(USSOError::InvalidToken)?;
    let mut validation = Validation::new(jsonwebtoken_alg);
    validation.algorithms = vec![jsonwebtoken_alg];
    match decode::<UserData>(token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(USSOError::ExpiredToken),
            _ => Err(USSOError::InvalidToken),
        },
    }
}

fn decode_eddsa_token(key: &Jwk, token: &str) -> Result<UserData, USSOError> {
    let x_b64 = key.x.as_deref().ok_or(USSOError::InvalidToken)?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| USSOError::InvalidToken)?;
    let decoding_key = DecodingKey::from_ed_der(&x);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.algorithms = vec![Algorithm::EdDSA];
    match decode::<UserData>(token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(USSOError::ExpiredToken),
            _ => Err(USSOError::InvalidToken),
        },
    }
}

fn decode_es512_token(key: &Jwk, token: &str) -> Result<UserData, USSOError> {
    use p521::ecdsa::{Signature, VerifyingKey};
    use p521::ecdsa::signature::Verifier;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(USSOError::InvalidToken);
    }

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| USSOError::InvalidToken)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| USSOError::InvalidToken)?;

    let x_b64 = key.x.as_deref().ok_or(USSOError::InvalidToken)?;
    let y_b64 = key.y.as_deref().ok_or(USSOError::InvalidToken)?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|_| USSOError::InvalidToken)?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|_| USSOError::InvalidToken)?;

    let mut encoded_point = vec![0x04u8];
    encoded_point.extend_from_slice(&x);
    encoded_point.extend_from_slice(&y);

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&encoded_point).map_err(|_| USSOError::InvalidToken)?;

    let message = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| USSOError::InvalidToken)?;

    // Check expiration
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| USSOError::InvalidToken)?;
    let claims: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&payload_bytes).map_err(|_| USSOError::InvalidToken)?;
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if exp < now {
            return Err(USSOError::ExpiredToken);
        }
    }

    let user_data: UserData =
        serde_json::from_slice(&payload_bytes).map_err(|_| USSOError::InvalidToken)?;
    Ok(user_data)
}



/// Check whether a JWT has expired by inspecting its `exp` claim.
///
/// If the `exp` claim is missing, the token is treated as valid for 24 hours.
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

/// Decode a JWT using the globally cached JWKS key set.
///
/// The JWKS cache must be initialized first via [`init_jwks_sync`](crate::jwks::init_jwks_sync)
/// or [`init_jwks_async`](crate::jwks::init_jwks_async). The correct key is
/// looked up by the `kid` header claim.
pub fn decode_token_with_jwks(_jwk_url: &str, token: &str) -> Result<UserData, USSOError> {
    let jwk_keys =
        get_jwk_keys().map_err(|_| USSOError::Other("JWKS not initialized".to_string()))?;
    let header =
        crate::schemas::JwtHeader::from_token(token).map_err(|_| USSOError::InvalidToken)?;
    let kid = header.kid.ok_or(USSOError::InvalidToken)?;
    let key = jwk_keys.match_kid(&kid).ok_or(USSOError::InvalidToken)?;
    decode_token(key, token)
}

/// A basic JWT authentication validator.
///
/// Accepts one or more JWT configurations (inline JWKS keys or a JWKS URL)
/// and attempts each in sequence when validating a token.
///
/// # Example
///
/// ```rust,no_run
/// use usso::core::Usso;
///
/// let usso = Usso::new(None, Some("https://sso.usso.io/website/jwks.json".into()), None);
/// match usso.user_data_from_token("eyJ...") {
///     Ok(user) => println!("Authenticated: {:?}", user.email),
///     Err(e) => eprintln!("Auth failed: {}", e),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Usso {
    jwt_configs: Vec<JWTConfig>,
}

impl Usso {
    /// Create a new `Usso` validator.
    ///
    /// - `jwt_config` — an explicit [`JWTConfig`] with keys and/or a JWKS URL
    /// - `jwk_url` — a JWKS URL to fetch keys from (used if `jwt_config` is `None`)
    /// - `key` — an inline [`Jwks`] key set (used if both above are `None`)
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

    /// Attempt to decode and validate a JWT against all configured key sources.
    ///
    /// Returns the first successfully decoded [`UserData`], or `USSOError::Unauthorized`
    /// if no config can validate the token.
    pub fn user_data_from_token(&self, token: &str) -> Result<UserData, USSOError> {
        for config in &self.jwt_configs {
            if let Ok(user_data) = config.decode(token) {
                return Ok(user_data);
            }
        }
        Err(USSOError::Unauthorized)
    }
}

/// A higher-level authentication manager.
///
/// Supports JWT validation with optional token-type enforcement (e.g. require
/// `token_type: "access"`) and API key verification against the USSO backend.
///
/// # Example
///
/// ```rust,no_run
/// use usso::core::UssoAuth;
///
/// let auth = UssoAuth::new(None, Some("https://sso.usso.io".into()));
/// let user = auth.user_data_from_token("eyJ...", Some("access"));
/// ```
#[derive(Debug, Clone)]
pub struct UssoAuth {
    jwt_configs: Vec<AuthConfig>,
    from_usso_base_url: Option<String>,
}

impl UssoAuth {
    /// Create a new `UssoAuth` manager.
    ///
    /// If `jwt_config` is `None`, a default [`AuthConfig`] is derived from
    /// `from_usso_base_url` (the JWKS URL becomes `{base}/.well-known/jwks.json`).
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

    /// Decode and validate a JWT, optionally enforcing the `token_type` claim.
    ///
    /// If `expected_token_type` is `Some("access")`, tokens whose `token_type`
    /// claim is not `"access"` are rejected.
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

    /// Verify an API key against the USSO backend and return the associated user data.
    ///
    /// Sends a POST request to the API key verify endpoint (`/api/sso/v1/apikeys/verify`).
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

    /// Heuristically detect the type of a compact token.
    ///
    /// - 3 dot-separated parts → `"jwt"`
    /// - 5 dot-separated parts → `"jwe"`
    /// - anything else → `None`
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
