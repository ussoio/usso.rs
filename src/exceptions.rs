//! Error types for the USSO client.
//!
//! - [`USSOError`] — authentication and authorization errors
//! - [`JwksError`] — JWKS fetching and caching errors
//! - [`JwtError`] — JWT parsing errors

use thiserror::Error;

/// Authentication and authorization errors returned by the library.
///
/// Each variant maps to an HTTP status code via [`status_code`](Self::status_code)
/// and a machine-readable error code via [`error_code`](Self::error_code).
#[derive(Error, Debug)]
pub enum USSOError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Expired token")]
    ExpiredToken,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Invalid token type")]
    InvalidTokenType,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("{0}")]
    Other(String),
}

impl USSOError {
    /// Returns the HTTP status code for this error (401 for most, 403 for permission denied).
    pub fn status_code(&self) -> u16 {
        match self {
            USSOError::PermissionDenied => 403,
            _ => 401,
        }
    }

    /// Returns a machine-readable error code string for this error.
    pub fn error_code(&self) -> &str {
        match self {
            USSOError::InvalidSignature => "invalid_signature",
            USSOError::InvalidToken => "invalid_token",
            USSOError::ExpiredToken => "expired_signature",
            USSOError::Unauthorized => "unauthorized",
            USSOError::InvalidTokenType => "invalid_token_type",
            USSOError::PermissionDenied => "permission_denied",
            USSOError::Other(_) => "error",
        }
    }
}

/// Errors that can occur when fetching or caching JWKS keys.
#[derive(Error, Debug)]
pub enum JwksError {
    #[error("HTTP error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Invalid JWKS data: {0}")]
    InvalidJwksData(String),
    #[error("JWKS not initialized")]
    NotInitialized,
}

/// Errors that can occur when parsing JWT headers or payloads.
#[derive(Debug)]
pub enum JwtError {
    InvalidFormat,
    DecodingError(String),
    MissingField(String),
    InvalidToken(String),
}
