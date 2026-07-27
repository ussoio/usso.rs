use thiserror::Error;

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
    pub fn status_code(&self) -> u16 {
        match self {
            USSOError::PermissionDenied => 403,
            _ => 401,
        }
    }

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

#[derive(Error, Debug)]
pub enum JwksError {
    #[error("HTTP error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Invalid JWKS data: {0}")]
    InvalidJwksData(String),
    #[error("JWKS not initialized")]
    NotInitialized,
}

#[derive(Debug)]
pub enum JwtError {
    InvalidFormat,
    DecodingError(String),
    MissingField(String),
    InvalidToken(String),
}
