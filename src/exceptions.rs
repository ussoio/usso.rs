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
    #[error("Error: {0}")]
    Other(String),
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
