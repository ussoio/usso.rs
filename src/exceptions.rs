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