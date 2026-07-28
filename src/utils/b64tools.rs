//! Base64↔UUID conversion utilities.
//!
//! USSO uses URL-safe base64 encoding (without padding by default) for UUIDs
//! in token claims. These helpers convert between [`Uuid`] and base64 strings.

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use uuid::Uuid;

/// Encode a [`Uuid`] as a URL-safe base64 string (with padding).
pub fn b64_encode_uuid(uuid: Uuid) -> String {
    URL_SAFE.encode(uuid.as_bytes())
}

/// Encode a [`Uuid`] as a URL-safe base64 string without padding.
pub fn b64_encode_uuid_strip(uuid: Uuid) -> String {
    b64_encode_uuid(uuid).trim_end_matches('=').to_string()
}

/// Decode a URL-safe base64 string into a [`Uuid`].
pub fn b64_decode_uuid(encoded: &str) -> Result<Uuid, base64::DecodeError> {
    let decoded = URL_SAFE.decode(encoded)?;
    Ok(Uuid::from_slice(&decoded).expect("base64 is invalid!"))
}
