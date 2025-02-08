use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use uuid::Uuid;

pub fn b64_encode_uuid(uuid: Uuid) -> String {
    URL_SAFE.encode(uuid.as_bytes())
}

pub fn b64_encode_uuid_strip(uuid: Uuid) -> String {
    b64_encode_uuid(uuid).trim_end_matches('=').to_string()
}

pub fn b64_decode_uuid(encoded: &str) -> Result<Uuid, base64::DecodeError> {
    let decoded = URL_SAFE.decode(encoded)?;
    Ok(Uuid::from_slice(&decoded).expect("wtf in b64"))
}
