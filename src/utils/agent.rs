use base64::Engine;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use ed25519_dalek::{Signer, SigningKey};
use ed25519_dalek::pkcs8::DecodePrivateKey;

pub fn generate_agent_jwt(
    scopes: &[String],
    aud: &str,
    tenant_id: Option<&str>,
    agent_id: Option<&String>,
    private_key: Option<&String>,
) -> String {
    let agent_id = agent_id.expect("agent_id is required");
    let pk_str = private_key.expect("private_key is required");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut payload = serde_json::json!({
        "iss": agent_id,
        "scopes": scopes,
        "aud": aud,
        "exp": now + 300,
        "nbf": now,
        "iat": now,
        "jti": Uuid::new_v4().to_string(),
    });
    if let Some(tid) = tenant_id {
        payload["tenant_id"] = serde_json::json!(tid);
    }

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&serde_json::json!({
            "alg": "Ed25519",
            "typ": "JWT",
        })).unwrap().as_bytes());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap().as_bytes());

    let signing_key = SigningKey::from_pkcs8_pem(pk_str).ok()
        .or_else(|| {
            let bytes = pk_str.as_bytes();
            let seed: [u8; 32] = bytes.try_into().ok()?;
            Some(SigningKey::from_bytes(&seed))
        });

    match signing_key {
        Some(key) => {
            let sig = key.sign(format!("{}.{}", header_b64, payload_b64).as_bytes());
            format!("{}.{}.{}", header_b64, payload_b64, 
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        }
        None => format!("{}.{}.", header_b64, payload_b64),
    }
}

pub fn get_agent_token(jwt: &str, base_url: &str) -> Result<String, crate::client::sync::ClientError> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/api/sso/v1/agents/auth", base_url);
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .map_err(crate::client::sync::ClientError::HttpError)?;

    let data: serde_json::Value = response
        .json()
        .map_err(crate::client::sync::ClientError::HttpError)?;

    data.get("tokens")
        .and_then(|t| t.get("access"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            crate::client::sync::ClientError::ValueError(
                "No access token in response".to_string(),
            )
        })
}

pub async fn get_agent_token_async(
    jwt: &str,
    base_url: &str,
) -> Result<String, crate::client::async_code::ClientError> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/sso/v1/agents/auth", base_url);
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(crate::client::async_code::ClientError::HttpError)?;

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(crate::client::async_code::ClientError::HttpError)?;

    data.get("tokens")
        .and_then(|t| t.get("access"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            crate::client::async_code::ClientError::ValueError(
                "No access token in response".to_string(),
            )
        })
}
