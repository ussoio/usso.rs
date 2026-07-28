//! Asynchronous API client.

use std::collections::HashMap;

use reqwest::Client;
use serde_json::Value;
use thiserror::Error;

use crate::core::Usso;
use crate::exceptions::USSOError;
use crate::schemas::UserResponse;

/// Errors returned by the sync and async API clients.
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("USSO error: {0}")]
    USSOError(USSOError),
    #[error("Value error: {0}")]
    ValueError(String),
}

/// An asynchronous API client for the USSO backend.
///
/// Mirrors the [`sync::UssoClient`](crate::client::sync::UssoClient) API
/// but uses `async` methods. All methods are prefixed with `async` or are
/// inherently async.
///
/// # Example
///
/// ```rust,no_run
/// use usso::client::async_code::AsyncUssoClient;
///
/// # async fn example() {
/// let mut client = AsyncUssoClient::new(
///     "https://sso.usso.io",
///     Some("api-key-123".into()),
///     None, None, None,
/// );
/// let users = client.get_users().await.unwrap();
/// # }
/// ```
pub struct AsyncUssoClient {
    pub client: Client,
    pub usso: Usso,
    pub base_url: String,
    pub api_key: Option<String>,
    pub agent_id: Option<String>,
    pub agent_private_key: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub headers: HashMap<String, String>,
    pub usso_refresh_url: String,
}

impl AsyncUssoClient {
    pub fn new(
        base_url: &str,
        api_key: Option<String>,
        agent_id: Option<String>,
        agent_private_key: Option<String>,
        refresh_token: Option<String>,
    ) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let usso_refresh_url = format!("{}/api/sso/v1/auth/refresh", base_url);
        let mut headers = HashMap::new();
        if let Some(ref key) = api_key {
            headers.insert("x-api-key".to_string(), key.clone());
        }

        AsyncUssoClient {
            client: Client::new(),
            usso: Usso::new(None, None, None),
            base_url,
            api_key,
            agent_id,
            agent_private_key,
            refresh_token,
            access_token: None,
            headers,
            usso_refresh_url,
        }
    }

    pub fn is_temporally_valid(&self) -> bool {
        match &self.access_token {
            Some(token) => crate::core::is_expired(token).map(|expired| !expired).unwrap_or(false),
            None => false,
        }
    }

    pub async fn get_session(&mut self) -> Result<(), ClientError> {
        if self.api_key.is_some() {
            return Ok(());
        }
        if !self.is_temporally_valid() {
            self.refresh().await?;
        }
        Ok(())
    }

    pub async fn refresh(&mut self) -> Result<(), ClientError> {
        let token = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("refresh_token is required".to_string()))?;

        let response = self
            .client
            .post(&self.usso_refresh_url)
            .json(&serde_json::json!({"refresh_token": token}))
            .send()
            .await
            .map_err(ClientError::HttpError)?;

        if !response.status().is_success() {
            return Err(ClientError::ValueError("Failed to refresh token".to_string()));
        }

        let data: Value = response.json().await.map_err(ClientError::HttpError)?;
        let access_token = data
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::ValueError("No access_token in response".to_string()))?;

        self.access_token = Some(access_token.to_string());
        self.headers
            .insert("Authorization".to_string(), format!("Bearer {}", access_token));
        Ok(())
    }

    pub async fn get_users(&self) -> Result<Vec<UserResponse>, ClientError> {
        let url = format!("{}/api/sso/v1/users", self.base_url);
        let mut req = self.client.get(&url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let response = req.send().await.map_err(ClientError::HttpError)?;
        let data: Value = response.json().await.map_err(ClientError::HttpError)?;
        let items = data
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ClientError::ValueError("No items in response".to_string()))?;
        let mut users = Vec::new();
        for item in items {
            let user: UserResponse = serde_json::from_value(item.clone())
                .map_err(|e| ClientError::ValueError(e.to_string()))?;
            users.push(user);
        }
        Ok(users)
    }

    pub async fn create_users(&self, data: Option<Value>) -> Result<UserResponse, ClientError> {
        let url = format!("{}/api/sso/v1/users", self.base_url);
        let mut req = self.client.post(&url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(json_data) = data {
            req = req.json(&json_data);
        }
        let response = req.send().await.map_err(ClientError::HttpError)?;
        response
            .json::<UserResponse>()
            .await
            .map_err(ClientError::HttpError)
    }

    pub async fn get_profile(&self, user_id: &str) -> Result<Value, ClientError> {
        let url = format!("{}/api/sso/v1/profiles/{}", self.base_url, user_id);
        let mut req = self.client.get(&url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let response = req.send().await.map_err(ClientError::HttpError)?;
        response.json::<Value>().await.map_err(ClientError::HttpError)
    }

    pub async fn add_identifier(
        &self,
        user_id: &str,
        identifier_type: &str,
        identifier: &str,
    ) -> Result<Value, ClientError> {
        let url = format!("{}/api/sso/v1/users/{}/identifiers", self.base_url, user_id);
        let mut req = self.client.post(&url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let response = req
            .json(&serde_json::json!({"type": identifier_type, "identifier": identifier}))
            .send()
            .await
            .map_err(ClientError::HttpError)?;
        response.json::<Value>().await.map_err(ClientError::HttpError)
    }

    pub async fn use_agent_token(
        &mut self,
        scopes: &[String],
        aud: &str,
        tenant_id: Option<&str>,
    ) -> Result<String, ClientError> {
        let agent_id = self
            .agent_id
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("agent_id is required".to_string()))?;
        let agent_private_key = self
            .agent_private_key
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("agent_private_key is required".to_string()))?;

        let tenant_id = match tenant_id {
            Some(tid) => Some(tid.to_string()),
            None => {
                let agent_response = self.get_agent_scopes().await?;
                agent_response
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            }
        };

        let jwt = crate::utils::agent::generate_agent_jwt(
            scopes,
            aud,
            tenant_id.as_deref(),
            Some(agent_id),
            Some(agent_private_key),
        );

        let token =
            crate::utils::agent::get_agent_token_async(&jwt, &self.base_url)
                .await?;
        self.access_token = Some(token.clone());
        self.headers
            .insert("Authorization".to_string(), format!("Bearer {}", token));
        Ok(token)
    }

    async fn get_agent_scopes(&self) -> Result<Value, ClientError> {
        let agent_id = self
            .agent_id
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("agent_id is required".to_string()))?;
        let agent_private_key = self
            .agent_private_key
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("agent_private_key is required".to_string()))?;

        let jwt = crate::utils::agent::generate_agent_jwt(
            &[],
            "sso",
            None,
            Some(agent_id),
            Some(agent_private_key),
        );

        let url = format!("{}/api/sso/v1/agents/scopes", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .map_err(ClientError::HttpError)?;
        response.json::<Value>().await.map_err(ClientError::HttpError)
    }

    async fn get_api_key_scopes(&self) -> Result<Value, ClientError> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| ClientError::ValueError("api_key is required".to_string()))?;

        let url = format!("{}/api/sso/v1/apikeys/verify", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({"api_key": api_key}))
            .send()
            .await
            .map_err(ClientError::HttpError)?;
        response.json::<Value>().await.map_err(ClientError::HttpError)
    }

    pub async fn get_scopes(&mut self) -> Result<Vec<String>, ClientError> {
        if let Some(ref token) = self.access_token {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() == 3 {
                use base64::Engine;
                let payload_bytes =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(parts[1])
                        .map_err(|e| ClientError::ValueError(e.to_string()))?;
                if let Ok(payload) =
                    serde_json::from_slice::<serde_json::Value>(&payload_bytes)
                {
                    if let Some(scopes) = payload.get("scopes").and_then(|v| v.as_array()) {
                        return Ok(scopes
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect());
                    }
                }
            }
        }

        if self.api_key.is_some() {
            let response = self.get_api_key_scopes().await?;
            return Ok(response
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default());
        }

        if self.agent_id.is_some() && self.agent_private_key.is_some() {
            let response = self.get_agent_scopes().await?;
            return Ok(response
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default());
        }

        if self.refresh_token.is_some() {
            self.refresh().await?;
            if let Some(ref token) = self.access_token {
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() == 3 {
                    use base64::Engine;
                    let payload_bytes =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(parts[1])
                            .map_err(|e| ClientError::ValueError(e.to_string()))?;
                    if let Ok(payload) =
                        serde_json::from_slice::<serde_json::Value>(&payload_bytes)
                    {
                        if let Some(scopes) = payload.get("scopes").and_then(|v| v.as_array()) {
                            return Ok(scopes
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect());
                        }
                    }
                }
            }
        }

        Ok(vec![])
    }

    pub async fn get_token(
        &mut self,
        scopes: &[String],
        aud: &str,
    ) -> Result<Option<String>, ClientError> {
        let user_scopes = self.get_scopes().await?;
        for scope in scopes {
            if !crate::authorization::has_subset_scope(scope, &user_scopes) {
                return Err(ClientError::USSOError(USSOError::PermissionDenied));
            }
        }

        if self.agent_id.is_none() || self.agent_private_key.is_none() {
            return Ok(None);
        }

        self.use_agent_token(scopes, aud, None).await.map(Some)
    }
}
