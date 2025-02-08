use reqwest::Client;
use serde_json::Value;
use thiserror::Error;

use crate::core::Usso;
use crate::exceptions::USSOError;
use crate::schemas::UserData;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("USSO error: {0}")]
    USSOError(USSOError),
}

pub struct AsyncUssoClient {
    pub client: Client,
    pub usso: Usso,
    pub base_url: String,
    pub api_key: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
}

impl AsyncUssoClient {
    pub fn new(base_url: &str, api_key: Option<String>, refresh_token: Option<String>) -> Self {
        AsyncUssoClient {
            client: Client::new(),
            usso: Usso::new(None, None, None),
            base_url: base_url.to_string(),
            api_key,
            refresh_token,
            access_token: None,
        }
    }

    pub async fn get_users(&self) -> Result<Vec<UserData>, ClientError> {
        let url = format!("{}/website/users", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ClientError::HttpError)?;
        let users: Vec<Value> = response.json().await.map_err(ClientError::HttpError)?;
        Ok(users
            .into_iter()
            .map(|user| UserData::from_json(&user))
            .collect())
    }
}
