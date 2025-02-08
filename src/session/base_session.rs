use std::collections::HashMap;

use reqwest::blocking::Client;
use reqwest::Method;
use thiserror::Error;

use crate::core::Usso;
use crate::exceptions::USSOError;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("USSO error: {0}")]
    USSOError(USSOError),
}

pub struct BaseUssoSession {
    pub client: Client,
    pub usso: Usso,
    pub base_url: String,
    pub api_key: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub headers: HashMap<String, String>,
}

impl BaseUssoSession {
    pub fn new(base_url: &str, api_key: Option<String>, refresh_token: Option<String>) -> Self {
        BaseUssoSession {
            client: Client::new(),
            usso: Usso::new(None, None, None),
            base_url: base_url.to_string(),
            api_key,
            refresh_token,
            access_token: None,
            headers: HashMap::new(),
        }
    }

    pub fn request(&self, method: Method, url: &String) -> Result<String, SessionError> {
        let response = self
            .client
            .request(method, url)
            .send()
            .map_err(SessionError::HttpError)?;
        response.text().map_err(SessionError::HttpError)
    }
}
