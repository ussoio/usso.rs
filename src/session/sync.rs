use reqwest::Method;
use thiserror::Error;

use crate::exceptions::USSOError;
use crate::schemas::UserData;
use crate::session::base_session::BaseUssoSession;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("HTTP error: {0}")]
    HttpError(reqwest::Error),
    #[error("USSO error: {0}")]
    USSOError(USSOError),
}

pub struct UssoSession {
    base_session: BaseUssoSession,
}

impl UssoSession {
    pub fn new(base_url: &str, api_key: Option<String>, refresh_token: Option<String>) -> Self {
        UssoSession {
            base_session: BaseUssoSession::new(base_url, api_key, refresh_token),
        }
    }

    pub fn get_users(&self) -> Result<Vec<UserData>, SessionError> {
        let url = format!("{}/website/users", self.base_session.base_url);
        let response = self
            .base_session
            .request(Method::GET, &url)
            .expect("error in fetch");
        let users: Vec<UserData> = serde_json::from_str(&response)
            .map_err(|e| SessionError::USSOError(USSOError::Other(e.to_string())))?;
        Ok(users)
    }
}
