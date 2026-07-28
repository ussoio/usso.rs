//! Axum integration — [`FromRequestParts`] extractors for USSO authentication.
//!
//! Requires the `axum` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! usso = { version = "0.3", features = ["axum"] }
//! ```
//!
//! # Extractors
//!
//! | Extractor | Description |
//! |-----------|-------------|
//! | [`AuthenticatedUser`] | Mandatory auth — rejects with 401 if token is missing or invalid |
//! | [`OptionalUser`] | Optional auth — returns `None` instead of rejecting |
//!
//! Both extractors read a Bearer token from the `Authorization` header and
//! validate it via `Extension<Arc<UssoAuth>>` which must be added to the router.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::{Router, routing::get, Extension};
//! use usso::core::UssoAuth;
//! use usso::integrations::axum::AuthenticatedUser;
//!
//! let auth = Arc::new(UssoAuth::new(None, Some("https://sso.usso.io".into())));
//!
//! async fn handler(user: AuthenticatedUser) -> String {
//!     format!("Hello {}", user.0.sub.as_deref().unwrap_or("unknown"))
//! }
//!
//! let app: Router<()> = Router::new()
//!     .route("/me", get(handler))
//!     .layer(Extension(auth));
//! ```

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};

use crate::core::UssoAuth;
use crate::schemas::UserData;

/// Axum extractor that authenticates a user from the request.
///
/// Extracts the Bearer token from the `Authorization` header and validates it
/// via [`UssoAuth`]. Requires `Extension<Arc<UssoAuth>>` to be added to the
/// router (usually via a [`tower::Layer`] or directly on the [`axum::Router`]).
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum::{Router, routing::get, Extension};
/// use usso::core::UssoAuth;
/// use usso::integrations::axum::AuthenticatedUser;
///
/// let auth = Arc::new(UssoAuth::new(None, Some("https://sso.usso.io".into())));
///
/// async fn handler(user: AuthenticatedUser) -> String {
///     format!("Hello {}", user.0.sub.as_deref().unwrap_or("unknown"))
/// }
///
/// let app: Router<()> = Router::new()
///     .route("/me", get(handler))
///     .layer(Extension(auth));
/// ```
pub struct AuthenticatedUser(pub UserData);

/// Axum extractor that optionally authenticates a user.
///
/// Like [`AuthenticatedUser`] but does not reject the request if no valid token
/// is found. This is useful for endpoints that work both for authenticated and
/// unauthenticated users.
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum::{Router, routing::get, Extension};
/// use usso::core::UssoAuth;
/// use usso::integrations::axum::OptionalUser;
///
/// let auth = Arc::new(UssoAuth::new(None, Some("https://sso.usso.io".into())));
///
/// async fn handler(user: OptionalUser) -> String {
///     match user.0 {
///         Some(u) => format!("Hello {}", u.sub.as_deref().unwrap_or("unknown")),
///         None => "Hello anonymous".into(),
///     }
/// }
///
/// let app: Router<()> = Router::new()
///     .route("/", get(handler))
///     .layer(Extension(auth));
/// ```
pub struct OptionalUser(pub Option<UserData>);

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() { None } else { Some(token.to_string()) }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .extensions
            .get::<Arc<UssoAuth>>()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "USSO auth not configured").into_response())?;

        let token = extract_bearer_token(&parts.headers)
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing token").into_response())?;

        let user = auth
            .user_data_from_token(&token, Some("access"))
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token").into_response())?;

        Ok(AuthenticatedUser(user))
    }
}

impl<S> FromRequestParts<S> for OptionalUser
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = match parts.extensions.get::<Arc<UssoAuth>>() {
            Some(a) => a,
            None => return Ok(OptionalUser(None)),
        };

        let token = match extract_bearer_token(&parts.headers) {
            Some(t) => t,
            None => return Ok(OptionalUser(None)),
        };

        let user = match auth.user_data_from_token(&token, Some("access")) {
            Ok(u) => u,
            Err(_) => return Ok(OptionalUser(None)),
        };

        Ok(OptionalUser(Some(user)))
    }
}
