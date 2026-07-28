//! Full-featured API clients for interacting with the USSO backend.
//!
//! - [`sync::UssoClient`] — blocking client
//! - [`async_code::AsyncUssoClient`] — async client
//!
//! Both provide session management (token refresh), user CRUD, profile
//! retrieval, identifier management, and agent authentication.

pub mod async_code;
pub mod sync;
