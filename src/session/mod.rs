//! Lightweight session wrappers for basic USSO API access.
//!
//! - [`base_session::BaseUssoSession`] — shared HTTP client and headers
//! - [`sync::UssoSession`] — synchronous session
//! - [`async_code::AsyncUssoSession`] — async session

pub mod async_code;
pub mod base_session;
pub mod sync;
