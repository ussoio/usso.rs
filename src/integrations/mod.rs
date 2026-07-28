//! Framework integrations for web frameworks.
//!
//! # Feature flags
//!
//! Each integration is gated behind a Cargo feature:
//!
//! | Feature | Module | Description |
//! |---------|--------|-------------|
//! | `axum` | [`axum`] | `FromRequestParts` extractors (`AuthenticatedUser`, `OptionalUser`) |

#[cfg(feature = "axum")]
pub mod axum;
