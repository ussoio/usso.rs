//! # USSO-RS
//!
//! Universal Single Sign-On (SSO) client for Rust microservices.
//!
//! Authenticate users, validate JWTs, check authorization scopes, and manage
//! sessions against the [USSO](https://usso.io) identity platform.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use usso::core::Usso;
//!
//! let usso = Usso::new(None, Some("https://sso.usso.io/website/jwks.json".into()), None);
//! let user = usso.user_data_from_token("eyJ...");
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `axum` | disabled | Enables [`integrations::axum`] — `FromRequestParts` extractors for axum |
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`core`] | JWT decoding, `Usso` and `UssoAuth` auth orchestrators |
//! | [`config`] | `AuthConfig`, `HeaderConfig`, `APIHeaderConfig` configuration types |
//! | [`jwks`] | JWKS fetching (sync/async) with global caching |
//! | [`authorization`] | Scope-based RBAC engine (includes `owner_authorization`, `broadest_scope_filter`, `get_common_scopes`) |
//! | [`integrations`] | Framework integrations (axum behind the `axum` feature) |
//! | [`client`] | Full API client with session management (sync + async) |
//! | [`session`] | Lightweight session wrapper |
//! | [`schemas`] | Data types: `UserData`, `Jwk` (RSA + EC), `Jwks`, `UserResponse` |
//! | [`exceptions`] | Error types |
//! | [`utils`] | Agent JWT generation and base64↔UUID utilities |

pub mod authorization;
pub mod client;
pub mod config;
pub mod core;
pub mod exceptions;
pub mod jwks;
pub mod schemas;
pub mod session;
pub mod integrations;
pub mod utils;
