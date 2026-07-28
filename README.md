# USSO-RS

[![Crates.io](https://img.shields.io/crates/v/usso.svg)](https://crates.io/crates/usso)
[![Docs](https://docs.rs/usso/badge.svg)](https://docs.rs/usso)
[![Rust Crate CI](https://github.com/ussoio/usso.rs/actions/workflows/crate.yml/badge.svg)](https://github.com/ussoio/usso.rs/actions/workflows/crate.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENCE.txt)

**Universal Single Sign-On (USSO) client for Rust microservices.**

Authenticate users, validate JWTs, check authorization scopes, and manage sessions against the [USSO](https://usso.io) identity platform — all with a single crate.

---

## Features

- **JWT validation** — Decode and verify JWTs signed with RS256/RS384/RS512/PS256/PS384/PS512, ES256/ES384/**ES512**, or EdDSA (auto-detected from the JWT header). JWKS keys support both RSA and EC key types.
- **API key authentication** — Verify API keys against the USSO backend.
- **Agent (service-to-service) auth** — Generate Ed25519-signed agent JWTs and exchange them for access tokens.
- **Token refresh** — Automatically refresh expired access tokens via the USSO refresh endpoint.
- **Scope-based authorization (RBAC)** — Built-in hierarchical permission engine with wildcard path/filter matching, owner authorization, scope intersection, and filter scoring.
- **Sync + Async** — Every API surface is available in both blocking and async variants.
- **User management** — List, create, and profile users via the USSO REST API.
- **Configurable** — Customize header names, cookie names, algorithms, and JWKS URLs.
- **Axum integration** *(optional)* — `FromRequestParts` extractors for painless auth in axum web apps.

---

## Quick Start

```toml
[dependencies]
usso = "0.3"

# Optional: axum integration
usso = { version = "0.3", features = ["axum"] }
```

### Validate a JWT (sync)

```rust
use usso::core::Usso;

let usso = Usso::new(None, Some("https://sso.usso.io/website/jwks.json".into()), None);
match usso.user_data_from_token("eyJ...") {
    Ok(user) => println!("Hello, {}", user.email.unwrap_or_default()),
    Err(e) => eprintln!("Auth failed: {}", e),
}
```

### Validate a JWT (async)

```rust
use usso::jwks::init_jwks_async;
use usso::core::decode_token_with_jwks;

init_jwks_async("https://sso.usso.io/website/jwks.json").await.unwrap();
let user = decode_token_with_jwks("https://sso.usso.io/website/jwks.json", "eyJ...").unwrap();
```

### Validate with token-type enforcement

```rust
use usso::core::UssoAuth;

let auth = UssoAuth::new(None, Some("https://sso.usso.io".into()));
// Enforce that this must be an "access" token
let user = auth.user_data_from_token("eyJ...", Some("access"))?;
```

### API key verification

```rust
use std::collections::HashMap;
let user = auth.user_data_from_api_key("sk-...", &HashMap::new())?;
```

### Interact with the USSO API

```rust
use usso::client::sync::UssoClient;

let mut client = UssoClient::new(
    "https://sso.usso.io",
    Some("api-key-123".into()),
    None, None, None,
);
let users = client.get_users()?;
```

### Agent authentication (server-to-server)

```rust
let mut client = UssoClient::new(
    "https://sso.usso.io",
    None,
    Some("agent-id-xyz".into()),
    Some("-----BEGIN PRIVATE KEY-----...".into()),
    None,
);
let token = client.use_agent_token(
    &["read:users".into()],
    "my-service",
    None,
)?;
```

### Authorization checks

```rust
use usso::authorization::check_access;

let scopes = vec!["admin:users".into(), "read:reports".into()];
let allowed = check_access(&scopes, "users", Some("delete"), None, false);
```

### Axum integration (requires `axum` feature)

```rust
use std::sync::Arc;
use axum::{Router, routing::get, Extension};
use usso::core::UssoAuth;
use usso::integrations::axum::AuthenticatedUser;

let auth = Arc::new(UssoAuth::new(None, Some("https://sso.usso.io".into())));

async fn me(user: AuthenticatedUser) -> String {
    format!("Hello {}", user.0.sub.as_deref().unwrap_or("unknown"))
}

let app: Router<()> = Router::new()
    .route("/me", get(me))
    .layer(Extension(auth));
```

---

## Modules

| Module | Description |
|--------|-------------|
| [`core`](https://docs.rs/usso/latest/usso/core/) | JWT decoding (RSA, EC, EdDSA, ES512), `Usso` and `UssoAuth` auth orchestrators |
| [`config`](https://docs.rs/usso/latest/usso/config/) | `AuthConfig`, `HeaderConfig`, `APIHeaderConfig` |
| [`jwks`](https://docs.rs/usso/latest/usso/jwks/) | JWKS fetching (sync/async) with global caching via `OnceLock` |
| [`authorization`](https://docs.rs/usso/latest/usso/authorization/) | Scope-based RBAC: `check_access`, `has_subset_scope`, `is_authorized`, `owner_authorization`, `broadest_scope_filter`, `get_common_scopes` |
| [`client`](https://docs.rs/usso/latest/usso/client/) | Full API client (`UssoClient` / `AsyncUssoClient`) with session management |
| [`session`](https://docs.rs/usso/latest/usso/session/) | Lightweight session wrapper (`UssoSession` / `AsyncUssoSession`) |
| [`schemas`](https://docs.rs/usso/latest/usso/schemas/) | Data types: `UserData`, `Jwk` (RSA + EC), `Jwks`, `UserResponse`, `UserIdentifierSchema` |
| [`exceptions`](https://docs.rs/usso/latest/usso/exceptions/) | Error types: `USSOError`, `JwksError`, `JwtError` |
| [`integrations`](https://docs.rs/usso/latest/usso/integrations/) | Framework integrations (axum — feature-gated) |
| [`utils`](https://docs.rs/usso/latest/usso/utils/) | Agent JWT generation and base64↔UUID conversion |

---

## Configuration

### AuthConfig

```rust
use usso::config::{AuthConfig, HeaderConfig, APIHeaderConfig};

let config = AuthConfig {
    jwks_url: Some("https://sso.usso.io/.well-known/jwks.json".into()),
    api_key_header: Some(APIHeaderConfig {
        header_name: Some("x-api-key".into()),
        verify_endpoint: String::new(), // defaults to /api/sso/v1/apikeys/verify
    }),
    jwt_header: Some(HeaderConfig {
        header_name: Some("Authorization".into()),
        cookie_name: Some("usso-access-token".into()),
    }),
    algorithm: "RS256".into(), // algorithm is auto-detected from the JWT header
};
```

### Environment

```env
JWKS_URL=https://sso.usso.io/website/jwks.json
```

---

## Algorithm Support

Token verification auto-detects the signing algorithm from the JWT header:

| Algorithm | Key Type | JWK Fields | Support |
|-----------|----------|------------|---------|
| RS256 / RS384 / RS512 | RSA | `n`, `e` | ✅ |
| PS256 / PS384 / PS512 | RSA-PSS | `n`, `e` | ✅ |
| ES256 / ES384 | ECDSA (P-256, P-384) | `crv`, `x`, `y` | ✅ |
| **ES512** | ECDSA (P-521) | `crv`, `x`, `y` | ✅ |
| EdDSA (Ed25519) | Edwards | `x` | ✅ |

---

## Authorization System

Scopes follow the format: `<action>:<resource>/<path>?<filters>`

**Privilege hierarchy:** `none(0)` < `read(10)` < `create(20)` < `update(30)` < `delete(40)` < `manage(50)` < `admin(60)` < `owner/*(90)` < `superadmin(100)`

Wildcards (`*`) are supported in path segments and filter values:
- `admin:*` matches any resource
- `read:users/*` matches any sub-resource of users
- `read:users?region=*` matches any region

### Available functions

| Function | Purpose |
|----------|---------|
| `check_access` | Check if any of the user's scopes grant access to a resource |
| `is_authorized` | Check a single user scope against a resource path |
| `has_subset_scope` / `is_subset_scope` | Scope containment / delegation checks |
| `owner_authorization` | Check if a user has owner-level access via user/workspace ID filters |
| `broadest_scope_filter` | Pick the least restrictive filter from a list (by restriction score) |
| `get_common_scopes` | Intersect two scope lists, preserving permitted scopes |
| `get_scope_filters` | Extract filters from scopes matching an action and resource |
| `parse_scope` | Parse a scope string into `(action, path_segments, filters)` |

```rust
use usso::authorization::{
    check_access, has_subset_scope, is_authorized, parse_scope,
    owner_authorization, broadest_scope_filter, get_common_scopes,
};

// Parse a scope
let (action, path, filters) = parse_scope("admin:users/123?region=us-east");

// Check a single scope
let ok = is_authorized("admin:users", "users", Some("delete"), None, false);

// Check against multiple scopes
let ok = check_access(&["admin:users".into()], "users", Some("read"), None, false);

// Check scope containment
let ok = has_subset_scope("read:users", &["admin:*".into()]);

// Owner authorization
let filter = std::collections::HashMap::from([("user_id".into(), "u1".into())]);
let ok = owner_authorization(Some(&filter), Some("u1"), None, None, None, None);

// Broadest (least restrictive) filter
let filters = vec![
    std::collections::HashMap::from([("tenant_id".into(), "t1".into()), ("user_id".into(), "u1".into())]),
    std::collections::HashMap::from([("tenant_id".into(), "t1".into())]),
];
let broadest = broadest_scope_filter(&filters);

// Common scopes
let common = get_common_scopes(&["admin:users".into()], &["read:users".into()]);
```

---

## Architecture

```
Your Microservice
  │
  ├── UssoAuth ──► JWT validation (RSA / EC / EdDSA / ES512) ──► USSO Server
  │               ► API key verify
  │
  ├── UssoClient ──► User management API
  │                 ► Token refresh
  │                 ► Agent auth (Ed25519 JWT exchange)
  │                 ► Scope resolution
  │
  ├── authorization (RBAC engine — 11 public functions)
  ├── jwks (global JWKS cache via OnceLock)
  ├── config (header/cookie extraction)
  └── integrations (axum extractors — feature-gated)
```

---

## Error Handling

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| `USSOError::InvalidSignature` | 401 | JWT signature mismatch |
| `USSOError::InvalidToken` | 401 | Malformed or unrecognized token |
| `USSOError::ExpiredToken` | 401 | Token has expired |
| `USSOError::Unauthorized` | 401 | Missing or invalid credentials |
| `USSOError::InvalidTokenType` | 401 | Token type mismatch (e.g. expected `access` but got `refresh`) |
| `USSOError::PermissionDenied` | 403 | Insufficient scope for the requested action |

---

## Development

```bash
# Build
cargo build

# Build with axum integration
cargo build --features axum

# Test
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# All checks
just precommit
```

The project uses `just` as a task runner. See [`justfile`](justfile) for available commands.

---

## License

MIT — see [`LICENCE.txt`](LICENCE.txt).
