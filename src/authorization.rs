//! Scope-based authorization (RBAC) engine.
//!
//! Scopes follow the format: `<action>:<resource>/<path>?<filters>`
//!
//! # Privilege hierarchy
//!
//! | Level | Value |
//! |-------|-------|
//! | `none` | 0 |
//! | `read` | 10 |
//! | `create` | 20 |
//! | `update` | 30 |
//! | `delete` | 40 |
//! | `manage` | 50 |
//! | `admin` | 60 |
//! | `owner` / `*` | 90 |
//! | `superadmin` | 100 |
//!
//! Wildcards (`*`) in path segments and filter values match any value.
//!
//! # Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`Action`] | Enum for the 9 known privilege levels (Read, Write, Admin, etc.) |
//!
//! # Public functions
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`parse_scope`] | Parse a scope string into (action, path, filters) |
//! | [`check_access`] | Check if any scope grants access to a resource |
//! | [`is_authorized`] | Check if a single scope grants access |
//! | [`has_subset_scope`] | Check if any scope can delegate a subset scope |
//! | [`is_subset_scope`] | Check if one scope is a subset of another |
//! | [`is_path_match`] | Match resource paths with wildcard support |
//! | [`is_filter_match`] | Match filter dicts with wildcard support |
//! | [`get_scope_filters`] | Extract filters from scopes matching action+resource |
//! | [`broadest_scope_filter`] | Return the least restrictive filter from a list |
//! | [`owner_authorization`] | Owner-level authorization check against user/owner/workspace IDs |
//! | [`get_common_scopes`] | Intersection of two scope lists |
//!
//! # Example
//!
//! ```
//! use usso::authorization::{Action, check_access};
//!
//! let scopes = vec!["admin:users".into(), "read:reports".into()];
//! assert!(check_access(&scopes, "users", Some(Action::Delete), None, false));
//! assert!(!check_access(&scopes, "billing", Some(Action::Read), None, false));
//! ```

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// A known USSO action/privilege level.
///
/// Each variant maps to a numeric level used in the hierarchical RBAC engine:
///
/// | Variant | Level |
/// |---------|-------|
/// | [`None`](Action::None) | 0 |
/// | [`Read`](Action::Read) | 10 |
/// | [`Create`](Action::Create) | 20 |
/// | [`Update`](Action::Update) | 30 |
/// | [`Delete`](Action::Delete) | 40 |
/// | [`Manage`](Action::Manage) | 50 |
/// | [`Admin`](Action::Admin) | 60 |
/// | [`Owner`](Action::Owner) | 90 |
/// | [`Superadmin`](Action::Superadmin) | 100 |
///
/// Convert from a string via [`FromStr`] or use [`Action::level`] to get the numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Read,
    Create,
    Update,
    Delete,
    Manage,
    Admin,
    Owner,
    Superadmin,
}

impl Action {
    /// Return the numeric privilege level for this action.
    pub fn level(self) -> i32 {
        match self {
            Action::None => 0,
            Action::Read => 10,
            Action::Create => 20,
            Action::Update => 30,
            Action::Delete => 40,
            Action::Manage => 50,
            Action::Admin => 60,
            Action::Owner => 90,
            Action::Superadmin => 100,
        }
    }

    /// Return the string representation of this action.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::None => "none",
            Action::Read => "read",
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Manage => "manage",
            Action::Admin => "admin",
            Action::Owner => "owner",
            Action::Superadmin => "superadmin",
        }
    }
}

impl FromStr for Action {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Action::None),
            "read" => Ok(Action::Read),
            "create" => Ok(Action::Create),
            "update" => Ok(Action::Update),
            "delete" => Ok(Action::Delete),
            "manage" => Ok(Action::Manage),
            "admin" => Ok(Action::Admin),
            "owner" | "*" => Ok(Action::Owner),
            "superadmin" => Ok(Action::Superadmin),
            _ => Err(()),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for Action {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn privilege_level(action: &str) -> i32 {
    match action {
        "none" => 0,
        "read" => 10,
        "create" => 20,
        "update" => 30,
        "delete" => 40,
        "manage" => 50,
        "admin" => 60,
        "owner" | "*" => 90,
        "superadmin" => 100,
        _ => 10,
    }
}

/// Parse a scope string into its components.
///
/// Returns `(action, path_segments, filters)`.
///
/// # Examples
///
/// ```
/// use usso::authorization::parse_scope;
///
/// let (action, path, filters) = parse_scope("admin:users/123?region=us-east");
/// assert_eq!(action, "admin");
/// assert_eq!(path, ["users", "123"]);
/// assert_eq!(filters.get("region").unwrap(), "us-east");
/// ```
pub fn parse_scope(scope: &str) -> (String, Vec<String>, HashMap<String, String>) {
    let colon_idx = scope.find(':');
    let question_idx = scope.find('?').unwrap_or(scope.len());

    let (action, resource_path) = if let Some(idx) = colon_idx {
        if idx < question_idx {
            (scope[..idx].to_string(), scope[idx + 1..question_idx].to_string())
        } else {
            (String::new(), scope[..question_idx].to_string())
        }
    } else {
        (String::new(), scope[..question_idx].to_string())
    };

    let filters = if question_idx < scope.len() {
        let query = &scope[question_idx + 1..];
        query.split('&').filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                _ => None,
            }
        }).collect()
    } else {
        HashMap::new()
    };

    let path_parts: Vec<String> = if resource_path.is_empty() {
        vec!["*".to_string()]
    } else {
        resource_path.split('/').map(|p| if p.is_empty() { "*" } else { p }.to_string()).collect()
    };

    (action, path_parts, filters)
}

fn normalize_path(path: &[String]) -> Vec<String> {
    path.to_vec()
}

fn match_path_parts(user_parts: &[String], req_parts: &[String], _strict: bool) -> bool {
    let mut wildcard_found = false;

    if !wildcard_match(&req_parts[req_parts.len() - 1], &user_parts[user_parts.len() - 1]) {
        return false;
    }
    if user_parts[user_parts.len() - 1].contains('*') {
        wildcard_found = true;
    }

    let user_path = &user_parts[..user_parts.len() - 1];
    let req_path = &req_parts[..req_parts.len() - 1];

    for (u, r) in user_path.iter().rev().zip(req_path.iter().rev()) {
        if r != "*" && !wildcard_match(r, u) {
            return false;
        }
        if u.contains('*') {
            wildcard_found = true;
        }
    }

    let offset = user_path.len() as isize - req_path.len() as isize;
    if offset > 0 && wildcard_found {
        for u in &user_path[..offset as usize] {
            if u != "*" {
                return false;
            }
        }
    }
    true
}

fn wildcard_match(text: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return text == pattern;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

/// Check whether a user's path matches a requested resource path.
///
/// Supports wildcard segments (`*`) in either path.
pub fn is_path_match(user_path: &[String], requested_path: &[String], strict: bool) -> bool {
    let user_parts = normalize_path(user_path);
    let req_parts = normalize_path(requested_path);
    match_path_parts(&user_parts, &req_parts, strict)
}

/// Check whether all of a user's filters are satisfied by the requested filters.
///
/// Supports wildcard values (`*`) in user filters.
pub fn is_filter_match(user_filters: &HashMap<String, String>, requested_filters: &HashMap<String, String>) -> bool {
    for (k, v) in user_filters {
        match requested_filters.get(k) {
            Some(rv) => {
                if !wildcard_match(rv, v) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

/// Check whether a single user scope grants access to a specific resource.
///
/// This is the core authorization check. It verifies:
/// - Path match (with wildcard support)
/// - Filter match (with wildcard support)
/// - Action privilege level (hierarchical)
pub fn is_authorized(
    user_scope: &str,
    requested_path: &str,
    requested_action: Option<Action>,
    requested_filter: Option<&HashMap<String, String>>,
    strict: bool,
) -> bool {
    let (user_action, user_path, user_filters) = parse_scope(user_scope);

    if !is_path_match(&user_path, &requested_path.split('/').map(|s| s.to_string()).collect::<Vec<_>>(), strict) {
        return false;
    }

    if let Some(filters) = requested_filter {
        if !is_filter_match(&user_filters, filters) {
            return false;
        }
    }

    if let Some(action) = requested_action {
        let user_level = privilege_level(&user_action);
        let req_level = action.level();
        return user_level >= req_level;
    }

    true
}

/// Check whether ANY of the user's scopes grant access to a resource.
///
/// Returns `true` if at least one scope satisfies the request.
///
/// # Example
///
/// ```
/// use usso::authorization::{check_access, Action};
///
/// let scopes = vec!["read:users".into(), "admin:reports".into()];
/// assert!(check_access(&scopes, "users", Some(Action::Read), None, false));
/// assert!(check_access(&scopes, "reports", Some(Action::Delete), None, false));
/// assert!(!check_access(&scopes, "billing", Some(Action::Read), None, false));
/// ```
pub fn check_access(
    user_scopes: &[String],
    resource_path: &str,
    action: Option<Action>,
    filters: Option<&HashMap<String, String>>,
    strict: bool,
) -> bool {
    for scope in user_scopes {
        if is_authorized(scope, resource_path, action, filters, strict) {
            return true;
        }
    }
    false
}

/// Check whether any user scope contains (is a superset of) the given scope.
///
/// Useful for checking if a user has permission to delegate a scope.
///
/// # Example
///
/// ```
/// use usso::authorization::has_subset_scope;
///
/// let scopes = vec!["admin:*".into()];
/// assert!(has_subset_scope("read:users", &scopes));
/// ```
pub fn has_subset_scope(subset_scope: &str, user_scopes: &[String]) -> bool {
    for user_scope in user_scopes {
        if is_subset_scope(subset_scope, user_scope) {
            return true;
        }
    }
    false
}

/// Return filters extracted from user scopes that match the given action and resource.
///
/// Filters are extracted from scopes whose privilege level >= requested action
/// and whose resource path matches the requested resource.
///
/// # Example
///
/// ```
/// use usso::authorization::{get_scope_filters, Action};
///
/// let scopes = vec!["read:users?tenant_id=t1".into(), "admin:*".into()];
/// let filters = get_scope_filters(Action::Read, "users", &scopes);
/// assert_eq!(filters.len(), 2);
/// ```
pub fn get_scope_filters(action: Action, resource: &str, user_scopes: &[String]) -> Vec<HashMap<String, String>> {
    let action_level = action.level();
    let requested_parts: Vec<String> = resource.split('/').map(|s| s.to_string()).collect();
    let mut matched = Vec::new();
    for scope in user_scopes {
        let (scope_action, scope_path, scope_filters) = parse_scope(scope);
        let scope_level = privilege_level(&scope_action);
        if scope_level < action_level {
            continue;
        }
        if !is_path_match(&scope_path, &requested_parts, false) {
            continue;
        }
        matched.push(scope_filters);
    }
    matched
}

/// Return the broadest (most restrictive) scope filter from a list.
///
/// Scores each filter by its restriction keys:
/// - `tenant_id` = 1, `workspace_id` = 2, `user_id` = 4, `uid` = 8
/// - Unknown keys = 16
/// - Empty filter scores 0 (least restrictive)
///
/// The filter with the **lowest** score is the most restrictive.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use usso::authorization::broadest_scope_filter;
///
/// let filters = vec![
///     HashMap::from([("tenant_id".into(), "t1".into()), ("user_id".into(), "u1".into())]),  // score = 5
///     HashMap::from([("tenant_id".into(), "t1".into())]),                                    // score = 1 (broadest)
/// ];
/// let broadest = broadest_scope_filter(&filters);
/// assert_eq!(broadest.get("tenant_id").unwrap(), "t1");
/// assert!(broadest.get("user_id").is_none());
/// ```
pub fn broadest_scope_filter(filters: &[HashMap<String, String>]) -> HashMap<String, String> {
    fn restriction_score(f: &HashMap<String, String>) -> i32 {
        if f.is_empty() {
            return 0;
        }
        let restriction_bits: [(&str, i32); 4] = [
            ("tenant_id", 1),
            ("workspace_id", 2),
            ("user_id", 4),
            ("uid", 8),
        ];
        let default_bit = 16;
        f.keys().fold(0, |acc, k| {
            acc + restriction_bits
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| *v)
                .unwrap_or(default_bit)
        })
    }

    filters
        .iter()
        .min_by_key(|f| restriction_score(f))
        .cloned()
        .unwrap_or_default()
}

/// Check owner-level authorization for a resource.
///
/// Grants access if the requested resource filter matches the user's ID
/// (or owner_id / workspace_id) and the user's privilege level is sufficient.
///
/// # Example
///
/// ```
/// use std::collections::HashMap;
/// use usso::authorization::{owner_authorization, Action};
///
/// let filter = HashMap::from([("user_id".into(), "u1".into())]);
/// assert!(owner_authorization(Some(&filter), Some("u1"), Some(Action::Owner), Some(Action::Read), None, None));
/// ```
pub fn owner_authorization(
    requested_filter: Option<&HashMap<String, String>>,
    user_id: Option<&str>,
    self_action: Option<Action>,
    action: Option<Action>,
    owner_id: Option<&str>,
    workspace_id: Option<&str>,
) -> bool {
    let uid = owner_id.or(user_id).or(workspace_id);

    if let (Some(uid), Some(filter)) = (uid, requested_filter) {
        let matches = filter.get("owner_id").is_some_and(|v| v == uid)
            || filter.get("user_id").is_some_and(|v| v == uid)
            || filter.get("workspace_id").is_some_and(|v| v == uid);

        if matches {
            let user_level = self_action.unwrap_or(Action::Read).level();
            let req_level = action.unwrap_or(Action::Read).level();
            return user_level >= req_level;
        }
    }
    false
}

/// Get common scopes between two scope lists.
///
/// Removes scopes from `scopes_a` that are not permitted by `scopes_b`,
/// and adds any permitted scopes from `scopes_b` that are subsets of
/// the removed scopes.
///
/// # Example
///
/// ```
/// use usso::authorization::get_common_scopes;
///
/// let a = vec!["admin:users".into(), "read:reports".into()];
/// let b = vec!["read:users".into()];
/// let common = get_common_scopes(&a, &b);
/// assert!(common.contains(&"read:users".to_string()));
/// ```
pub fn get_common_scopes(scopes_a: &[String], scopes_b: &[String]) -> Vec<String> {
    let not_permitted: Vec<String> = scopes_a
        .iter()
        .filter(|scope| !has_subset_scope(scope, scopes_b))
        .cloned()
        .collect();

    if not_permitted.is_empty() {
        return scopes_a.to_vec();
    }

    let new_permitted: Vec<String> = scopes_b
        .iter()
        .filter(|scope| has_subset_scope(scope, &not_permitted))
        .cloned()
        .collect();

    let mut result: Vec<String> = scopes_a
        .iter()
        .filter(|s| !not_permitted.contains(s))
        .cloned()
        .collect();
    result.extend(new_permitted);
    result.sort();
    result.dedup();
    result
}

/// Check whether one scope is a subset of another (i.e. `subset_scope` is
/// implied by `super_scope`).
///
/// A scope A is a subset of scope B if B has equal or higher privilege, the
/// paths match, and B's filters are a superset of A's filters.
pub fn is_subset_scope(subset_scope: &str, super_scope: &str) -> bool {
    let (child_action, child_path, child_filters) = parse_scope(subset_scope);
    let (parent_action, parent_path, parent_filters) = parse_scope(super_scope);

    let child_level = privilege_level(&child_action);
    let parent_level = privilege_level(&parent_action);
    if parent_level < child_level {
        return false;
    }

    let child_path_str = child_path.join("/");
    if !is_path_match(
        &parent_path,
        &child_path_str.split('/').map(|s| s.to_string()).collect::<Vec<_>>(),
        false,
    ) {
        return false;
    }

    for (k, v) in &parent_filters {
        match child_filters.get(k) {
            Some(cv) if cv == v => {}
            _ => return false,
        }
    }
    true
}
