use std::collections::HashMap;

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

pub fn is_path_match(user_path: &[String], requested_path: &[String], strict: bool) -> bool {
    let user_parts = normalize_path(user_path);
    let req_parts = normalize_path(requested_path);
    match_path_parts(&user_parts, &req_parts, strict)
}

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

pub fn is_authorized(
    user_scope: &str,
    requested_path: &str,
    requested_action: Option<&str>,
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
        if !action.is_empty() {
            let user_level = privilege_level(&user_action);
            let req_level = privilege_level(action);
            return user_level >= req_level;
        }
    }

    true
}

pub fn check_access(
    user_scopes: &[String],
    resource_path: &str,
    action: Option<&str>,
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

pub fn has_subset_scope(subset_scope: &str, user_scopes: &[String]) -> bool {
    for user_scope in user_scopes {
        if is_subset_scope(subset_scope, user_scope) {
            return true;
        }
    }
    false
}

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
