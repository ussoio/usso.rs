#[cfg(test)]
mod tests {
    use dotenvy::dotenv;
    use std::env;
    use usso::jwks::{get_jwk_keys, init_jwks_sync};

    #[test]
    fn fetch_jwks() {
        dotenv().ok();
        let jwk_url = env::var("JWKS_URL").expect("Missing JWKS_URL");
        init_jwks_sync(&jwk_url).expect("Can't init JWKS");
        let jwks = get_jwk_keys().expect("Can't get JWKS");
        assert!(!jwks.keys.is_empty());
        assert!(jwks.keys.len() > 0);
    }
}
