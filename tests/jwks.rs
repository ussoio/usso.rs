#[cfg(test)]
mod tests {
    use std::env;
    use dotenvy::dotenv;
    use usso::jwks::{init_jwks,get_jwk_keys};
    
    #[test]
    fn fetch_jwks() {
        dotenv().ok();
        let jwk_url = env::var("JWKS_URL").expect("Missing JWKS_URL");
        init_jwks(&jwk_url).expect("Can't init JWKS");
        let jwks=get_jwk_keys().expect("Can't get JWKS");
        assert!(!jwks.keys.is_empty());
        assert!(jwks.keys.len() > 0);
    }
}
