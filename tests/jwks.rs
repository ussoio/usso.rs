#[cfg(test)]
mod tests {
    use usso::jwks::{get_jwk_keys, init_jwks_sync};

    fn mock_jwks_json() -> &'static str {
        r#"{
            "keys": [
                {
                    "kid": "test-key-1",
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "uTQ0RdJdPClWD4lw8rFmRKG6UhsJwqYq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8rq7q8",
                    "e": "AQAB"
                }
            ]
        }"#
    }

    #[test]
    fn fetch_jwks() {
        let mut server = mockito::Server::new();
        let url = server.url();

        let mock = server
            .mock("GET", "/website/jwks.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_jwks_json())
            .create();

        let jwk_url = format!("{}/website/jwks.json", url);
        init_jwks_sync(&jwk_url).expect("Can't init JWKS");
        let jwks = get_jwk_keys().expect("Can't get JWKS");
        assert!(!jwks.keys.is_empty());
        assert!(jwks.keys.len() > 0);
        assert_eq!(jwks.keys[0].kid, "test-key-1");

        mock.assert();
    }

    #[test]
    fn fetch_jwks_http_error() {
        let mut server = mockito::Server::new();
        let url = server.url();

        let mock = server
            .mock("GET", "/website/jwks.json")
            .with_status(521)
            .create();

        let jwk_url = format!("{}/website/jwks.json", url);
        let result = init_jwks_sync(&jwk_url);
        assert!(result.is_err());

        mock.assert();
    }
}
