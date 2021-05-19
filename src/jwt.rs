use jwt_simple::algorithms::RSAPublicKeyLike;
use jwt_simple::prelude::{JWTClaims, NoCustomClaims, RS256PublicKey, VerificationOptions};
use jwt_simple::Error;
use log::trace;

pub fn parse_multiple(
    token: &str,
    secrets: Vec<String>,
) -> Result<JWTClaims<NoCustomClaims>, Vec<Error>> {
    let mut errors: Vec<Error> = Vec::new();
    for sec in secrets {
        match parse(token, &sec[..]) {
            Ok(jwt) => return Ok(jwt),
            Err(err) => errors.push(err),
        }
    }
    Err(errors)
}

pub fn parse(token: &str, secret: &str) -> Result<JWTClaims<NoCustomClaims>, Error> {
    trace!("Raw JWT: {}", token);
    trace!("Secret: {}", secret);

    let pub_key = RS256PublicKey::from_pem(secret)?;
    let verification = VerificationOptions {
        required_public_key: Some(String::from(secret)),
        required_subject: None,
        required_key_id: None,
        required_nonce: None,
        allowed_issuers: None,
        allowed_audiences: None,
        reject_before: None,
        time_tolerance: None,
        max_validity: None,
        accept_future: true,
    };
    pub_key.verify_token(token, Some(verification))
}

#[cfg(test)]
mod tests {
    fn parse_test(pub_key_path: &str, jwt_path: &str, should_pass: bool) {
        let pub_key = std::fs::read_to_string(pub_key_path).expect("missing public.pem file");
        let jwt = std::fs::read_to_string(jwt_path).expect("missing jwt file");
        let result = super::parse(&jwt.trim()[..], &pub_key[..]);
        assert_eq!(result.is_ok(), should_pass);
    }

    #[test]
    fn test_cases() {
        self::parse_test("./tests/invalid/public.pem", "./tests/invalid/jwt", false);
        self::parse_test("./tests/valid/public.pem", "./tests/valid/jwt", true);
    }
}
