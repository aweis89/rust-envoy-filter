use jwt_simple::algorithms::RSAPublicKeyLike;
use jwt_simple::prelude::{Deserialize, JWTClaims, RS256PublicKey, Serialize, VerificationOptions};
use jwt_simple::Error;
use log::trace;

pub fn parse_multiple<T: for<'de> Deserialize<'de> + Serialize>(
    token: &str,
    secrets: Vec<String>,
) -> Result<JWTClaims<T>, Vec<Error>> {
    let mut errors: Vec<Error> = Vec::new();
    for sec in secrets {
        match parse(token, &sec[..]) {
            Ok(jwt) => return Ok(jwt),
            Err(err) => errors.push(err),
        }
    }
    Err(errors)
}

pub fn parse<T: for<'de> Deserialize<'de> + Serialize>(
    token: &str,
    secret: &str,
) -> Result<JWTClaims<T>, Error> {
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
    use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
    use std::fs;

    fn parse_test(pub_key_path: &str, jwt_path: &str, should_pass: bool) {
        let pub_key = fs::read_to_string(pub_key_path).expect("missing public.pem file");
        let jwt = fs::read_to_string(jwt_path).expect("missing jwt file");
        let result: Result<JWTClaims<NoCustomClaims>, jwt_simple::Error> =
            super::parse(&jwt.trim()[..], &pub_key[..]);
        assert_eq!(result.is_ok(), should_pass);
    }

    #[test]
    fn test_parse() {
        self::parse_test("./tests/invalid/public.pem", "./tests/invalid/jwt", false);
        self::parse_test("./tests/valid/public.pem", "./tests/valid/jwt", true);
    }
}
