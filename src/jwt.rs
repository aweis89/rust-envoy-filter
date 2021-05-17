use jsonwebtoken::{decode, errors::Error, DecodingKey, TokenData, Validation};
use log::info;
use serde::{Deserialize, Serialize};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    nbf: usize, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

pub fn parse(token: &str, secret: &str) -> Result<TokenData<Claims>, Error> {
    // `parsed` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
    info!("Raw JWT: {}", token);
    info!("Secret: {}", secret);
    let parsed = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;
    info!("Parsed JWT: {:?}", parsed);
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let claims = super::Claims {};
        match super::run("", "") {
            Ok(token) => asser,
        }
    }
}
