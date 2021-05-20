use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
use log::info;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_yaml;
use std::{str, vec};
use thiserror::Error;
mod jwt;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|c| -> Box<dyn RootContext> {
        Box::new(JwtHandler {
            context_id: c,
            pub_keys: None,
        })
    });
}

#[derive(Serialize, Deserialize, Clone)]
struct JwtHandler {
    context_id: u32,
    pub_keys: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SkillzJwtClaim<'a> {
    sub: &'a str,
    name: &'a str,
    admin: bool,
}

impl RootContext for JwtHandler {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        let config = self
            .get_configuration()
            .expect("unable to retrieve configuration");
        let config = Config::retrieve(config).expect("unable to decode json config");
        self.pub_keys = config.pub_keys;
        return true;
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(JwtHandler {
            pub_keys: self.pub_keys.clone(),
            context_id,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    pub_keys: Option<Vec<String>>,
}

impl Config {
    fn retrieve(yaml: Vec<u8>) -> Result<Config, serde_yaml::Error> {
        let config = String::from_utf8(yaml).expect("config utf8 decoding error");
        let config: Config = serde_yaml::from_str(&config[..])?;
        Ok(config)
    }
}

impl Context for JwtHandler {}
impl HttpContext for JwtHandler {
    fn on_http_request_headers(&mut self, _num_headers: usize) -> Action {
        info!("context_id: {}", self.context_id);
        let keys = self.pub_keys.as_ref().expect("missing public keys");
        for key in keys {
            info!("checking_key {}", key)
        }
        match self.jwt_from_header() {
            Ok(jwt) => {
                info!("got valid jwt");
                let jwt_json = json!(jwt).to_string();
                self.set_http_request_header("jwt-valid", Some("true"));
                self.set_http_request_header("jwt-json", Some(&jwt_json[..]));
            }
            Err(err) => {
                self.send_http_response(
                    400,
                    vec![("invalid", "request")],
                    Some(err.to_string().as_bytes()),
                );
            }
        };
        Action::Continue
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("no auth header")]
    NoAuthHeaderError,
    #[error("invalid auth header")]
    InvalidAuthHeaderError,
    #[error("jwt token not valid")]
    JwtTokenError(Vec<jwt_simple::Error>),
}

const AUTHORIZATION: &str = "Authorization";
const BEARER: &str = "Bearer ";

impl JwtHandler {
    fn jwt_from_header(&self) -> Result<JWTClaims<NoCustomClaims>, Error> {
        let jwt = self.extract_header()?;
        match jwt::parse_multiple(&jwt[..], self.pub_keys.clone().unwrap()) {
            Ok(jwt) => return Ok(jwt),
            Err(err) => return Err(Error::JwtTokenError(err)),
        }
    }

    fn extract_header(&self) -> Result<String, Error> {
        let header = match self.get_http_request_header(AUTHORIZATION) {
            Some(h) => h,
            None => return Err(Error::NoAuthHeaderError),
        };
        let auth_header = match str::from_utf8(header.as_bytes()) {
            Ok(v) => v,
            Err(_) => return Err(Error::NoAuthHeaderError),
        };
        if !auth_header.starts_with(BEARER) {
            return Err(Error::InvalidAuthHeaderError);
        }
        Ok(auth_header.trim_start_matches(BEARER).to_owned())
    }
}
