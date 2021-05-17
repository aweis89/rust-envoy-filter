use log::info;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, LogLevel};
mod jwt;

const CONFIG: Config = Config { secret: None };

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(CONFIG) });
    proxy_wasm::set_http_context(|context_id, _root_context_id| -> Box<dyn HttpContext> {
        Box::new(JwtHandler { context_id })
    })
}

struct Config {
    secret: Option<String>,
}

impl Context for Config {}

impl RootContext for Config {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        match self.get_configuration() {
            Some(conf) => {
                let conf_str = std::str::from_utf8(&conf).expect("couldn't convert to utf8");
                println!("Got config: {}", conf_str);
                self.secret = Some(conf_str.to_string())
            }
            None => {
                println!("Missing config");
                return false;
            }
        }
        true
    }
}

struct JwtHandler {
    context_id: u32,
}

impl Context for JwtHandler {}

impl HttpContext for JwtHandler {
    fn on_http_request_headers(&mut self, num_headers: usize) -> Action {
        match jwt::parse("", "") {
            Ok(jwt) => {
                info!("got valid jwt: {:?}", jwt);
                info!("AUD {}", jwt.claims.aud);
                self.set_http_request_header("valid-jwt", Some("valid"))
            }
            Err(err) => {
                info!("unable to validate jwt: {}", err);
                self.send_http_response(400, vec![("invalid", "request")], Some(b"Unauthorized"));
            }
        }

        info!("Got {} HTTP headers in #{}.", num_headers, self.context_id);
        let headers = self.get_http_request_headers();
        let mut authority = "";

        for (name, value) in &headers {
            if name == ":authority" {
                authority = value;
            }
        }

        self.set_http_request_header("x-hello", Some(&format!("Hello world from {}", authority)));

        Action::Continue
    }
}
