use rocket::Outcome;
use rocket::http::Status;
use rocket::request::{self, Request, FromRequest};
use rocket::http::hyper::header::Basic;
use rocket::http::hyper::Error as HyperError;

use crate::CONFIG;

use std::{
    process::{exit},
};

pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// Returns true if `key` is a valid API key string.
fn is_valid(key: &str) -> Option<BasicAuth> {
    if !key.starts_with("Basic ") {
        return None;
    }
    // Strip off the "Basic: " prefix, to allow hyper parsing.
    let encoded_auth = &key[6..];
    let parsed: std::result::Result<Basic, HyperError> = encoded_auth.parse();
    match parsed {
        Ok(basic) => match basic.password {
            // We only accept username + password, not just username
            Some(password) =>
                Some(BasicAuth{
                    username: basic.username,
                    password: password,
                }),
            None => None,
        },
        Err(error) => {
            error!("{}", error);
            return None
        }
    }
}

#[derive(Debug)]
pub enum BasicAuthError {
    BadCount,
    Missing,
    Invalid,
}

impl<'a, 'r> FromRequest<'a, 'r> for BasicAuth {
    type Error = BasicAuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        match keys.len() {
            0 => Outcome::Failure((Status::Unauthorized, BasicAuthError::Missing)),
            1 => {
                let whatever = is_valid(keys[0]);
                match whatever {
                    Some(basic) => Outcome::Success(basic),
                    None => Outcome::Failure((Status::Unauthorized, BasicAuthError::Invalid)),
                }
            },
            _ => Outcome::Failure((Status::BadRequest, BasicAuthError::BadCount)),
        }
    }
}

pub struct PrometheusUser();

impl<'a, 'r> FromRequest<'a, 'r> for PrometheusUser {
    type Error = BasicAuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        match (CONFIG.metrics_username(), CONFIG.metrics_password()) {
            // Some username and password provided in configuration
            (Some(username), Some(password)) => {
                // Gather username and password from BasicAuth header
                let outcome = BasicAuth::from_request(request);
                match outcome {
                    Outcome::Success(basic) => {
                        // Password login
                        if basic.username == username && basic.password == password {
                            Outcome::Success(PrometheusUser())
                        } else {
                            Outcome::Failure((Status::Unauthorized, BasicAuthError::Invalid))
                        }
                    },
                    // TODO: forward
                    Outcome::Failure((status, error)) => Outcome::Failure((status, error)),
                    Outcome::Forward(args) => Outcome::Forward(args),
                }
            },
            // Passwordless login
            (None,None) => Outcome::Success(PrometheusUser()),
            // Missing username or password, shouldn't happen by invariant
            (_, _) => Outcome::Failure((Status::BadRequest, BasicAuthError::Invalid)),
        }
    }
}
 

#[get("/world")]
fn world(login: BasicAuth) -> std::string::String {
    return "Hello, ".to_owned() + &login.username
}

#[get("/world2")]
fn world2(_login: PrometheusUser) -> &'static str {
    return "Hello, prometheus"
}

// Enable prometheus metrics, if configured to do so.
pub fn metrics(rocket: rocket::Rocket) -> rocket::Rocket {
    if CONFIG.metrics_enable() {
        let metrics_path = &CONFIG.metrics_path();
        if !metrics_path.starts_with('/') {
            error!("Metrics path invalid! Must start with '/'.");
            exit(1);
        }

//        TODO: Check for url conflicts?
//        let path_in_use = rocket.routes().any(|&x| x.uri == metrics_path);
//        if path_in_use {
//            error!("Metrics path conflict! Path already in use.");
//            exit(1);
//        }

        let (error, message) = match (CONFIG.metrics_username(), CONFIG.metrics_password()) {
            (Some(_), Some(_)) => (false, "Using password protected metrics"),
            (Some(_), None) => (true, "Missing metrics password"),
            (None, Some(_)) => (true, "Missing metrics username"),
            (None, None) => (false, "Using passwordless metrics"),
        };
        if error {
            error!("{}", message);
            exit(1);
        } else {
            info!("{}", message);
        }

        use rocket_prometheus::PrometheusMetrics;
        let prometheus = PrometheusMetrics::new();
        return rocket
            .attach(prometheus.clone())
            .mount(metrics_path, prometheus)
            .mount("/hello", routes![world])
            .mount("/hello2", routes![world2]);
    }
    return rocket;
}
