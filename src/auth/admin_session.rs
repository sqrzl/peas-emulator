use crate::error::{Error, Result};
use chrono::Utc;
use hyper::{Body, Request};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const ADMIN_LOGIN_PATH: &str = "/admin/v1/auth/login";
pub const ADMIN_LOGOUT_PATH: &str = "/admin/v1/auth/logout";
pub const ADMIN_SESSION_COOKIE_NAME: &str = "peas_admin_session";

const ADMIN_ISSUER: &str = "peas-emulator";
const ADMIN_SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, Deserialize)]
pub struct AdminLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct AdminSessionManager {
    private_key_pem: String,
    public_key_pem: String,
    session_ttl: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSessionClaims {
    sub: String,
    iss: String,
    iat: i64,
    exp: i64,
}

impl AdminSessionManager {
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| {
            Error::InternalError(format!("failed to generate admin signing key: {err}"))
        })?;
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|err| {
                Error::InternalError(format!("failed to encode admin signing key: {err}"))
            })?
            .to_string();
        let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).map_err(|err| {
            Error::InternalError(format!("failed to encode admin verification key: {err}"))
        })?;

        Ok(Self {
            private_key_pem,
            public_key_pem,
            session_ttl: ADMIN_SESSION_TTL,
        })
    }

    pub fn issue_session_cookie(&self, username: &str) -> Result<String> {
        let token = self.issue_token(username)?;
        Ok(format!(
            "{name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            name = ADMIN_SESSION_COOKIE_NAME,
            token = token,
            max_age = self.session_ttl.as_secs(),
        ))
    }

    pub fn clear_session_cookie() -> String {
        format!(
            "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            name = ADMIN_SESSION_COOKIE_NAME
        )
    }

    pub fn has_valid_session(&self, req: &Request<Body>) -> bool {
        req.headers()
            .get("cookie")
            .and_then(|header| header.to_str().ok())
            .and_then(|cookie_header| self.subject_from_cookie_header(cookie_header))
            .is_some()
    }

    pub fn subject_from_cookie_header(&self, cookie_header: &str) -> Option<String> {
        let token = extract_cookie_value(cookie_header, ADMIN_SESSION_COOKIE_NAME)?;
        self.subject_from_token(token)
    }

    fn issue_token(&self, username: &str) -> Result<String> {
        let now = Utc::now().timestamp();
        let claims = AdminSessionClaims {
            sub: username.to_string(),
            iss: ADMIN_ISSUER.to_string(),
            iat: now,
            exp: now + self.session_ttl.as_secs() as i64,
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).map_err(
            |err| Error::InternalError(format!("failed to load admin signing key: {err}")),
        )?;

        encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).map_err(|err| {
            Error::InternalError(format!("failed to sign admin session token: {err}"))
        })
    }

    fn subject_from_token(&self, token: &str) -> Option<String> {
        let validation = Validation::new(Algorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_pem(self.public_key_pem.as_bytes()).ok()?;
        let claims = decode::<AdminSessionClaims>(token, &decoding_key, &validation)
            .ok()?
            .claims;

        if claims.iss != ADMIN_ISSUER {
            return None;
        }

        Some(claims.sub)
    }
}

fn extract_cookie_value<'a>(cookie_header: &'a str, cookie_name: &str) -> Option<&'a str> {
    cookie_header.split(';').map(str::trim).find_map(|cookie| {
        let (name, value) = cookie.split_once('=')?;
        (name == cookie_name).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_issue_and_validate_a_session_cookie() {
        let manager = AdminSessionManager::new().expect("session manager should build");
        let cookie = manager
            .issue_session_cookie("admin")
            .expect("cookie should build");

        assert!(cookie.contains(ADMIN_SESSION_COOKIE_NAME));
        let token = cookie
            .split_once('=')
            .expect("cookie should contain token")
            .1
            .split(';')
            .next()
            .expect("cookie token should exist");

        assert_eq!(manager.subject_from_token(token).as_deref(), Some("admin"));
    }

    #[test]
    fn should_extract_cookie_value_from_cookie_header() {
        let cookie_header = "foo=bar; peas_admin_session=abc.def.ghi; theme=tabby";

        assert_eq!(
            extract_cookie_value(cookie_header, ADMIN_SESSION_COOKIE_NAME),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn should_build_session_clear_cookie_header() {
        let cookie = AdminSessionManager::clear_session_cookie();

        assert!(cookie.contains("peas_admin_session="));
        assert!(cookie.contains("Max-Age=0"));
    }
}