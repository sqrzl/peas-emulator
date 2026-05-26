use crate::auth::{AdminLoginRequest, AdminSessionManager};
use crate::error::{Error, Result};
use crate::services::{json_error_response, json_response};
use crate::storage::Storage;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tokio::fs as async_fs;

/// Launches the UI-focused server (port 9001) that exposes the JSON API and optionally serves the web UI.
pub async fn start_ui_server(
    storage: Arc<dyn Storage>,
    config: Arc<crate::Config>,
) -> crate::error::Result<()> {
    let ui_port = config.ui_port;
    let addr = ([0, 0, 0, 0], ui_port).into();
    let admin_session = Arc::new(AdminSessionManager::new()?);

    let make_svc = make_service_fn(move |_conn| {
        let storage = storage.clone();
        let config = config.clone();
        let admin_session = admin_session.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let storage = storage.clone();
                let config = config.clone();
                let admin_session = admin_session.clone();
                handle_ui_request(storage, config, admin_session, req)
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);
    tracing::info!("UI server listening on http://0.0.0.0:{}", ui_port);

    server
        .await
        .map_err(|e| crate::error::Error::InternalError(e.to_string()))
}

async fn handle_ui_request(
    storage: Arc<dyn Storage>,
    config: Arc<crate::Config>,
    admin_session: Arc<AdminSessionManager>,
    req: Request<Body>,
) -> std::result::Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();

    if path == crate::auth::admin_session::ADMIN_LOGIN_PATH {
        let resp = handle_admin_login(config, admin_session, req).await;
        return Ok(resp);
    }

    if path == crate::auth::admin_session::ADMIN_LOGOUT_PATH {
        let resp = handle_admin_logout(req);
        return Ok(resp);
    }

    if path == crate::auth::admin_session::ADMIN_SESSION_PATH {
        let resp = handle_admin_session(config, admin_session, req);
        return Ok(resp);
    }

    if path == "/admin/v1" || path.starts_with("/admin/v1/") {
        if !admin_request_is_authorized(&req, &config, &admin_session) {
            return Ok(admin_unauthorized_response());
        }

        let resp = match crate::api::admin::handle_request(storage, req).await {
            Ok(resp) => resp,
            Err(err) => crate::api::admin::error_response(&err),
        };
        return Ok(resp);
    }

    if path.starts_with("/api/") {
        return Ok(json_error_response(&Error::RouteNotFound(path)));
    }

    let has_static = Path::new("./static").exists() || Path::new("/app/ui/dist").exists();

    if has_static {
        let static_dir = if Path::new("./static").exists() {
            "./static"
        } else {
            "/app/ui/dist"
        };

        // Try to serve index.html
        match async_fs::read(format!("{}/index.html", static_dir)).await {
            Ok(content) => {
                let body = Body::from(content);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(body)
                    .unwrap_or_else(|_| {
                        let mut resp = Response::new(Body::empty());
                        *resp.status_mut() = StatusCode::OK;
                        resp
                    }))
            }
            Err(_) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Static content not found"))
                .unwrap_or_else(|_| {
                    let mut resp = Response::new(Body::from("Static content not found"));
                    *resp.status_mut() = StatusCode::NOT_FOUND;
                    resp
                })),
        }
    } else {
        let default_content =
            "<html><body><h1>Peas Emulator</h1><p>Running in headless mode</p></body></html>";
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(default_content))
            .unwrap_or_else(|_| Response::new(Body::from(default_content))))
    }
}

async fn handle_admin_login(
    config: Arc<crate::Config>,
    admin_session: Arc<AdminSessionManager>,
    req: Request<Body>,
) -> Response<Body> {
    if req.method() != Method::POST {
        return json_error_response(&Error::MethodNotAllowed(format!(
            "{} {}",
            req.method(),
            crate::auth::admin_session::ADMIN_LOGIN_PATH
        )));
    }

    let login_request: AdminLoginRequest = match read_json(req).await {
        Ok(request) => request,
        Err(err) => return json_error_response(&err),
    };

    if !config.validate_credentials(&login_request.username, &login_request.password) {
        return admin_login_unauthorized_response();
    }

    let cookie = match admin_session.issue_session_cookie(&login_request.username) {
        Ok(cookie) => cookie,
        Err(err) => return json_error_response(&err),
    };

    let mut response = json_response(
        StatusCode::OK,
        &crate::api::models::SuccessResponse { success: true },
    );

    match hyper::header::HeaderValue::from_str(&cookie) {
        Ok(header_value) => {
            response.headers_mut().insert("set-cookie", header_value);
            response.headers_mut().insert(
                "cache-control",
                hyper::header::HeaderValue::from_static("no-store"),
            );
            response
        }
        Err(err) => json_error_response(&Error::InternalError(format!(
            "failed to encode admin session cookie: {err}"
        ))),
    }
}

fn handle_admin_logout(req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST {
        return json_error_response(&Error::MethodNotAllowed(format!(
            "{} {}",
            req.method(),
            crate::auth::admin_session::ADMIN_LOGOUT_PATH
        )));
    }

    let mut response = json_response(
        StatusCode::OK,
        &crate::api::models::SuccessResponse { success: true },
    );
    response.headers_mut().insert(
        "set-cookie",
        hyper::header::HeaderValue::from_static(
            "peas_admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        ),
    );
    response.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn handle_admin_session(
    config: Arc<crate::Config>,
    admin_session: Arc<AdminSessionManager>,
    req: Request<Body>,
) -> Response<Body> {
    if req.method() != Method::GET {
        return json_error_response(&Error::MethodNotAllowed(format!(
            "{} {}",
            req.method(),
            crate::auth::admin_session::ADMIN_SESSION_PATH
        )));
    }

    let (mode, username) = if !config.admin_auth_enforced() {
        ("open", None)
    } else if let Some(username) = admin_session.subject_from_request(&req) {
        ("session", Some(username))
    } else if let Some(username) = admin_basic_auth_subject(&req, &config) {
        ("basic", Some(username))
    } else {
        return admin_unauthorized_response();
    };

    json_response(
        StatusCode::OK,
        &crate::api::models::AdminSessionResponse {
            mode: mode.to_string(),
            username,
        },
    )
}

fn admin_request_is_authorized(
    req: &Request<Body>,
    config: &crate::Config,
    admin_session: &AdminSessionManager,
) -> bool {
    if !config.admin_auth_enforced() {
        return true;
    }

    if admin_session.has_valid_session(req) {
        return true;
    }

    admin_basic_auth_subject(req, config).is_some()
}

fn admin_basic_auth_subject(req: &Request<Body>, config: &crate::Config) -> Option<String> {
    let auth_header = req.headers().get("authorization")?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (provided_key, provided_secret) = decoded.split_once(':')?;

    config
        .validate_credentials(provided_key, provided_secret)
        .then(|| provided_key.to_string())
}

fn admin_unauthorized_response() -> Response<Body> {
    let body = crate::api::models::ErrorResponse {
        error: "Unauthorized".to_string(),
        code: "Unauthorized".to_string(),
        details: Some(
            "Provide a valid admin session cookie or Basic auth with ACCESS_KEY_ID and SECRET_ACCESS_KEY"
                .to_string(),
        ),
    };
    let mut response = json_response(StatusCode::UNAUTHORIZED, &body);
    response.headers_mut().insert(
        "www-authenticate",
        hyper::header::HeaderValue::from_static("Basic realm=\"Peas Admin\""),
    );
    response
}

fn admin_login_unauthorized_response() -> Response<Body> {
    let body = crate::api::models::ErrorResponse {
        error: "Unauthorized".to_string(),
        code: "Unauthorized".to_string(),
        details: Some("Invalid admin credentials".to_string()),
    };

    json_response(StatusCode::UNAUTHORIZED, &body)
}

async fn read_json<T: DeserializeOwned>(req: Request<Body>) -> Result<T> {
    let bytes = to_bytes(req.into_body())
        .await
        .map_err(|e| Error::InvalidRequest(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| Error::InvalidRequest(e.to_string()))
}
