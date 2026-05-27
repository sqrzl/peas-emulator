use crate::auth::{AdminLoginRequest, AdminSessionManager};
use crate::error::{Error, Result};
use crate::services::{json_error_response, json_response};
use crate::storage::Storage;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use mime_guess::from_path;
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

        return Ok(serve_static_content(Path::new(static_dir), &path).await);
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

    async fn serve_static_content(static_dir: &Path, request_path: &str) -> Response<Body> {
        let normalized_path = request_path.trim_start_matches('/');
        let candidates: Vec<String> = if normalized_path.is_empty() {
            vec!["index.html".to_string()]
        } else if Path::new(normalized_path).extension().is_some() {
            vec![normalized_path.to_string()]
        } else {
            vec![
                format!("{normalized_path}/index.html"),
                "index.html".to_string(),
            ]
        };

        for relative_path in candidates {
            let file_path = static_dir.join(&relative_path);
            if let Ok(content) = async_fs::read(&file_path).await {
                let content_type = if file_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == "index.html")
                {
                    "text/html; charset=utf-8".to_string()
                } else {
                    from_path(&file_path)
                        .first_or_octet_stream()
                        .essence_str()
                        .to_string()
                };

                return Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", content_type)
                    .body(Body::from(content))
                    .unwrap_or_else(|_| Response::new(Body::empty()));
            }
        }

        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from("Static content not found"))
            .unwrap_or_else(|_| Response::new(Body::from("Static content not found")))
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

#[cfg(test)]
mod tests {
    use super::serve_static_content;
    use hyper::body::to_bytes;
    use hyper::StatusCode;
    use std::fs;

    fn temp_static_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("peas-ui-static-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp static dir should be created");
        dir
    }

    #[tokio::test]
    async fn should_serve_static_assets_with_their_real_mime_type() {
        let static_dir = temp_static_dir();
        fs::create_dir_all(static_dir.join("assets")).expect("asset dir should be created");
        fs::write(
            static_dir.join("assets/app.js"),
            "export const app = 'peas';",
        )
        .expect("asset should be written");

        let response = serve_static_content(&static_dir, "/assets/app.js").await;

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type header should exist")
            .to_str()
            .expect("content-type should be valid utf-8");
        assert!(content_type.contains("javascript"), "content-type = {content_type}");

        let body = to_bytes(response.into_body()).await.expect("body should read");
        assert_eq!(body.as_ref(), b"export const app = 'peas';");
    }

    #[tokio::test]
    async fn should_fall_back_to_index_for_spa_routes() {
        let static_dir = temp_static_dir();
        fs::write(static_dir.join("index.html"), "<!doctype html><div id=\"app\"></div>")
            .expect("index should be written");

        let response = serve_static_content(&static_dir, "/dashboard/settings").await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .expect("content-type header should exist")
                .to_str()
                .expect("content-type should be valid utf-8"),
            "text/html; charset=utf-8"
        );

        let body = to_bytes(response.into_body()).await.expect("body should read");
        assert!(String::from_utf8(body.to_vec())
            .expect("body should be utf-8")
            .contains("id=\"app\""));
    }

    #[tokio::test]
    async fn should_return_not_found_for_missing_static_assets() {
        let static_dir = temp_static_dir();
        fs::write(static_dir.join("index.html"), "<!doctype html><div id=\"app\"></div>")
            .expect("index should be written");

        let response = serve_static_content(&static_dir, "/assets/missing.js").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body()).await.expect("body should read");
        assert_eq!(body.as_ref(), b"Static content not found");
    }
}
