use crate::storage::Storage;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode, Server as HyperServer};
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tokio::fs as async_fs;

/// Launches the UI-focused server (port 9001) that exposes the JSON API and optionally serves the web UI.
pub async fn start_ui_server(storage: Arc<dyn Storage>, ui_port: u16) -> crate::error::Result<()> {
    let addr = ([0, 0, 0, 0], ui_port).into();

    let make_svc = make_service_fn(move |_conn| {
        let storage = storage.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let storage = storage.clone();
                handle_ui_request(storage, req)
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);
    tracing::info!("UI server listening on http://0.0.0.0:{}", ui_port);

    server.await.map_err(|e| crate::error::Error::InternalError(e.to_string()))
}

async fn handle_ui_request(
    _storage: Arc<dyn Storage>,
    _req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
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
        let default_content = "<html><body><h1>Peas Emulator</h1><p>Running in headless mode</p></body></html>";
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(default_content))
            .unwrap_or_else(|_| Response::new(Body::from(default_content))))
    }
}
