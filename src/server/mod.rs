use crate::auth::AuthConfig;
use crate::providers::AdapterRegistry;
use crate::storage::Storage;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server as HyperServer, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tracing::error;

mod handlers;
mod http;

pub use http::{Request as RequestExt, ResponseBuilder, RouteMatch, Router};
pub(crate) use handlers::handle_request as handle_s3_request;

pub struct Server {
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    adapters: Arc<AdapterRegistry>,
    api_port: u16,
}

impl Server {
    pub fn new(storage: Arc<dyn Storage>, auth_config: Arc<AuthConfig>, api_port: u16) -> Self {
        Self {
            storage,
            auth_config,
            adapters: Arc::new(AdapterRegistry::default()),
            api_port,
        }
    }

    pub async fn start(self) -> crate::error::Result<()> {
        let storage = self.storage.clone();
        let auth_config = self.auth_config.clone();
        let adapters = self.adapters.clone();
        let api_port = self.api_port;

        let addr = ([0, 0, 0, 0], api_port).into();

        let make_svc = make_service_fn(move |_conn| {
            let storage = storage.clone();
            let auth_config = auth_config.clone();
            let adapters = adapters.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let storage = storage.clone();
                    let auth_config = auth_config.clone();
                    let adapters = adapters.clone();
                    handle_request(storage, auth_config, adapters, req)
                }))
            }
        });

        let server = HyperServer::bind(&addr).serve(make_svc);
        tracing::info!("S3 API listening on http://0.0.0.0:{}", api_port);

        server
            .await
            .map_err(|e| crate::error::Error::InternalError(e.to_string()))?;
        Ok(())
    }
}

async fn handle_request(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    adapters: Arc<AdapterRegistry>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    match http::Request::from_hyper(req).await {
        Ok(parsed_req) => match adapters
            .handle(storage, auth_config, parsed_req)
            .await
        {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Handler error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal Server Error"))
                    .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error"))))
            }
        },
        Err(e) => {
            error!("Failed to parse request: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Bad Request"))
                .unwrap_or_else(|_| Response::new(Body::from("Bad Request"))))
        }
    }
}

#[cfg(test)]
mod adapter_routing_tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::FilesystemStorage;
    use hyper::body::to_bytes;
    use hyper::Request as HyperRequest;
    use std::fs;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir = std::env::temp_dir().join(format!("peas-routing-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    fn auth_disabled() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: std::time::Duration::from_secs(3600),
            api_port: 9000,
            ui_port: 9001,
        })
    }

    async fn call(
        storage: Arc<dyn Storage>,
        req: HyperRequest<Body>,
    ) -> Response<Body> {
        handle_request(
            storage,
            auth_disabled(),
            Arc::new(AdapterRegistry::default()),
            req,
        )
        .await
        .expect("request should complete")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_route_azure_requests_through_azure_adapter() {
        let storage = temp_storage();

        let create = HyperRequest::builder()
            .method("PUT")
            .uri("http://localhost/devstoreaccount1/photos?restype=container")
            .header("x-ms-version", "2023-11-03")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage.clone(), create).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let list = HyperRequest::builder()
            .method("GET")
            .uri("http://localhost/devstoreaccount1?comp=list")
            .header("x-ms-version", "2023-11-03")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage, list).await;
        let body = to_bytes(resp.into_body()).await.expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("utf8").contains("photos"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_route_gcs_requests_through_gcs_adapter() {
        let storage = temp_storage();

        let create = HyperRequest::builder()
            .method("PUT")
            .uri("http://localhost/media")
            .header("host", "storage.googleapis.com")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage.clone(), create).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let get = HyperRequest::builder()
            .method("GET")
            .uri("http://localhost/")
            .header("host", "storage.googleapis.com")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage, get).await;
        let body = to_bytes(resp.into_body()).await.expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("utf8").contains("media"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_route_oci_requests_through_oci_adapter() {
        let storage = temp_storage();

        let req = HyperRequest::builder()
            .method("GET")
            .uri("http://localhost/n/testnamespace")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage, req).await;
        let body = to_bytes(resp.into_body()).await.expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("utf8").contains("testnamespace"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_fall_back_to_s3_adapter_for_plain_requests() {
        let storage = temp_storage();

        let create = HyperRequest::builder()
            .method("PUT")
            .uri("http://localhost/plain-bucket")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage.clone(), create).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let list = HyperRequest::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Body::empty())
            .expect("request should build");
        let resp = call(storage, list).await;
        let body = to_bytes(resp.into_body()).await.expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("utf8").contains("plain-bucket"));
    }
}
