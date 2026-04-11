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
