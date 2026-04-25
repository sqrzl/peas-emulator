#![allow(dead_code)]

use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request, Response};
use peas_emulator::server::Server;
use peas_emulator::storage::{FilesystemStorage, Storage};
use peas_emulator::Config;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration, Instant};

pub const AZURE_VERSION: &str = "2023-11-03";

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("port reservation should bind");
    let port = listener
        .local_addr()
        .expect("listener should have local addr")
        .port();
    drop(listener);
    port
}

fn temp_storage_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    let _ = fs::create_dir_all(&dir);
    dir
}

pub struct LiveServer {
    pub base_url: String,
    pub client: Client<HttpConnector, Body>,
    task: JoinHandle<peas_emulator::Result<()>>,
    storage_dir: PathBuf,
}

impl LiveServer {
    pub async fn start_api(auth_config: Config) -> Self {
        let api_port = reserve_port();
        let storage_dir = temp_storage_dir("peas-e2e-s3");
        let storage: Arc<dyn Storage> = Arc::new(FilesystemStorage::new(&storage_dir));
        let config = Arc::new(Config {
            api_port,
            ui_port: reserve_port(),
            blobs_path: storage_dir.to_string_lossy().to_string(),
            ..auth_config
        });

        let task = tokio::spawn(Server::new(storage, config, api_port).start());
        let server = Self {
            base_url: format!("http://127.0.0.1:{api_port}"),
            client: Client::new(),
            task,
            storage_dir,
        };
        server.wait_until_ready().await;
        server
    }

    pub async fn start_s3(auth_config: Config) -> Self {
        Self::start_api(auth_config).await
    }

    async fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.task.is_finished() {
                panic!("server task exited before becoming ready");
            }

            let request = Request::builder()
                .method("GET")
                .uri(format!("{}/?list-type=2", self.base_url))
                .body(Body::empty())
                .expect("readiness request should build");

            match self.client.request(request).await {
                Ok(_) => return,
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }

        panic!("server did not become ready before timeout");
    }

    pub async fn request(&self, request: Request<Body>) -> Response<Body> {
        self.client
            .request(request)
            .await
            .expect("live request should complete")
    }
}

impl Drop for LiveServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_dir_all(&self.storage_dir);
    }
}

pub fn auth_disabled() -> Config {
    Config {
        access_key_id: None,
        secret_access_key: None,
        enforce_auth: false,
        blobs_path: "./blobs".to_string(),
        lifecycle_interval: Duration::from_secs(3600),
        api_port: 9000,
        ui_port: 9001,
    }
}

pub fn auth_enabled(key: &str, secret: &str) -> Config {
    Config {
        access_key_id: Some(key.to_string()),
        secret_access_key: Some(secret.to_string()),
        enforce_auth: true,
        blobs_path: "./blobs".to_string(),
        lifecycle_interval: Duration::from_secs(3600),
        api_port: 9000,
        ui_port: 9001,
    }
}

pub async fn text_body(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body())
        .await
        .expect("response body should read");
    String::from_utf8(bytes.to_vec()).expect("response body should be utf8")
}

pub fn rebase_url(base_url: &str, upstream_location: &str) -> String {
    let uri: hyper::Uri = upstream_location
        .parse()
        .expect("upstream location should parse");
    let path_and_query = uri
        .path_and_query()
        .expect("upstream location should include path and query")
        .as_str();
    format!("{base_url}{path_and_query}")
}