use std::sync::Arc;

use peas_emulator::api::server::start_ui_server;
use peas_emulator::Config;
use peas_emulator::server::Server;
use peas_emulator::storage::FilesystemStorage;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration from environment variables
    let config = Config::from_env();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("peas_emulator=info".parse().unwrap()),
        )
        .init();

    tracing::info!(version = "0.1.0", "Peas Emulator started");
    tracing::info!("S3-compliant emulator with Wasabi API compatibility");

    // Log authentication status
    if config.enforce_auth {
        if let Some(key) = config.access_key() {
            tracing::info!(access_key = key, "Authentication enabled");
        }
    } else {
        tracing::info!("Authentication disabled");
    }

    // Initialize storage
    tracing::info!(path = %config.blobs_path, "Using filesystem storage");
    let storage = Arc::new(FilesystemStorage::new(&config.blobs_path));

    // Start lifecycle executor
    let lifecycle_executor = peas_emulator::LifecycleExecutor::new(storage.clone(), config.lifecycle_interval);
    let _lifecycle_handle = lifecycle_executor.start();
    tracing::info!("Lifecycle executor started");

    // Start both servers
    tracing::info!("S3 API listening on http://127.0.0.1:9000");
    tracing::info!("UI listening on http://127.0.0.1:9001");

    let api_server = Server::new(storage.clone(), Arc::new(config.clone()), 9000).start();
    let ui_server = start_ui_server(storage, 9001);

    // Run both servers concurrently
    tokio::select! {
        result = api_server => result,
        result = ui_server => result,
    }
}
