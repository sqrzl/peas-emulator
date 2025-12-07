use std::sync::Arc;

use peas_emulator::api::server::start_ui_server;
use peas_emulator::Config;
use peas_emulator::server::Server;
use peas_emulator::storage::FilesystemStorage;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load configuration from environment variables
    let config = Config::from_env();

    // Initialize logging - use JSON format if LOG_JSON=true
    if config.log_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("peas_emulator=info".parse().unwrap()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("peas_emulator=info".parse().unwrap()),
            )
            .init();
    }

    println!("Peas Emulator v0.1.0");
    println!("S3-compliant emulator with Wasabi API compatibility\n");

    // Log authentication status
    if config.enforce_auth {
        if let Some(key) = config.access_key() {
            println!("Authentication enabled with access key: {}", key);
        }
    } else {
        println!("Authentication disabled. Set PEAS_ACCESS_KEY_ID and PEAS_SECRET_ACCESS_KEY to enable");
    }

    // Initialize storage
    println!("Using filesystem storage at: {}", config.blobs_path);
    let storage = Arc::new(FilesystemStorage::new(&config.blobs_path));

    // Start lifecycle executor
    let lifecycle_executor = peas_emulator::LifecycleExecutor::new(storage.clone(), config.lifecycle_interval);
    let _lifecycle_handle = lifecycle_executor.start();
    println!("Lifecycle executor started");

    // Start both servers
    println!("S3 API on http://127.0.0.1:9000");
    println!("UI on http://127.0.0.1:9001\n");

    let api_server = Server::new(storage.clone(), Arc::new(config.clone()), 9000).start();
    let ui_server = start_ui_server(storage, 9001);

    // Run both servers concurrently
    tokio::select! {
        result = api_server => result,
        result = ui_server => result,
    }
}
