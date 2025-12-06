use std::env;
use std::sync::Arc;

use peas_emulator::api::server::start_ui_server;
use peas_emulator::server::Server;
use peas_emulator::storage::FilesystemStorage;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging - use JSON format if LOG_JSON=true
    let use_json = env::var("LOG_JSON").unwrap_or_default() == "true";
    
    if use_json {
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

    // Initialize storage
    let blobs_path = env::var("BLOBS_PATH").unwrap_or_else(|_| "./blobs".to_string());
    println!("Using filesystem storage at: {}", blobs_path);
    let storage = Arc::new(FilesystemStorage::new(&blobs_path));

    // Start lifecycle executor
    let lifecycle_executor = peas_emulator::LifecycleExecutor::new(storage.clone());
    let _lifecycle_handle = lifecycle_executor.start();
    println!("Lifecycle executor started");

    // Start both servers
    println!("S3 API on http://127.0.0.1:9000");
    println!("UI on http://127.0.0.1:9001\n");

    let api_server = Server::new(storage.clone(), 9000).start();
    let ui_server = start_ui_server(storage, 9001);

    // Run both servers concurrently
    tokio::select! {
        result = api_server => result,
        result = ui_server => result,
    }
}
