use crate::storage::Storage;
use actix_files as fs;
use actix_web::{web, App, HttpResponse, HttpServer};
use std::sync::Arc;

/// Launches the UI-focused server (port 9001) that exposes the JSON API and optionally serves the web UI.
pub async fn start_ui_server(storage: Arc<dyn Storage>, ui_port: u16) -> std::io::Result<()> {
    let storage_ui = storage.clone();

    let has_static = std::path::Path::new("./static").exists()
        || std::path::Path::new("/app/ui/dist").exists();

    HttpServer::new(move || {
        let app = App::new()
            .app_data(web::Data::new(storage_ui.clone()))
            // UI-friendly JSON API endpoints live on the UI port
            .configure(super::configure);

        if has_static {
            let static_dir = if std::path::Path::new("./static").exists() {
                "./static"
            } else {
                "/app/ui/dist"
            };

            app.service(fs::Files::new("/", static_dir).index_file("index.html"))
        } else {
            app.route("/", web::get().to(|| async {
                HttpResponse::Ok()
                    .content_type("text/html")
                    .body("<html><body><h1>Peas Emulator</h1><p>Running in headless mode</p></body></html>")
            }))
        }
    })
    .bind(("0.0.0.0", ui_port))?
    .run()
    .await
}
