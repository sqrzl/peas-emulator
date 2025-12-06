use crate::storage::Storage;
use actix_web::{web, App, HttpServer};
use std::sync::Arc;

mod handlers;

pub struct Server {
    storage: Arc<dyn Storage>,
    api_port: u16,
}

impl Server {
    pub fn new(storage: Arc<dyn Storage>, api_port: u16) -> Self {
        Self { storage, api_port }
    }

    pub async fn start(self) -> std::io::Result<()> {
        let storage_api = self.storage.clone();
        let api_port = self.api_port;

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(storage_api.clone()))
                // S3-compatible endpoints (port 9000)
                .route("/", web::get().to(handlers::list_buckets))
                .service(
                    web::scope("")
                        // Bucket operations (with query routing)
                        .route("/{bucket}", web::get().to(handlers::bucket_get_or_list_objects))
                        .route("/{bucket}", web::put().to(handlers::bucket_put))
                        .route("/{bucket}", web::delete().to(handlers::bucket_delete))
                        .route("/{bucket}", web::head().to(handlers::bucket_head))
                        .route("/{bucket}", web::post().to(handlers::bucket_post))
                        // Object operations
                        .route("/{bucket}/{key:.*}", web::put().to(handlers::object_put))
                        .route("/{bucket}/{key:.*}", web::get().to(handlers::object_get))
                        .route("/{bucket}/{key:.*}", web::head().to(handlers::object_head))
                        .route("/{bucket}/{key:.*}", web::delete().to(handlers::object_delete))
                        .route("/{bucket}/{key:.*}", web::post().to(handlers::object_post))
                )
        })
        .bind(("0.0.0.0", api_port))?
        .run()
        .await
    }
}
