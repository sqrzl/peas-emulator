use crate::storage::Storage;
use actix_web::{web, HttpResponse};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BucketInfo {
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListBucketsResponse {
    pub buckets: Vec<BucketInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsResponse {
    pub objects: Vec<ObjectInfo>,
    pub prefix: String,
    pub delimiter: Option<String>,
}

/// GET /api/buckets - List all buckets
pub async fn list_buckets(
    storage: web::Data<Arc<dyn Storage>>,
) -> actix_web::Result<HttpResponse> {
    match storage.list_buckets() {
        Ok(buckets) => {
            let bucket_infos = buckets
                .into_iter()
                .map(|bucket| BucketInfo {
                    name: bucket.name,
                    created_at: bucket.created_at.to_rfc3339(),
                })
                .collect();

            Ok(HttpResponse::Ok().json(ListBucketsResponse {
                buckets: bucket_infos,
            }))
        }
        Err(e) => {
            eprintln!("Error listing buckets: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list buckets"
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/objects - List objects in a bucket
pub async fn list_objects(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = bucket_name.into_inner();
    let prefix = query.get("prefix").map(|s| s.as_str());
    let delimiter = query.get("delimiter").map(|s| s.as_str());
    let marker = query.get("marker").map(|s| s.as_str());

    match storage.list_objects(&bucket_name, prefix, delimiter, marker) {
        Ok(objects) => {
            let object_infos = objects
                .into_iter()
                .map(|obj| ObjectInfo {
                    key: obj.key,
                    size: obj.size,
                    last_modified: obj.last_modified.to_rfc3339(),
                    etag: obj.etag,
                })
                .collect();

            Ok(HttpResponse::Ok().json(ListObjectsResponse {
                objects: object_infos,
                prefix: prefix.unwrap_or("").to_string(),
                delimiter: delimiter.map(|s| s.to_string()),
            }))
        }
        Err(e) => {
            eprintln!("Error listing objects: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list objects"
            })))
        }
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/buckets")
            .route("", web::get().to(list_buckets))
            .route("/{bucket-name}/objects", web::get().to(list_objects)),
    );
}
