use crate::storage::Storage;
use crate::models::Object;
use actix_web::{web, HttpResponse, HttpRequest};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::collections::HashMap;

// ============================================================================
// Request/Response Models
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BucketInfo {
    pub name: String,
    pub created_at: String,
    pub versioning_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub content_type: Option<String>,
    pub storage_class: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObjectVersionInfo {
    pub key: String,
    pub version_id: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub is_latest: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBucketRequest {
    pub name: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectMetadataResponse {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub content_type: Option<String>,
    pub metadata: HashMap<String, String>,
    pub version_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BucketDetailsResponse {
    pub name: String,
    pub created_at: String,
    pub versioning_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersioningRequest {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TagsResponse {
    pub tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TagsRequest {
    pub tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MultipartUploadInfo {
    pub key: String,
    pub upload_id: String,
    pub initiated: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListMultipartResponse {
    pub uploads: Vec<MultipartUploadInfo>,
}

// ============================================================================
// Bucket Operations
// ============================================================================

/// GET /api/buckets - List all buckets
pub async fn list_buckets(
    storage: web::Data<Arc<dyn Storage>>,
) -> actix_web::Result<HttpResponse> {
    match storage.list_buckets() {
        Ok(buckets) => {
            let bucket_infos = buckets
                .into_iter()
                .map(|bucket| BucketInfo {
                    name: bucket.name.clone(),
                    created_at: bucket.created_at.to_rfc3339(),
                    versioning_enabled: bucket.versioning_enabled,
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

/// POST /api/buckets - Create a new bucket
pub async fn create_bucket(
    storage: web::Data<Arc<dyn Storage>>,
    req: web::Json<CreateBucketRequest>,
) -> actix_web::Result<HttpResponse> {
    match storage.create_bucket(req.name.clone()) {
        Ok(_) => Ok(HttpResponse::Created().json(serde_json::json!({
            "success": true,
            "bucket": req.name
        }))),
        Err(e) => {
            eprintln!("Error creating bucket: {:?}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to create bucket: {}", e)
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name} - Get bucket details
pub async fn get_bucket(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    match storage.get_bucket(&bucket_name) {
        Ok(bucket) => Ok(HttpResponse::Ok().json(BucketDetailsResponse {
            name: bucket.name,
            created_at: bucket.created_at.to_rfc3339(),
            versioning_enabled: bucket.versioning_enabled,
        })),
        Err(e) => {
            eprintln!("Error getting bucket: {:?}", e);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Bucket not found"
            })))
        }
    }
}

/// DELETE /api/buckets/{bucket-name} - Delete a bucket
pub async fn delete_bucket(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    match storage.delete_bucket(&bucket_name) {
        Ok(_) => Ok(HttpResponse::NoContent().finish()),
        Err(e) => {
            eprintln!("Error deleting bucket: {:?}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to delete bucket: {}", e)
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/versioning - Get versioning status
pub async fn get_versioning(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    match storage.get_bucket(&bucket_name) {
        Ok(bucket) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "enabled": bucket.versioning_enabled
        }))),
        Err(e) => {
            eprintln!("Error getting versioning: {:?}", e);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Bucket not found"
            })))
        }
    }
}

/// PUT /api/buckets/{bucket-name}/versioning - Enable/disable versioning
pub async fn set_versioning(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
    req: web::Json<VersioningRequest>,
) -> actix_web::Result<HttpResponse> {
    let result = if req.enabled {
        storage.enable_versioning(&bucket_name)
    } else {
        storage.suspend_versioning(&bucket_name)
    };
    
    match result {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "enabled": req.enabled
        }))),
        Err(e) => {
            eprintln!("Error setting versioning: {:?}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to set versioning: {}", e)
            })))
        }
    }
}

// ============================================================================
// Object Operations
// ============================================================================

/// GET /api/buckets/{bucket-name}/objects - List objects in a bucket
pub async fn list_objects(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = bucket_name.into_inner();
    let prefix = query.get("prefix").map(|s| s.as_str());
    let delimiter = query.get("delimiter").map(|s| s.as_str());
    let marker = query.get("marker").map(|s| s.as_str());
    let max_keys = query.get("max-keys")
        .and_then(|s| s.parse::<usize>().ok());

    match storage.list_objects(&bucket_name, prefix, delimiter, marker, max_keys) {
        Ok(result) => {
            let object_infos: Vec<ObjectInfo> = result.objects
                .into_iter()
                .map(|obj| ObjectInfo {
                    key: obj.key,
                    size: obj.size,
                    last_modified: obj.last_modified.to_rfc3339(),
                    etag: obj.etag,
                    content_type: Some(obj.content_type.clone()),
                    storage_class: obj.storage_class,
                })
                .collect();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "objects": object_infos,
                "prefix": prefix.unwrap_or(""),
                "delimiter": delimiter,
                "is_truncated": result.is_truncated,
                "next_marker": result.next_marker,
            })))
        }
        Err(e) => {
            eprintln!("Error listing objects: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list objects"
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/objects/{key:.*} - Get object metadata
pub async fn get_object_metadata(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.get_object(&bucket_name, &key) {
        Ok(obj) => Ok(HttpResponse::Ok().json(ObjectMetadataResponse {
            key: obj.key,
            size: obj.size,
            last_modified: obj.last_modified.to_rfc3339(),
            etag: obj.etag,
            content_type: Some(obj.content_type),
            metadata: obj.metadata,
            version_id: obj.version_id,
        })),
        Err(e) => {
            eprintln!("Error getting object metadata: {:?}", e);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Object not found"
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/objects/{key:.*}/download - Download object data
pub async fn download_object(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.get_object(&bucket_name, &key) {
        Ok(obj) => {
            let content_type = if obj.content_type.is_empty() {
                "application/octet-stream".to_string()
            } else {
                obj.content_type.clone()
            };
            Ok(HttpResponse::Ok()
                .content_type(content_type)
                .insert_header(("ETag", obj.etag))
                .insert_header(("Content-Length", obj.size.to_string()))
                .body(obj.data))
        }
        Err(e) => {
            eprintln!("Error downloading object: {:?}", e);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Object not found"
            })))
        }
    }
}

/// POST /api/buckets/{bucket-name}/objects - Upload an object
pub async fn upload_object(
    storage: web::Data<Arc<dyn Storage>>,
    bucket_name: web::Path<String>,
    req: HttpRequest,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    // Get object key from query parameter
    let query = web::Query::<HashMap<String, String>>::from_query(req.query_string())?;
    let key = match query.get("key") {
        Some(k) => k.clone(),
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Missing 'key' query parameter"
            })));
        }
    };

    // Get content type from header or default
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract metadata headers (x-amz-meta-*)
    let mut metadata = HashMap::new();
    for (name, value) in req.headers() {
        if let Some(meta_key) = name.as_str().strip_prefix("x-amz-meta-") {
            if let Ok(meta_value) = value.to_str() {
                metadata.insert(meta_key.to_string(), meta_value.to_string());
            }
        }
    }

    let object = Object {
        key: key.clone(),
        data: body.to_vec(),
        size: body.len() as u64,
        etag: format!("{:x}", md5::compute(&body)),
        last_modified: chrono::Utc::now(),
        content_type: content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
        metadata,
        version_id: None,
        storage_class: "STANDARD".to_string(),
        tags: HashMap::new(),
        acl: None,
    };

    match storage.put_object(&bucket_name, key.clone(), object) {
        Ok(_) => Ok(HttpResponse::Created().json(serde_json::json!({
            "success": true,
            "key": key
        }))),
        Err(e) => {
            eprintln!("Error uploading object: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to upload object: {}", e)
            })))
        }
    }
}

/// DELETE /api/buckets/{bucket-name}/objects/{key:.*} - Delete an object
pub async fn delete_object(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.delete_object(&bucket_name, &key) {
        Ok(_) => Ok(HttpResponse::NoContent().finish()),
        Err(e) => {
            eprintln!("Error deleting object: {:?}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to delete object: {}", e)
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/objects/{key:.*}/versions - List object versions
pub async fn list_object_versions(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.list_object_versions(&bucket_name, Some(&key)) {
        Ok(versions) => {
            let version_infos: Vec<ObjectVersionInfo> = versions
                .into_iter()
                .filter(|v| v.key == key)
                .map(|v| ObjectVersionInfo {
                    key: v.key,
                    version_id: v.version_id.unwrap_or_else(|| "null".to_string()),
                    size: v.size,
                    last_modified: v.last_modified.to_rfc3339(),
                    etag: v.etag,
                    is_latest: true, // TODO: determine if it's actually the latest
                })
                .collect();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "versions": version_infos
            })))
        }
        Err(e) => {
            eprintln!("Error listing versions: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list versions"
            })))
        }
    }
}

/// GET /api/buckets/{bucket-name}/objects/{key:.*}/tags - Get object tags
pub async fn get_object_tags(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.get_object_tags(&bucket_name, &key) {
        Ok(tags) => Ok(HttpResponse::Ok().json(TagsResponse { tags })),
        Err(e) => {
            eprintln!("Error getting tags: {:?}", e);
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Object not found"
            })))
        }
    }
}

/// PUT /api/buckets/{bucket-name}/objects/{key:.*}/tags - Set object tags
pub async fn put_object_tags(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
    req: web::Json<TagsRequest>,
) -> actix_web::Result<HttpResponse> {
    let (bucket_name, key) = path.into_inner();
    
    match storage.put_object_tags(&bucket_name, &key, req.tags.clone()) {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true
        }))),
        Err(e) => {
            eprintln!("Error setting tags: {:?}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to set tags: {}", e)
            })))
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/buckets")
            // Bucket operations
            .route("", web::get().to(list_buckets))
            .route("", web::post().to(create_bucket))
            .route("/{bucket-name}", web::get().to(get_bucket))
            .route("/{bucket-name}", web::delete().to(delete_bucket))
            
            // Versioning
            .route("/{bucket-name}/versioning", web::get().to(get_versioning))
            .route("/{bucket-name}/versioning", web::put().to(set_versioning))
            
            // Object listing
            .route("/{bucket-name}/objects", web::get().to(list_objects))
            .route("/{bucket-name}/objects", web::post().to(upload_object))
            
            // Object operations (must be after /objects route)
            .route("/{bucket-name}/objects/{key:.*}/metadata", web::get().to(get_object_metadata))
            .route("/{bucket-name}/objects/{key:.*}/download", web::get().to(download_object))
            .route("/{bucket-name}/objects/{key:.*}/versions", web::get().to(list_object_versions))
            .route("/{bucket-name}/objects/{key:.*}/tags", web::get().to(get_object_tags))
            .route("/{bucket-name}/objects/{key:.*}/tags", web::put().to(put_object_tags))
            .route("/{bucket-name}/objects/{key:.*}", web::delete().to(delete_object)),
    );
}
