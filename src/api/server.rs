use crate::error::{Error, Result};
use crate::services::{
    bucket as bucket_service, json_error_response, json_response, object as object_service,
};
use crate::storage::Storage;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tokio::fs as async_fs;
use urlencoding::decode;

/// Launches the UI-focused server (port 9001) that exposes the JSON API and optionally serves the web UI.
pub async fn start_ui_server(storage: Arc<dyn Storage>, ui_port: u16) -> crate::error::Result<()> {
    let addr = ([0, 0, 0, 0], ui_port).into();

    let make_svc = make_service_fn(move |_conn| {
        let storage = storage.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let storage = storage.clone();
                handle_ui_request(storage, req)
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);
    tracing::info!("UI server listening on http://0.0.0.0:{}", ui_port);

    server
        .await
        .map_err(|e| crate::error::Error::InternalError(e.to_string()))
}

async fn handle_ui_request(
    storage: Arc<dyn Storage>,
    req: Request<Body>,
) -> std::result::Result<Response<Body>, Infallible> {
    // Route JSON API requests first (anonymous UI API; no auth)
    if req.uri().path().starts_with("/api/") {
        let resp = match handle_api_request(storage, req).await {
            Ok(resp) => resp,
            Err(err) => json_error_response(&err),
        };
        return Ok(resp);
    }

    let has_static = Path::new("./static").exists() || Path::new("/app/ui/dist").exists();

    if has_static {
        let static_dir = if Path::new("./static").exists() {
            "./static"
        } else {
            "/app/ui/dist"
        };

        // Try to serve index.html
        match async_fs::read(format!("{}/index.html", static_dir)).await {
            Ok(content) => {
                let body = Body::from(content);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(body)
                    .unwrap_or_else(|_| {
                        let mut resp = Response::new(Body::empty());
                        *resp.status_mut() = StatusCode::OK;
                        resp
                    }))
            }
            Err(_) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Static content not found"))
                .unwrap_or_else(|_| {
                    let mut resp = Response::new(Body::from("Static content not found"));
                    *resp.status_mut() = StatusCode::NOT_FOUND;
                    resp
                })),
        }
    } else {
        let default_content =
            "<html><body><h1>Peas Emulator</h1><p>Running in headless mode</p></body></html>";
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(default_content))
            .unwrap_or_else(|_| Response::new(Body::from(default_content))))
    }
}

async fn read_json<T: DeserializeOwned>(req: Request<Body>) -> Result<T> {
    let bytes = to_bytes(req.into_body())
        .await
        .map_err(|e| Error::InvalidRequest(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| Error::InvalidRequest(e.to_string()))
}

fn decode_component(input: &str) -> String {
    decode(input)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| input.to_string())
}

fn object_to_metadata(obj: crate::models::Object) -> crate::api::models::ObjectMetadata {
    crate::api::models::ObjectMetadata {
        key: obj.key,
        size: obj.size,
        last_modified: obj.last_modified.to_rfc3339(),
        etag: obj.etag,
        content_type: Some(obj.content_type),
        metadata: obj.metadata,
        version_id: obj.version_id,
        storage_class: obj.storage_class,
    }
}

fn map_object_list(objects: Vec<crate::models::Object>) -> Vec<crate::api::models::ObjectInfo> {
    objects
        .into_iter()
        .map(|o| crate::api::models::ObjectInfo {
            key: o.key,
            size: o.size,
            last_modified: o.last_modified.to_rfc3339(),
            etag: o.etag,
            content_type: Some(o.content_type),
            storage_class: o.storage_class,
        })
        .collect()
}

fn parse_query_map(query: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            let key = decode_component(k);
            let val = decode_component(v);
            out.insert(key, val);
        }
    }
    out
}

async fn handle_api_request(
    storage: Arc<dyn Storage>,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("");

    // /api/buckets
    if path == "/api/buckets" {
        match method {
            Method::GET => {
                let buckets =
                    tokio::task::block_in_place(|| bucket_service::list_buckets(storage.as_ref()))?;
                let resp = crate::api::models::ListBucketsResponse {
                    buckets: buckets
                        .into_iter()
                        .map(|b| {
                            let versioning_enabled = bucket_service::versioning_enabled(&b);
                            crate::api::models::BucketInfo {
                                name: b.name,
                                created_at: b.created_at.to_rfc3339(),
                                versioning_enabled,
                            }
                        })
                        .collect(),
                };
                return Ok(json_response(StatusCode::OK, &resp));
            }
            Method::POST => {
                #[derive(Deserialize)]
                struct CreateReq {
                    name: String,
                }
                let payload: CreateReq = read_json(req).await?;
                tokio::task::block_in_place(|| {
                    bucket_service::create_bucket(storage.as_ref(), payload.name)
                })?;
                let resp = crate::api::models::SuccessResponse { success: true };
                return Ok(json_response(StatusCode::OK, &resp));
            }
            _ => return Err(Error::InvalidRequest("Unsupported method".into())),
        }
    }

    // /api/buckets/{bucket}
    if let Some(rest) = path.strip_prefix("/api/buckets/") {
        let mut segments = rest.splitn(3, '/');
        let bucket = decode_component(segments.next().unwrap_or(""));
        if bucket.is_empty() {
            return Err(Error::InvalidRequest("Missing bucket".into()));
        }

        match segments.next() {
            None => match method {
                Method::GET => {
                    let bucket = tokio::task::block_in_place(|| {
                        bucket_service::get_bucket(storage.as_ref(), &bucket)
                    })?;
                    let versioning_enabled = bucket_service::versioning_enabled(&bucket);
                    let resp = crate::api::models::BucketDetails {
                        name: bucket.name,
                        created_at: bucket.created_at.to_rfc3339(),
                        versioning_enabled,
                    };
                    return Ok(json_response(StatusCode::OK, &resp));
                }
                Method::DELETE => {
                    tokio::task::block_in_place(|| {
                        bucket_service::delete_bucket(storage.as_ref(), &bucket)
                    })?;
                    return Ok(json_response(
                        StatusCode::OK,
                        &crate::api::models::SuccessResponse { success: true },
                    ));
                }
                _ => return Err(Error::InvalidRequest("Unsupported method".into())),
            },
            Some("versioning") => match method {
                Method::GET => {
                    let bucket = tokio::task::block_in_place(|| {
                        bucket_service::get_bucket(storage.as_ref(), &bucket)
                    })?;
                    let resp = crate::api::models::VersioningStatus {
                        enabled: bucket_service::versioning_enabled(&bucket),
                    };
                    return Ok(json_response(StatusCode::OK, &resp));
                }
                Method::PUT => {
                    #[derive(Deserialize)]
                    struct VersioningReq {
                        enabled: bool,
                    }
                    let body: VersioningReq = read_json(req).await?;
                    tokio::task::block_in_place(|| {
                        bucket_service::set_versioning(storage.as_ref(), &bucket, body.enabled)
                    })?;
                    return Ok(json_response(
                        StatusCode::OK,
                        &crate::api::models::SuccessResponse { success: true },
                    ));
                }
                _ => return Err(Error::InvalidRequest("Unsupported method".into())),
            },
            Some("objects") => {
                let remainder = segments.next().unwrap_or("");

                // List objects
                if remainder.is_empty() {
                    if method != Method::GET {
                        return Err(Error::InvalidRequest("Unsupported method".into()));
                    }

                    let params = parse_query_map(query);
                    let prefix = params.get("prefix").cloned();
                    let delimiter = params.get("delimiter").cloned();
                    let marker = params.get("marker").cloned();
                    let max_keys = params.get("max-keys").and_then(|s| s.parse::<usize>().ok());

                    let list = tokio::task::block_in_place(|| {
                        object_service::list_objects(
                            storage.as_ref(),
                            &bucket,
                            prefix.as_deref(),
                            delimiter.as_deref(),
                            marker.as_deref(),
                            max_keys,
                        )
                    })?;

                    let resp = crate::api::models::ListObjectsResponse {
                        objects: map_object_list(list.objects),
                        prefix: prefix.unwrap_or_default(),
                        delimiter,
                        is_truncated: list.is_truncated,
                        next_marker: list.next_marker,
                    };
                    return Ok(json_response(StatusCode::OK, &resp));
                }

                // Handle object sub-resources
                let mut key_and_action = remainder.splitn(2, '/');
                let key_part = key_and_action.next().unwrap_or("");
                let action = key_and_action.next();
                let key = decode_component(key_part);

                match action {
                    Some("metadata") if method == Method::GET => {
                        let obj = tokio::task::block_in_place(|| {
                            object_service::get_object(storage.as_ref(), &bucket, &key)
                        })?;
                        let resp = object_to_metadata(obj);
                        return Ok(json_response(StatusCode::OK, &resp));
                    }
                    Some("download") if method == Method::GET => {
                        let obj = tokio::task::block_in_place(|| {
                            object_service::get_object(storage.as_ref(), &bucket, &key)
                        })?;
                        let builder = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", obj.content_type);
                        return Ok(builder
                            .body(Body::from(obj.data))
                            .unwrap_or_else(|_| Response::new(Body::empty())));
                    }
                    Some("versions") if method == Method::GET => {
                        let versions = tokio::task::block_in_place(|| {
                            object_service::list_object_versions(
                                storage.as_ref(),
                                &bucket,
                                Some(&key),
                            )
                        })?;
                        let resp = crate::api::models::ListVersionsResponse {
                            versions: versions
                                .into_iter()
                                .map(|v| crate::api::models::ObjectVersionInfo {
                                    key: v.key,
                                    version_id: v.version_id.unwrap_or_default(),
                                    size: v.size,
                                    last_modified: v.last_modified.to_rfc3339(),
                                    etag: v.etag,
                                    is_latest: false,
                                })
                                .collect(),
                        };
                        return Ok(json_response(StatusCode::OK, &resp));
                    }
                    Some("tags") if method == Method::GET => {
                        let tags = tokio::task::block_in_place(|| {
                            object_service::get_object_tags(storage.as_ref(), &bucket, &key)
                        })?;
                        return Ok(json_response(
                            StatusCode::OK,
                            &crate::api::models::TagsResponse { tags },
                        ));
                    }
                    Some("tags") if method == Method::PUT => {
                        #[derive(Deserialize)]
                        struct TagsReq {
                            tags: std::collections::HashMap<String, String>,
                        }
                        let body: TagsReq = read_json(req).await?;
                        tokio::task::block_in_place(|| {
                            object_service::put_object_tags(
                                storage.as_ref(),
                                &bucket,
                                &key,
                                body.tags,
                            )
                        })?;
                        return Ok(json_response(
                            StatusCode::OK,
                            &crate::api::models::SuccessResponse { success: true },
                        ));
                    }
                    None => {
                        match method {
                            Method::POST => {
                                // Upload object; key comes from query param
                                let params = parse_query_map(query);
                                let key_param = params.get("key").cloned();
                                let key_to_use = key_param.unwrap_or_else(|| key.clone());
                                let headers = req.headers().clone();
                                let bytes = to_bytes(req.into_body())
                                    .await
                                    .map_err(|e| Error::InvalidRequest(e.to_string()))?;
                                let content_type = headers
                                    .get("content-type")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("application/octet-stream")
                                    .to_string();

                                // Extract metadata headers
                                let mut metadata = std::collections::HashMap::new();
                                for (name, value) in headers.iter() {
                                    if let Some(stripped) =
                                        name.as_str().strip_prefix("x-amz-meta-")
                                    {
                                        if let Ok(v) = value.to_str() {
                                            metadata.insert(stripped.to_string(), v.to_string());
                                        }
                                    }
                                }

                                let obj = crate::models::Object::new_with_metadata(
                                    key_to_use.clone(),
                                    bytes.to_vec(),
                                    content_type,
                                    metadata,
                                );
                                tokio::task::block_in_place(|| {
                                    object_service::put_object(
                                        storage.as_ref(),
                                        &bucket,
                                        key_to_use.clone(),
                                        obj,
                                    )
                                })?;
                                return Ok(json_response(
                                    StatusCode::OK,
                                    &crate::api::models::SuccessResponse { success: true },
                                ));
                            }
                            Method::DELETE => {
                                tokio::task::block_in_place(|| {
                                    object_service::delete_object(storage.as_ref(), &bucket, &key)
                                })?;
                                return Ok(json_response(
                                    StatusCode::OK,
                                    &crate::api::models::SuccessResponse { success: true },
                                ));
                            }
                            _ => return Err(Error::InvalidRequest("Unsupported method".into())),
                        }
                    }
                    _ => return Err(Error::InvalidRequest("Unsupported object action".into())),
                }
            }
            _ => return Err(Error::InvalidRequest("Unsupported path".into())),
        }
    }

    Err(Error::InvalidRequest("Unsupported path".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{BucketDetails, ObjectMetadata, SuccessResponse};
    use crate::storage::FilesystemStorage;
    use hyper::body::to_bytes;
    use hyper::Request;
    use serde::de::DeserializeOwned;
    use std::fs;
    use std::sync::Arc;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir = std::env::temp_dir().join(format!("peas-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    async fn call(api_req: Request<Body>, storage: Arc<dyn Storage>) -> Response<Body> {
        handle_ui_request(storage, api_req).await.unwrap()
    }

    async fn json_body<T: DeserializeOwned>(resp: Response<Body>) -> T {
        let bytes = to_bytes(resp.into_body())
            .await
            .expect("response body should read");
        serde_json::from_slice(&bytes).expect("response body should deserialize")
    }

    fn assert_json_content_type(resp: &Response<Body>) {
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bucket_crud_json() {
        let storage = temp_storage();

        // Arrange
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/buckets")
            .header("content-type", "application/json")
            .body(Body::from("{\"name\":\"demo\"}"))
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let created: SuccessResponse = json_body(resp).await;
        assert!(created.success);

        // Arrange
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/buckets/demo")
            .body(Body::empty())
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let bucket: BucketDetails = json_body(resp).await;
        assert_eq!(bucket.name, "demo");
        assert!(!bucket.versioning_enabled);

        // Arrange
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/buckets/demo")
            .body(Body::empty())
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let deleted: SuccessResponse = json_body(resp).await;
        assert!(deleted.success);

        // Arrange
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/buckets/demo")
            .body(Body::empty())
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn object_upload_download() {
        let storage = temp_storage();

        // Arrange
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/buckets")
            .header("content-type", "application/json")
            .body(Body::from("{\"name\":\"demo\"}"))
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let created: SuccessResponse = json_body(resp).await;
        assert!(created.success);

        // Arrange
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/buckets/demo/objects/path-placeholder?key=hello.txt")
            .header("content-type", "text/plain")
            .header("x-amz-meta-owner", "alice")
            .header("X-Amz-Meta-Environment", "dev")
            .body(Body::from("hello"))
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let uploaded: SuccessResponse = json_body(resp).await;
        assert!(uploaded.success);

        // Arrange
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/buckets/demo/objects/hello.txt/metadata")
            .body(Body::empty())
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let metadata: ObjectMetadata = json_body(resp).await;
        assert_eq!(metadata.key, "hello.txt");
        assert_eq!(metadata.content_type.as_deref(), Some("text/plain"));
        assert_eq!(metadata.metadata.get("owner"), Some(&"alice".to_string()));
        assert_eq!(
            metadata.metadata.get("environment"),
            Some(&"dev".to_string())
        );

        // Arrange
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/buckets/demo/objects/hello.txt/download")
            .body(Body::empty())
            .unwrap();

        // Act
        let resp = call(req, storage.clone()).await;

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain")
        );
        let bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(&bytes[..], b"hello");
    }
}
