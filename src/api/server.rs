use crate::error::{Error, Result};
use crate::services::{
    bucket as bucket_service, json_error_response, json_response, object as object_service,
};
use crate::storage::Storage;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tokio::fs as async_fs;
use urlencoding::decode;

/// Launches the UI-focused server (port 9001) that exposes the JSON API and optionally serves the web UI.
pub async fn start_ui_server(
    storage: Arc<dyn Storage>,
    config: Arc<crate::Config>,
) -> crate::error::Result<()> {
    let ui_port = config.ui_port;
    let addr = ([0, 0, 0, 0], ui_port).into();

    let make_svc = make_service_fn(move |_conn| {
        let storage = storage.clone();
        let config = config.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let storage = storage.clone();
                let config = config.clone();
                handle_ui_request(storage, config, req)
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
    config: Arc<crate::Config>,
    req: Request<Body>,
) -> std::result::Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();

    if path == "/admin/v1" || path.starts_with("/admin/v1/") {
        if !admin_request_is_authorized(&req, &config) {
            return Ok(admin_unauthorized_response());
        }

        let resp = match crate::api::admin::handle_request(storage, req).await {
            Ok(resp) => resp,
            Err(err) => crate::api::admin::error_response(&err),
        };
        return Ok(resp);
    }

    // Keep the pre-existing JSON API surface for the current UI until it is migrated.
    if path.starts_with("/api/") {
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

fn admin_request_is_authorized(req: &Request<Body>, config: &crate::Config) -> bool {
    if !config.admin_auth_enforced() {
        return true;
    }

    let Some(auth_header) = req.headers().get("authorization") else {
        return false;
    };
    let Ok(auth_header) = auth_header.to_str() else {
        return false;
    };
    let Some(encoded) = auth_header.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((provided_key, provided_secret)) = decoded.split_once(':') else {
        return false;
    };

    config.validate_credentials(provided_key, provided_secret)
}

fn admin_unauthorized_response() -> Response<Body> {
    let body = crate::api::models::ErrorResponse {
        error: "Unauthorized".to_string(),
        code: "Unauthorized".to_string(),
        details: Some("Provide Basic auth with ACCESS_KEY_ID and SECRET_ACCESS_KEY".to_string()),
    };
    let mut response = json_response(StatusCode::UNAUTHORIZED, &body);
    response.headers_mut().insert(
        "www-authenticate",
        hyper::header::HeaderValue::from_static("Basic realm=\"Peas Admin\""),
    );
    response
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

fn bucket_to_details(bucket: crate::models::Bucket) -> crate::api::models::BucketDetails {
    let versioning_enabled = bucket_service::versioning_enabled(&bucket);
    crate::api::models::BucketDetails {
        name: bucket.name,
        created_at: bucket.created_at.to_rfc3339(),
        versioning_enabled,
    }
}

fn bucket_to_info(bucket: crate::models::Bucket) -> crate::api::models::BucketInfo {
    let versioning_enabled = bucket_service::versioning_enabled(&bucket);
    crate::api::models::BucketInfo {
        name: bucket.name,
        created_at: bucket.created_at.to_rfc3339(),
        versioning_enabled,
    }
}

fn object_to_info(o: crate::models::Object) -> crate::api::models::ObjectInfo {
    crate::api::models::ObjectInfo {
        key: o.key,
        size: o.size,
        last_modified: o.last_modified.to_rfc3339(),
        etag: o.etag,
        content_type: Some(o.content_type),
        storage_class: o.storage_class,
    }
}

fn map_object_list(objects: Vec<crate::models::Object>) -> Vec<crate::api::models::ObjectInfo> {
    objects.into_iter().map(object_to_info).collect()
}

fn parse_query_map(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            let key = decode_component(k);
            let val = decode_component(v);
            out.insert(key, val);
        }
    }
    out
}

#[derive(Serialize)]
struct LegacyListBucketsResponse {
    buckets: Vec<crate::api::models::BucketInfo>,
}

#[derive(Serialize)]
struct LegacyListObjectsResponse {
    objects: Vec<crate::api::models::ObjectInfo>,
    prefix: String,
    delimiter: Option<String>,
    is_truncated: bool,
    next_marker: Option<String>,
}

#[derive(Serialize)]
struct LegacyListVersionsResponse {
    versions: Vec<crate::api::models::ObjectVersionInfo>,
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
                let resp = LegacyListBucketsResponse {
                    buckets: buckets.into_iter().map(bucket_to_info).collect(),
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
                    let resp = bucket_to_details(bucket);
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

                    let resp = LegacyListObjectsResponse {
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
                        let resp = LegacyListVersionsResponse {
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
