use crate::error::{Error, Result};
use crate::services::{
    bucket as bucket_service, json_error_response, json_response, object as object_service,
};
use crate::storage::Storage;
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
    let path = req.uri().path().to_string();

    if path == "/admin/v1" || path.starts_with("/admin/v1/") {
        let resp = match handle_admin_request(storage, req).await {
            Ok(resp) => resp,
            Err(err) => json_error_response(&err),
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

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[derive(Clone, Debug)]
struct PageParams {
    next: usize,
    limit: usize,
    search: Option<String>,
}

fn parse_page_params(query: &str) -> Result<PageParams> {
    let params = parse_query_map(query);

    let next = params
        .get("next")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| Error::InvalidRequest("invalid next token".into()))
        })
        .transpose()?
        .unwrap_or(0);

    let limit = params
        .get("limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| Error::InvalidRequest("invalid limit".into()))
        })
        .transpose()?
        .unwrap_or(50);

    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidRequest(
            "limit must be between 1 and 500".into(),
        ));
    }

    let search = params
        .get("search")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    Ok(PageParams {
        next,
        limit,
        search,
    })
}

fn paginate<T>(items: Vec<T>, page: &PageParams) -> (Vec<T>, Option<String>) {
    let start = page.next.min(items.len());
    let end = (start + page.limit).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    let items = items.into_iter().skip(start).take(page.limit).collect();
    (items, next)
}

fn contains_search(value: &str, search: Option<&str>) -> bool {
    match search {
        Some(search) => value.to_ascii_lowercase().contains(search),
        None => true,
    }
}

fn encode_next(next: Option<String>) -> Option<String> {
    next
}

fn parse_bucket_and_remainder(rest: &str) -> Result<(String, Option<&str>)> {
    let (bucket, remainder) = match rest.split_once('/') {
        Some((bucket, remainder)) => (bucket, Some(remainder)),
        None => (rest, None),
    };

    let bucket = decode_component(bucket);
    if bucket.is_empty() {
        return Err(Error::InvalidRequest("Missing bucket".into()));
    }

    Ok((bucket, remainder))
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

async fn handle_admin_request(
    storage: Arc<dyn Storage>,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("");
    let admin_path = path
        .strip_prefix("/admin/v1")
        .ok_or_else(|| Error::InvalidRequest("Unsupported path".into()))?;

    if admin_path == "/buckets" {
        match method {
            Method::GET => {
                let page = parse_page_params(query)?;
                let mut buckets =
                    tokio::task::block_in_place(|| bucket_service::list_buckets(storage.as_ref()))?;
                buckets.sort_by(|left, right| left.name.cmp(&right.name));
                let buckets = buckets
                    .into_iter()
                    .filter(|bucket| contains_search(&bucket.name, page.search.as_deref()))
                    .map(bucket_to_info)
                    .collect();
                let (items, next) = paginate(buckets, &page);

                return Ok(json_response(
                    StatusCode::OK,
                    &crate::api::models::ListBucketsResponse {
                        items,
                        next: encode_next(next),
                    },
                ));
            }
            Method::POST => {
                #[derive(Deserialize)]
                struct CreateReq {
                    name: String,
                }

                let payload: CreateReq = read_json(req).await?;
                let name = payload.name;
                tokio::task::block_in_place(|| {
                    bucket_service::create_bucket(storage.as_ref(), name.clone())
                })?;
                let bucket =
                    tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), &name))?;
                return Ok(json_response(StatusCode::CREATED, &bucket_to_details(bucket)));
            }
            _ => return Err(Error::InvalidRequest("Unsupported method".into())),
        }
    }

    if let Some(rest) = admin_path.strip_prefix("/buckets/") {
        let (bucket, remainder) = parse_bucket_and_remainder(rest)?;

        match remainder {
            None => match method {
                Method::GET => {
                    let bucket = tokio::task::block_in_place(|| {
                        bucket_service::get_bucket(storage.as_ref(), &bucket)
                    })?;
                    return Ok(json_response(StatusCode::OK, &bucket_to_details(bucket)));
                }
                Method::DELETE => {
                    tokio::task::block_in_place(|| {
                        bucket_service::delete_bucket(storage.as_ref(), &bucket)
                    })?;
                    return Ok(empty_response(StatusCode::NO_CONTENT));
                }
                _ => return Err(Error::InvalidRequest("Unsupported method".into())),
            },
            Some("versioning") => match method {
                Method::GET => {
                    let bucket = tokio::task::block_in_place(|| {
                        bucket_service::get_bucket(storage.as_ref(), &bucket)
                    })?;
                    return Ok(json_response(
                        StatusCode::OK,
                        &crate::api::models::VersioningStatus {
                            enabled: bucket_service::versioning_enabled(&bucket),
                        },
                    ));
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
                        &crate::api::models::VersioningStatus {
                            enabled: body.enabled,
                        },
                    ));
                }
                _ => return Err(Error::InvalidRequest("Unsupported method".into())),
            },
            Some(remainder) if remainder == "objects" => {
                if method != Method::GET {
                    return Err(Error::InvalidRequest("Unsupported method".into()));
                }

                let page = parse_page_params(query)?;
                let mut objects = tokio::task::block_in_place(|| {
                    object_service::list_objects(storage.as_ref(), &bucket, None, None, None, None)
                })?
                .objects;
                objects.sort_by(|left, right| left.key.cmp(&right.key));
                let objects = objects
                    .into_iter()
                    .filter(|object| contains_search(&object.key, page.search.as_deref()))
                    .map(object_to_info)
                    .collect();
                let (items, next) = paginate(objects, &page);

                return Ok(json_response(
                    StatusCode::OK,
                    &crate::api::models::ListObjectsResponse {
                        items,
                        next: encode_next(next),
                    },
                ));
            }
            Some(remainder) if remainder.starts_with("objects/") => {
                let object_rest = remainder.trim_start_matches("objects/");
                if object_rest.is_empty() {
                    return Err(Error::InvalidRequest("Missing object key".into()));
                }

                if let Some(key) = object_rest.strip_suffix("/content") {
                    let key = decode_component(key);
                    match method {
                        Method::GET => {
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
                        Method::PUT => {
                            let existed = tokio::task::block_in_place(|| {
                                object_service::object_exists(storage.as_ref(), &bucket, &key)
                            })?;
                            let headers = req.headers().clone();
                            let bytes = to_bytes(req.into_body())
                                .await
                                .map_err(|e| Error::InvalidRequest(e.to_string()))?;
                            let content_type = headers
                                .get("content-type")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("application/octet-stream")
                                .to_string();

                            let mut metadata = HashMap::new();
                            for (name, value) in headers.iter() {
                                if let Some(stripped) = name.as_str().strip_prefix("x-amz-meta-") {
                                    if let Ok(value) = value.to_str() {
                                        metadata.insert(stripped.to_string(), value.to_string());
                                    }
                                }
                            }

                            let object = crate::models::Object::new_with_metadata(
                                key.clone(),
                                bytes.to_vec(),
                                content_type,
                                metadata,
                            );
                            tokio::task::block_in_place(|| {
                                object_service::put_object(
                                    storage.as_ref(),
                                    &bucket,
                                    key.clone(),
                                    object,
                                )
                            })?;
                            let stored = tokio::task::block_in_place(|| {
                                object_service::get_object(storage.as_ref(), &bucket, &key)
                            })?;
                            let status = if existed {
                                StatusCode::OK
                            } else {
                                StatusCode::CREATED
                            };
                            return Ok(json_response(status, &object_to_metadata(stored)));
                        }
                        _ => return Err(Error::InvalidRequest("Unsupported method".into())),
                    }
                }

                if let Some(key) = object_rest.strip_suffix("/versions") {
                    if method != Method::GET {
                        return Err(Error::InvalidRequest("Unsupported method".into()));
                    }

                    let key = decode_component(key);
                    let page = parse_page_params(query)?;
                    let current_version_id = tokio::task::block_in_place(|| {
                        object_service::get_object(storage.as_ref(), &bucket, &key)
                    })
                    .ok()
                    .and_then(|object| object.version_id);
                    let mut versions = tokio::task::block_in_place(|| {
                        object_service::list_object_versions(storage.as_ref(), &bucket, Some(&key))
                    })?;
                    versions.sort_by(|left, right| right.last_modified.cmp(&left.last_modified));
                    let versions = versions
                        .into_iter()
                        .filter(|object| {
                            contains_search(&object.key, page.search.as_deref())
                                || object
                                    .version_id
                                    .as_deref()
                                    .map(|version_id| {
                                        contains_search(version_id, page.search.as_deref())
                                    })
                                    .unwrap_or(false)
                        })
                        .map(|object| {
                            let version_id = object.version_id.clone().unwrap_or_default();
                            crate::api::models::ObjectVersionInfo {
                                key: object.key,
                                version_id: version_id.clone(),
                                size: object.size,
                                last_modified: object.last_modified.to_rfc3339(),
                                etag: object.etag,
                                is_latest: current_version_id.as_deref() == Some(version_id.as_str()),
                            }
                        })
                        .collect();
                    let (items, next) = paginate(versions, &page);

                    return Ok(json_response(
                        StatusCode::OK,
                        &crate::api::models::ListVersionsResponse {
                            items,
                            next: encode_next(next),
                        },
                    ));
                }

                if let Some(key) = object_rest.strip_suffix("/tags") {
                    let key = decode_component(key);
                    match method {
                        Method::GET => {
                            let tags = tokio::task::block_in_place(|| {
                                object_service::get_object_tags(storage.as_ref(), &bucket, &key)
                            })?;
                            return Ok(json_response(
                                StatusCode::OK,
                                &crate::api::models::TagsResponse { tags },
                            ));
                        }
                        Method::PUT => {
                            #[derive(Deserialize)]
                            struct TagsReq {
                                tags: HashMap<String, String>,
                            }

                            let body: TagsReq = read_json(req).await?;
                            tokio::task::block_in_place(|| {
                                object_service::put_object_tags(
                                    storage.as_ref(),
                                    &bucket,
                                    &key,
                                    body.tags.clone(),
                                )
                            })?;
                            return Ok(json_response(
                                StatusCode::OK,
                                &crate::api::models::TagsResponse { tags: body.tags },
                            ));
                        }
                        _ => return Err(Error::InvalidRequest("Unsupported method".into())),
                    }
                }

                let key = decode_component(object_rest);
                match method {
                    Method::GET => {
                        let object = tokio::task::block_in_place(|| {
                            object_service::get_object(storage.as_ref(), &bucket, &key)
                        })?;
                        return Ok(json_response(StatusCode::OK, &object_to_metadata(object)));
                    }
                    Method::DELETE => {
                        tokio::task::block_in_place(|| {
                            object_service::delete_object(storage.as_ref(), &bucket, &key)
                        })?;
                        return Ok(empty_response(StatusCode::NO_CONTENT));
                    }
                    _ => return Err(Error::InvalidRequest("Unsupported method".into())),
                }
            }
            _ => return Err(Error::InvalidRequest("Unsupported path".into())),
        }
    }

    Err(Error::InvalidRequest("Unsupported path".into()))
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
                    buckets: buckets
                        .into_iter()
                        .map(bucket_to_info)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{
        BucketDetails, ListBucketsResponse, ListObjectsResponse, ListVersionsResponse,
        ObjectMetadata, TagsResponse, VersioningStatus,
    };
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
    async fn admin_bucket_crud_json() {
        let storage = temp_storage();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/buckets")
            .header("content-type", "application/json")
            .body(Body::from("{\"name\":\"demo\"}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_json_content_type(&resp);
        let created: BucketDetails = json_body(resp).await;
        assert_eq!(created.name, "demo");
        assert!(!created.versioning_enabled);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let bucket: BucketDetails = json_body(resp).await;
        assert_eq!(bucket.name, "demo");
        assert!(!bucket.versioning_enabled);

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/v1/buckets/demo/versioning")
            .header("content-type", "application/json")
            .body(Body::from("{\"enabled\":true}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let versioning: VersioningStatus = json_body(resp).await;
        assert!(versioning.enabled);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/buckets/demo")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admin_object_content_and_tags() {
        let storage = temp_storage();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/buckets")
            .header("content-type", "application/json")
            .body(Body::from("{\"name\":\"demo\"}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/v1/buckets/demo/objects/hello.txt/content")
            .header("content-type", "text/plain")
            .header("x-amz-meta-owner", "alice")
            .header("X-Amz-Meta-Environment", "dev")
            .body(Body::from("hello"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_json_content_type(&resp);
        let uploaded: ObjectMetadata = json_body(resp).await;
        assert_eq!(uploaded.key, "hello.txt");

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects/hello.txt")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

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

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/v1/buckets/demo/objects/hello.txt/tags")
            .header("content-type", "application/json")
            .body(Body::from("{\"tags\":{\"env\":\"dev\"}}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let tags: TagsResponse = json_body(resp).await;
        assert_eq!(tags.tags.get("env"), Some(&"dev".to_string()));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects/hello.txt/tags")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let tags: TagsResponse = json_body(resp).await;
        assert_eq!(tags.tags.get("env"), Some(&"dev".to_string()));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects/hello.txt/content")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain")
        );
        let bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(&bytes[..], b"hello");

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/buckets/demo/objects/hello.txt")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admin_lists_support_next_limit_and_search() {
        let storage = temp_storage();

        for bucket in ["alpha", "beta", "gamma"] {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/admin/v1/buckets")
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"name\":\"{}\"}}", bucket)))
                .unwrap();
            let resp = call(req, storage.clone()).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets?limit=1&search=a")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let buckets: ListBucketsResponse = json_body(resp).await;
        assert_eq!(buckets.items.len(), 1);
        assert!(buckets.next.is_some());

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/buckets")
            .header("content-type", "application/json")
            .body(Body::from("{\"name\":\"demo\"}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/admin/v1/buckets/demo/versioning")
            .header("content-type", "application/json")
            .body(Body::from("{\"enabled\":true}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        for key in ["alpha.txt", "beta.txt", "gamma.bin"] {
            let req = Request::builder()
                .method(Method::PUT)
                .uri(format!("/admin/v1/buckets/demo/objects/{}/content", key))
                .header("content-type", "text/plain")
                .body(Body::from(key.to_string()))
                .unwrap();
            let resp = call(req, storage.clone()).await;
            assert!(matches!(resp.status(), StatusCode::CREATED | StatusCode::OK));
        }

        for body in ["v1", "v2"] {
            let req = Request::builder()
                .method(Method::PUT)
                .uri("/admin/v1/buckets/demo/objects/versioned.txt/content")
                .header("content-type", "text/plain")
                .body(Body::from(body))
                .unwrap();
            let resp = call(req, storage.clone()).await;
            assert!(matches!(resp.status(), StatusCode::CREATED | StatusCode::OK));
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects?limit=1&search=.txt")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let objects: ListObjectsResponse = json_body(resp).await;
        assert_eq!(objects.items.len(), 1);
        let next = objects.next.clone().expect("objects page should continue");

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/admin/v1/buckets/demo/objects?limit=1&search=.txt&next={}", next))
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let next_page: ListObjectsResponse = json_body(resp).await;
        assert_eq!(next_page.items.len(), 1);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects/versioned.txt/versions?limit=1&search=versioned")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let versions: ListVersionsResponse = json_body(resp).await;
        assert_eq!(versions.items.len(), 1);
        assert!(versions.next.is_some());
    }
}
