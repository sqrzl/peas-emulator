use crate::error::{Error, Result};
use crate::services::{bucket as bucket_service, json_response, object as object_service};
use crate::storage::Storage;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hyper::body::to_bytes;
use hyper::{Body, Method, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use urlencoding::decode;

pub async fn handle_request(
    storage: Arc<dyn Storage>,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let admin_path = path
        .strip_prefix("/admin/v1")
        .ok_or_else(|| Error::RouteNotFound(path.clone()))?;

    if admin_path == "/buckets" {
        return match method {
            Method::GET => list_buckets(storage, &query),
            Method::POST => create_bucket(storage, req).await,
            _ => Err(Error::MethodNotAllowed(path)),
        };
    }

    if let Some(rest) = admin_path.strip_prefix("/buckets/") {
        let (bucket, remainder) = parse_bucket_and_remainder(rest)?;

        return match remainder {
            None => match method {
                Method::GET => get_bucket(storage, &bucket),
                Method::DELETE => delete_bucket(storage, &bucket),
                _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
            },
            Some("versioning") => match method {
                Method::GET => get_bucket_versioning(storage, &bucket),
                Method::PUT => set_bucket_versioning(storage, &bucket, req).await,
                _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
            },
            Some("objects") => match method {
                Method::GET => list_objects(storage, &bucket, &query),
                _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
            },
            Some(remainder) if remainder.starts_with("objects/") => {
                handle_object_request(
                    storage,
                    &bucket,
                    remainder.trim_start_matches("objects/"),
                    &query,
                    req,
                )
                .await
            }
            _ => Err(Error::RouteNotFound(path)),
        };
    }

    Err(Error::RouteNotFound(path))
}

pub fn error_response(err: &Error) -> Response<Body> {
    let details = match err {
        Error::InvalidRequest(details)
        | Error::MethodNotAllowed(details)
        | Error::RouteNotFound(details) => Some(details.clone()),
        _ => None,
    };

    let body = crate::api::models::ErrorResponse {
        error: err.to_string(),
        code: err.error_code().to_string(),
        details,
    };

    json_response(err.status_code(), &body)
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

fn decode_component(input: &str) -> String {
    decode(input)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| input.to_string())
}

async fn read_json<T: DeserializeOwned>(req: Request<Body>) -> Result<T> {
    let bytes = to_bytes(req.into_body())
        .await
        .map_err(|e| Error::InvalidRequest(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| Error::InvalidRequest(e.to_string()))
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
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

#[derive(Clone, Debug)]
struct PageParams {
    next: usize,
    limit: usize,
    search: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum PageTokenKind {
    Buckets,
    Objects,
    Versions,
}

impl PageTokenKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Buckets => "buckets",
            Self::Objects => "objects",
            Self::Versions => "versions",
        }
    }
}

fn parse_next_token(token: &str, kind: PageTokenKind) -> Result<usize> {
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::InvalidRequest("invalid next token".into()))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| Error::InvalidRequest("invalid next token".into()))?;
    let (token_kind, offset) = decoded
        .split_once(':')
        .ok_or_else(|| Error::InvalidRequest("invalid next token".into()))?;

    if token_kind != kind.as_str() {
        return Err(Error::InvalidRequest("invalid next token".into()));
    }

    offset
        .parse::<usize>()
        .map_err(|_| Error::InvalidRequest("invalid next token".into()))
}

fn parse_page_params(query: &str, kind: PageTokenKind) -> Result<PageParams> {
    let params = parse_query_map(query);

    let next = params
        .get("next")
        .map(|value| parse_next_token(value, kind))
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

fn paginate<T>(items: Vec<T>, page: &PageParams) -> (Vec<T>, Option<usize>) {
    let start = page.next.min(items.len());
    let end = (start + page.limit).min(items.len());
    let next = (end < items.len()).then_some(end);
    let items = items.into_iter().skip(start).take(page.limit).collect();
    (items, next)
}

fn encode_next(next: Option<usize>, kind: PageTokenKind) -> Option<String> {
    next.map(|offset| URL_SAFE_NO_PAD.encode(format!("{}:{}", kind.as_str(), offset)))
}

fn contains_search(value: &str, search: Option<&str>) -> bool {
    match search {
        Some(search) => value.to_ascii_lowercase().contains(search),
        None => true,
    }
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

fn list_buckets(storage: Arc<dyn Storage>, query: &str) -> Result<Response<Body>> {
    let page = parse_page_params(query, PageTokenKind::Buckets)?;
    let mut buckets =
        tokio::task::block_in_place(|| bucket_service::list_buckets(storage.as_ref()))?;
    buckets.sort_by(|left, right| left.name.cmp(&right.name));
    let buckets = buckets
        .into_iter()
        .filter(|bucket| contains_search(&bucket.name, page.search.as_deref()))
        .map(bucket_to_info)
        .collect();
    let (items, next) = paginate(buckets, &page);

    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::ListBucketsResponse {
            items,
            next: encode_next(next, PageTokenKind::Buckets),
        },
    ))
}

async fn create_bucket(storage: Arc<dyn Storage>, req: Request<Body>) -> Result<Response<Body>> {
    #[derive(Deserialize)]
    struct CreateReq {
        name: String,
    }

    let payload: CreateReq = read_json(req).await?;
    let name = payload.name;
    tokio::task::block_in_place(|| bucket_service::create_bucket(storage.as_ref(), name.clone()))?;
    let bucket =
        tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), &name))?;

    Ok(json_response(
        StatusCode::CREATED,
        &bucket_to_details(bucket),
    ))
}

fn get_bucket(storage: Arc<dyn Storage>, bucket: &str) -> Result<Response<Body>> {
    let bucket =
        tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket))?;
    Ok(json_response(StatusCode::OK, &bucket_to_details(bucket)))
}

fn delete_bucket(storage: Arc<dyn Storage>, bucket: &str) -> Result<Response<Body>> {
    tokio::task::block_in_place(|| bucket_service::delete_bucket(storage.as_ref(), bucket))?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

fn get_bucket_versioning(storage: Arc<dyn Storage>, bucket: &str) -> Result<Response<Body>> {
    let bucket =
        tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket))?;
    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::VersioningStatus {
            enabled: bucket_service::versioning_enabled(&bucket),
        },
    ))
}

async fn set_bucket_versioning(
    storage: Arc<dyn Storage>,
    bucket: &str,
    req: Request<Body>,
) -> Result<Response<Body>> {
    #[derive(Deserialize)]
    struct VersioningReq {
        enabled: bool,
    }

    let body: VersioningReq = read_json(req).await?;
    tokio::task::block_in_place(|| {
        bucket_service::set_versioning(storage.as_ref(), bucket, body.enabled)
    })?;

    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::VersioningStatus {
            enabled: body.enabled,
        },
    ))
}

fn list_objects(storage: Arc<dyn Storage>, bucket: &str, query: &str) -> Result<Response<Body>> {
    let page = parse_page_params(query, PageTokenKind::Objects)?;
    let mut objects = tokio::task::block_in_place(|| {
        object_service::list_objects(storage.as_ref(), bucket, None, None, None, None)
    })?
    .objects;
    objects.sort_by(|left, right| left.key.cmp(&right.key));
    let objects = objects
        .into_iter()
        .filter(|object| contains_search(&object.key, page.search.as_deref()))
        .map(object_to_info)
        .collect();
    let (items, next) = paginate(objects, &page);

    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::ListObjectsResponse {
            items,
            next: encode_next(next, PageTokenKind::Objects),
        },
    ))
}

async fn handle_object_request(
    storage: Arc<dyn Storage>,
    bucket: &str,
    object_rest: &str,
    query: &str,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if object_rest.is_empty() {
        return Err(Error::InvalidRequest("Missing object key".into()));
    }

    if let Some(key) = object_rest.strip_suffix("/content") {
        let key = decode_component(key);
        return match method {
            Method::GET => download_object_content(storage, bucket, &key),
            Method::PUT => put_object_content(storage, bucket, &key, req).await,
            _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
        };
    }

    if let Some(key) = object_rest.strip_suffix("/versions") {
        let key = decode_component(key);
        return match method {
            Method::GET => list_object_versions(storage, bucket, &key, query),
            _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
        };
    }

    if let Some(key) = object_rest.strip_suffix("/tags") {
        let key = decode_component(key);
        return match method {
            Method::GET => get_object_tags(storage, bucket, &key),
            Method::PUT => put_object_tags(storage, bucket, &key, req).await,
            _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
        };
    }

    if object_rest.contains('/') {
        return Err(Error::RouteNotFound(path));
    }

    let key = decode_component(object_rest);
    match method {
        Method::GET => get_object_metadata(storage, bucket, &key),
        Method::DELETE => delete_object(storage, bucket, &key),
        _ => Err(Error::MethodNotAllowed(format!("{} {}", method, path))),
    }
}

fn get_object_metadata(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
) -> Result<Response<Body>> {
    let object =
        tokio::task::block_in_place(|| object_service::get_object(storage.as_ref(), bucket, key))?;
    Ok(json_response(StatusCode::OK, &object_to_metadata(object)))
}

fn delete_object(storage: Arc<dyn Storage>, bucket: &str, key: &str) -> Result<Response<Body>> {
    tokio::task::block_in_place(|| object_service::delete_object(storage.as_ref(), bucket, key))?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}

fn download_object_content(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
) -> Result<Response<Body>> {
    let obj =
        tokio::task::block_in_place(|| object_service::get_object(storage.as_ref(), bucket, key))?;
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", obj.content_type);
    Ok(builder
        .body(Body::from(obj.data))
        .unwrap_or_else(|_| Response::new(Body::empty())))
}

async fn put_object_content(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let existed = tokio::task::block_in_place(|| {
        object_service::object_exists(storage.as_ref(), bucket, key)
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
        key.to_string(),
        bytes.to_vec(),
        content_type,
        metadata,
    );
    tokio::task::block_in_place(|| {
        object_service::put_object(storage.as_ref(), bucket, key.to_string(), object)
    })?;
    let stored =
        tokio::task::block_in_place(|| object_service::get_object(storage.as_ref(), bucket, key))?;
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(json_response(status, &object_to_metadata(stored)))
}

fn list_object_versions(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
    query: &str,
) -> Result<Response<Body>> {
    let page = parse_page_params(query, PageTokenKind::Versions)?;
    let current_version_id =
        tokio::task::block_in_place(|| object_service::get_object(storage.as_ref(), bucket, key))
            .ok()
            .and_then(|object| object.version_id);
    let mut versions = tokio::task::block_in_place(|| {
        object_service::list_object_versions(storage.as_ref(), bucket, Some(key))
    })?;
    versions.sort_by(|left, right| right.last_modified.cmp(&left.last_modified));
    let versions = versions
        .into_iter()
        .filter(|object| {
            contains_search(&object.key, page.search.as_deref())
                || object
                    .version_id
                    .as_deref()
                    .map(|version_id| contains_search(version_id, page.search.as_deref()))
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

    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::ListVersionsResponse {
            items,
            next: encode_next(next, PageTokenKind::Versions),
        },
    ))
}

fn get_object_tags(storage: Arc<dyn Storage>, bucket: &str, key: &str) -> Result<Response<Body>> {
    let tags = tokio::task::block_in_place(|| {
        object_service::get_object_tags(storage.as_ref(), bucket, key)
    })?;
    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::TagsResponse { tags },
    ))
}

async fn put_object_tags(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
    req: Request<Body>,
) -> Result<Response<Body>> {
    #[derive(Deserialize)]
    struct TagsReq {
        tags: HashMap<String, String>,
    }

    let body: TagsReq = read_json(req).await?;
    tokio::task::block_in_place(|| {
        object_service::put_object_tags(storage.as_ref(), bucket, key, body.tags.clone())
    })?;
    Ok(json_response(
        StatusCode::OK,
        &crate::api::models::TagsResponse { tags: body.tags },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::{
        BucketDetails, ErrorResponse, ListBucketsResponse, ListObjectsResponse,
        ListVersionsResponse, ObjectMetadata, TagsResponse, VersioningStatus,
    };
    use crate::storage::FilesystemStorage;
    use hyper::body::to_bytes;
    use hyper::Request;
    use serde::de::DeserializeOwned;
    use std::fs;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir = std::env::temp_dir().join(format!("peas-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    async fn call(api_req: Request<Body>, storage: Arc<dyn Storage>) -> Response<Body> {
        match handle_request(storage, api_req).await {
            Ok(resp) => resp,
            Err(err) => error_response(&err),
        }
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
            .method(Method::PUT)
            .uri("/admin/v1/buckets/demo/versioning")
            .header("content-type", "application/json")
            .body(Body::from("{\"enabled\":false}"))
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let versioning: VersioningStatus = json_body(resp).await;
        assert!(!versioning.enabled);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/buckets/demo")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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
            assert!(matches!(
                resp.status(),
                StatusCode::CREATED | StatusCode::OK
            ));
        }

        for body in ["v1", "v2"] {
            let req = Request::builder()
                .method(Method::PUT)
                .uri("/admin/v1/buckets/demo/objects/versioned.txt/content")
                .header("content-type", "text/plain")
                .body(Body::from(body))
                .unwrap();
            let resp = call(req, storage.clone()).await;
            assert!(matches!(
                resp.status(),
                StatusCode::CREATED | StatusCode::OK
            ));
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
            .uri(format!(
                "/admin/v1/buckets/demo/objects?limit=1&search=.txt&next={}",
                next
            ))
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let next_page: ListObjectsResponse = json_body(resp).await;
        assert_eq!(next_page.items.len(), 1);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/buckets/demo/objects/versioned.txt/versions?limit=10&search=versioned")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_json_content_type(&resp);
        let versions: ListVersionsResponse = json_body(resp).await;
        assert!(versions.items.len() >= 2);
        assert!(versions.items.iter().any(|version| version.is_latest));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admin_reports_method_and_route_errors() {
        let storage = temp_storage();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/buckets/demo")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_json_content_type(&resp);
        let error: ErrorResponse = json_body(resp).await;
        assert_eq!(error.code, "MethodNotAllowed");
        assert_eq!(error.error, "Method not allowed");

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/v1/does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = call(req, storage.clone()).await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let error: ErrorResponse = json_body(resp).await;
        assert_eq!(error.code, "NotFound");
        assert_eq!(error.error, "Route not found");
    }
}
