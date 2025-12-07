use super::http::{Request, ResponseBuilder, RouteMatch, Router};
use crate::auth::{AuthConfig, AuthInfo, SigV4Config, SignatureVerifier};
use crate::models::policy::{AuthContext, Authorizer, PolicyEffect};
use crate::models::Owner;
use crate::storage::Storage;
use crate::utils::xml as xml_utils;
use crate::utils::{headers as header_utils, validation};
use http::StatusCode;
use hyper::{Body, Response};
use std::sync::Arc;
use tracing::warn;

fn default_owner() -> Owner {
    Owner {
        id: "peas-emulator".to_string(),
        display_name: "Peas Emulator".to_string(),
    }
}
/// Verify SigV4 signature in the request
#[allow(clippy::result_large_err)]
fn verify_sigv4_signature(
    req: &dyn crate::auth::HttpRequestLike,
    auth_config: &AuthConfig,
) -> Result<bool, Response<Body>> {
    if !auth_config.enforce_auth {
        return Ok(true);
    }

    let auth_header = match req.header("authorization") {
        Some(h) => h,
        None => return Ok(true),
    };

    if !auth_header.starts_with("AWS4-HMAC-SHA256") {
        return Ok(true);
    }

    let req_id = header_utils::generate_request_id();

    let amz_date = match req.header("x-amz-date").or_else(|| req.header("date")) {
        Some(d) => d.to_string(),
        None => {
            let xml = xml_utils::error_xml("InvalidRequest", "Missing date header", &req_id);
            let resp = ResponseBuilder::new(StatusCode::BAD_REQUEST)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes());
            return Err(resp.build());
        }
    };

    let signature = match extract_sigv4_signature(auth_header) {
        Some(sig) => sig,
        None => {
            let xml = xml_utils::error_xml(
                "InvalidRequest",
                "Missing signature in authorization header",
                &req_id,
            );
            let resp = ResponseBuilder::new(StatusCode::BAD_REQUEST)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes());
            return Err(resp.build());
        }
    };

    let credential_scope = match extract_credential_scope(auth_header) {
        Some(scope) => scope,
        None => {
            let xml = xml_utils::error_xml(
                "InvalidRequest",
                "Missing credential in authorization header",
                &req_id,
            );
            let resp = ResponseBuilder::new(StatusCode::BAD_REQUEST)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes());
            return Err(resp.build());
        }
    };

    let secret_key = match auth_config.secret_key() {
        Some(key) => key,
        None => {
            warn!("SigV4 signature verification requested but no secret key configured");
            return Ok(true);
        }
    };

    let access_key = match auth_config.access_key() {
        Some(key) => key,
        None => {
            warn!("SigV4 signature verification requested but no access key configured");
            return Ok(true);
        }
    };

    let canonical_request = build_canonical_request(req);
    let sigv4_config = SigV4Config {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
    };

    let is_valid = SignatureVerifier::verify(
        &signature,
        &canonical_request,
        &amz_date,
        &credential_scope,
        &sigv4_config,
    );

    if !is_valid {
        warn!("SigV4 signature verification failed");
        let xml = xml_utils::error_xml(
            "SignatureDoesNotMatch",
            "The provided signature does not match",
            &req_id,
        );
        let resp = ResponseBuilder::new(StatusCode::FORBIDDEN)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes());
        return Err(resp.build());
    }

    Ok(true)
}

/// Extract signature from SigV4 Authorization header
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn extract_sigv4_signature(auth_header: &str) -> Option<String> {
    for part in auth_header.split(',') {
        let part = part.trim();
        if let Some(stripped) = part.strip_prefix("Signature=") {
            return Some(stripped.to_string());
        }
    }
    None
}

/// Extract credential scope from SigV4 Authorization header
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn extract_credential_scope(auth_header: &str) -> Option<String> {
    for part in auth_header.split(',') {
        let part = part.trim();
        if let Some(cred_start) = part.find("Credential=") {
            let credential = &part[cred_start + 11..];
            if let Some(slash_pos) = credential.find('/') {
                let scope = &credential[slash_pos + 1..];
                return Some(scope.split(',').next().unwrap_or(scope).to_string());
            }
        }
    }
    None
}

/// Build canonical request for SigV4 verification
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn build_canonical_request(req: &dyn crate::auth::HttpRequestLike) -> String {
    let method = "GET"; // Simplified - in real impl would get from request
    let uri = "/"; // Simplified - in real impl would get from request
    let query = req.query().unwrap_or("");

    format!("{}\n{}\n{}\n\nhost\nUNSIGNED-PAYLOAD", method, uri, query)
}

/// Check if the request is authorized to perform the action
#[allow(clippy::result_large_err)]
fn check_authorization(
    req: &dyn crate::auth::HttpRequestLike,
    auth_config: &AuthConfig,
    storage: &Arc<dyn Storage>,
    bucket: &str,
    key: Option<&str>,
    action: &str,
) -> Result<AuthInfo, Response<Body>> {
    verify_sigv4_signature(req, auth_config)?;

    let auth_info = AuthInfo::from_request(req, auth_config);

    if !auth_config.enforce_auth {
        return Ok(auth_info);
    }

    let resource = if let Some(k) = key {
        format!("arn:aws:s3:::{}/{}", bucket, k)
    } else {
        format!("arn:aws:s3:::{}", bucket)
    };

    let owner_id = default_owner().id;
    let context = AuthContext {
        principal: auth_info.principal.clone(),
        is_authenticated: auth_info.is_authenticated,
        action: action.to_string(),
        resource: resource.clone(),
        bucket_owner: Some(owner_id.clone()),
        object_owner: Some(owner_id.clone()),
    };

    let acl_allowed = if let Some(k) = key {
        match storage.get_object_acl(bucket, k) {
            Ok(acl) => Authorizer::check_acl_permission(&acl, &owner_id, &context),
            Err(_) => false,
        }
    } else {
        match storage.get_bucket_acl(bucket) {
            Ok(acl) => Authorizer::check_acl_permission(&acl, &owner_id, &context),
            Err(_) => false,
        }
    };

    let policy_result = match storage.get_bucket_policy(bucket) {
        Ok(policy) => Authorizer::evaluate_policy(&policy, &context),
        Err(_) => PolicyEffect::Neutral,
    };
    let final_decision = match policy_result {
        PolicyEffect::Deny => PolicyEffect::Deny,
        PolicyEffect::Allow => PolicyEffect::Allow,
        PolicyEffect::Neutral => {
            let is_allowed = acl_allowed
                || (auth_info.is_authenticated && auth_info.principal.contains(&owner_id));
            if is_allowed {
                PolicyEffect::Allow
            } else {
                PolicyEffect::Deny
            }
        }
    };

    match final_decision {
        PolicyEffect::Allow => Ok(auth_info),
        _ => {
            warn!(
                principal = %context.principal,
                action = %action,
                resource = %resource,
                "Access denied"
            );
            let req_id = header_utils::generate_request_id();
            let xml = xml_utils::error_xml("AccessDenied", "Access Denied", &req_id);
            let resp = ResponseBuilder::new(StatusCode::FORBIDDEN)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes());
            Err(resp.build())
        }
    }
}

pub async fn handle_request(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    req: Request,
) -> Result<Response<Body>, String> {
    let route = Router::route(req.method(), req.path());
    let req_id = header_utils::generate_request_id();

    match route {
        RouteMatch::ListBuckets => list_buckets(storage, auth_config, req, req_id).await,

        RouteMatch::BucketGet(bucket) => {
            bucket_get_or_list_objects(storage, &bucket, &req, req_id).await
        }

        RouteMatch::BucketPut(bucket) => {
            bucket_put(storage, auth_config, &bucket, &req, req_id).await
        }

        RouteMatch::BucketDelete(bucket) => {
            bucket_delete(storage, auth_config, &bucket, &req, req_id).await
        }

        RouteMatch::BucketHead(bucket) => bucket_head(storage, &bucket, req_id).await,

        RouteMatch::BucketPost(bucket) => bucket_post(storage, &bucket, req_id).await,

        RouteMatch::ObjectGet(bucket, key) => {
            object_get(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectPut(bucket, key) => {
            object_put(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectDelete(bucket, key) => {
            object_delete(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectHead(bucket, key) => {
            object_head(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectPost(bucket, key) => {
            object_post(storage, &bucket, &key, &req, req_id).await
        }

        RouteMatch::NotFound => {
            let xml = xml_utils::error_xml("NotFound", "Not Found", &req_id);
            Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn list_buckets(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    req: Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        &req,
        &auth_config,
        &storage,
        "*",
        None,
        "s3:ListAllMyBuckets",
    ) {
        return Ok(response);
    }

    let buckets = tokio::task::block_in_place(|| storage.list_buckets())?;
    let xml = xml_utils::list_buckets_xml(&buckets);

    Ok(ResponseBuilder::new(StatusCode::OK)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", &req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .body(xml.into_bytes())
        .build())
}

pub async fn bucket_head(
    storage: Arc<dyn Storage>,
    bucket: &str,
    req_id: String,
) -> Result<Response<Body>, String> {
    tokio::task::block_in_place(|| storage.get_bucket(bucket))?;

    Ok(ResponseBuilder::new(StatusCode::OK)
        .header("x-amz-request-id", &req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .empty())
}

pub async fn bucket_delete(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    let action = if req.has_query_param("lifecycle") {
        "s3:DeleteLifecycleConfiguration"
    } else {
        "s3:DeleteBucket"
    };

    if let Err(response) = check_authorization(req, &auth_config, &storage, bucket, None, action) {
        return Ok(response);
    }

    if req.has_query_param("lifecycle") {
        match tokio::task::block_in_place(|| storage.delete_bucket_lifecycle(bucket)) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(e) => {
                let (status, code) = match e {
                    crate::error::Error::BucketNotFound => (StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(code, &e.to_string(), &req_id);
                Ok(ResponseBuilder::new(status)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build())
            }
        }
    } else if req.has_query_param("policy") {
        match tokio::task::block_in_place(|| storage.delete_bucket_policy(bucket)) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(e) => {
                let (status, code) = match e {
                    crate::error::Error::BucketNotFound => (StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(code, &e.to_string(), &req_id);
                Ok(ResponseBuilder::new(status)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build())
            }
        }
    } else {
        tokio::task::block_in_place(|| storage.delete_bucket(bucket))?;
        Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty())
    }
}

pub async fn bucket_put(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    let action = if req.has_query_param("versioning") {
        "s3:PutBucketVersioning"
    } else if req.has_query_param("lifecycle") {
        "s3:PutLifecycleConfiguration"
    } else if req.has_query_param("acl") {
        "s3:PutBucketAcl"
    } else if req.has_query_param("policy") {
        "s3:PutBucketPolicy"
    } else {
        "s3:CreateBucket"
    };

    if let Err(response) = check_authorization(req, &auth_config, &storage, bucket, None, action) {
        return Ok(response);
    }

    if let Err(e) = validation::validate_bucket_name(bucket) {
        let xml = xml_utils::error_xml("InvalidBucketName", &e, &req_id);
        return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build());
    }

    // Default: Create bucket
    tokio::task::block_in_place(|| storage.create_bucket(bucket.to_string()))?;

    Ok(ResponseBuilder::new(StatusCode::OK)
        .header("x-amz-request-id", &req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .empty())
}

pub async fn bucket_get_or_list_objects(
    storage: Arc<dyn Storage>,
    bucket: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Default: List objects
    let prefix = req.query_param("prefix");
    let delimiter = req.query_param("delimiter");
    let marker = req.query_param("marker");
    let max_keys = req
        .query_param("max-keys")
        .and_then(|s| s.parse::<usize>().ok());

    match tokio::task::block_in_place(|| {
        storage.list_objects(bucket, prefix, delimiter, marker, max_keys)
    }) {
        Ok(result) => {
            let xml = xml_utils::list_objects_xml(
                &result.objects,
                bucket,
                prefix.unwrap_or(""),
                delimiter,
                marker,
                result.objects.len(),
                result.is_truncated,
                result.next_marker.as_deref(),
            );
            Ok(ResponseBuilder::new(StatusCode::OK)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .body(xml.into_bytes())
                .build())
        }
        Err(e) => {
            let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
            Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn bucket_post(
    _storage: Arc<dyn Storage>,
    _bucket: &str,
    req_id: String,
) -> Result<Response<Body>, String> {
    let xml = xml_utils::error_xml(
        "NotImplemented",
        "Bucket POST operations not yet implemented",
        &req_id,
    );
    Ok(ResponseBuilder::new(StatusCode::NOT_IMPLEMENTED)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", &req_id)
        .body(xml.into_bytes())
        .build())
}

pub async fn object_get(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        req,
        &auth_config,
        &storage,
        bucket,
        Some(key),
        "s3:GetObject",
    ) {
        return Ok(response);
    }

    // Default: Get object
    match tokio::task::block_in_place(|| storage.get_object(bucket, key)) {
        Ok(obj) => Ok(ResponseBuilder::new(StatusCode::OK)
            .content_type(&obj.content_type)
            .header("Content-Length", &obj.size.to_string())
            .header("ETag", &obj.etag.to_string())
            .header("Last-Modified", &header_utils::format_last_modified())
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .header("x-amz-storage-class", "STANDARD")
            .header("Accept-Ranges", "bytes")
            .body(obj.data)
            .build()),
        Err(e) => {
            let xml = xml_utils::error_xml("NoSuchKey", &e.to_string(), &req_id);
            Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn object_put(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        req,
        &auth_config,
        &storage,
        bucket,
        Some(key),
        "s3:PutObject",
    ) {
        return Ok(response);
    }

    if let Err(e) = validation::validate_bucket_name(bucket) {
        let xml = xml_utils::error_xml("InvalidBucketName", &e, &req_id);
        return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build());
    }

    if let Err(e) = validation::validate_object_key(key) {
        let xml = xml_utils::error_xml("InvalidKey", &e, &req_id);
        return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build());
    }

    let content_type = req
        .header("content-type")
        .unwrap_or("application/octet-stream")
        .to_string();

    let metadata = header_utils::extract_metadata_from_http_headers(req);
    let obj = crate::models::Object::new_with_metadata(
        key.to_string(),
        req.body.to_vec(),
        content_type,
        metadata,
    );
    let obj_key = obj.key.clone();
    let etag = obj.etag.clone();

    match tokio::task::block_in_place(|| storage.put_object(bucket, obj_key, obj)) {
        Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
            .header("Content-Length", "0")
            .header("ETag", &etag.to_string())
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty()),
        Err(e) => {
            let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
            Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn object_delete(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        req,
        &auth_config,
        &storage,
        bucket,
        Some(key),
        "s3:DeleteObject",
    ) {
        return Ok(response);
    }

    match tokio::task::block_in_place(|| storage.delete_object(bucket, key)) {
        Ok(_) => Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty()),
        Err(e) => {
            let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
            Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn object_head(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        req,
        &auth_config,
        &storage,
        bucket,
        Some(key),
        "s3:GetObject",
    ) {
        return Ok(response);
    }

    match tokio::task::block_in_place(|| storage.get_object(bucket, key)) {
        Ok(obj) => Ok(ResponseBuilder::new(StatusCode::OK)
            .content_type(&obj.content_type)
            .header("Content-Length", &obj.size.to_string())
            .header("ETag", &obj.etag.to_string())
            .header("Last-Modified", &header_utils::format_last_modified())
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .header("x-amz-storage-class", "STANDARD")
            .empty()),
        Err(e) => {
            let xml = xml_utils::error_xml("NoSuchKey", &e.to_string(), &req_id);
            Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}

pub async fn object_post(
    storage: Arc<dyn Storage>,
    bucket: &str,
    key: &str,
    req: &Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Handle initiate multipart upload
    if req.has_query_param("uploads") {
        match tokio::task::block_in_place(|| {
            storage.create_multipart_upload(bucket, key.to_string())
        }) {
            Ok(upload) => {
                let xml = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Bucket>{}</Bucket>
    <Key>{}</Key>
    <UploadId>{}</UploadId>
</InitiateMultipartUploadResult>"#,
                    bucket, upload.key, upload.upload_id
                );
                Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build())
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build())
            }
        }
    } else {
        let xml = xml_utils::error_xml(
            "NotImplemented",
            "Object POST operations not yet implemented",
            &req_id,
        );
        Ok(ResponseBuilder::new(StatusCode::NOT_IMPLEMENTED)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build())
    }
}
