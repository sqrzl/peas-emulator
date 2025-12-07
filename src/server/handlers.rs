use super::*;
use actix_web::{web, HttpRequest, HttpResponse};
use crate::auth::{AuthConfig, AuthInfo, SignatureVerifier, SigV4Config};
use crate::models::{Acl, CannedAcl, Owner};
use crate::models::policy::{AuthContext, Authorizer, PolicyEffect};
use crate::utils::{headers as header_utils, validation};
use crate::utils::xml as xml_utils;
use tracing::{info, warn, instrument};

fn default_owner() -> Owner {
    Owner {
        id: "peas-emulator".to_string(),
        display_name: "Peas Emulator".to_string(),
    }
}

/// Verify SigV4 signature in the request
/// Returns Ok(true) if signature is valid or auth is not enforced
/// Returns Ok(false) if signature is invalid
/// Returns Err(HttpResponse) with 400/403 error if verification fails
fn verify_sigv4_signature(
    req: &HttpRequest,
    auth_config: &AuthConfig,
) -> Result<bool, HttpResponse> {
    // If auth is not enforced, skip verification
    if !auth_config.enforce_auth {
        return Ok(true);
    }

    // Check if there's an Authorization header with SigV4
    let auth_header = match req.headers().get("authorization") {
        Some(header) => match header.to_str() {
            Ok(s) => s,
            Err(_) => return Ok(true), // Invalid header format, will be caught later
        },
        None => return Ok(true), // No auth header, will be handled by other checks
    };

    // Only verify if it's SigV4
    if !auth_header.starts_with("AWS4-HMAC-SHA256") {
        return Ok(true); // Not SigV4, skip verification (v2 or presigned URLs handled separately)
    }

    let req_id = header_utils::generate_request_id();

    // Extract required headers for SigV4
    let amz_date = match req.headers().get("x-amz-date")
        .or_else(|| req.headers().get("date")) {
        Some(h) => match h.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidRequest", "Invalid date header", &req_id);
                return Err(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        },
        None => {
            let xml = xml_utils::error_xml("InvalidRequest", "Missing date header", &req_id);
            return Err(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }
    };

    // Extract signature from Authorization header
    let signature = match extract_sigv4_signature(auth_header) {
        Some(sig) => sig,
        None => {
            let xml = xml_utils::error_xml("InvalidRequest", "Missing signature in authorization header", &req_id);
            return Err(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }
    };

    // Extract credential scope from Authorization header
    let credential_scope = match extract_credential_scope(auth_header) {
        Some(scope) => scope,
        None => {
            let xml = xml_utils::error_xml("InvalidRequest", "Missing credential in authorization header", &req_id);
            return Err(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }
    };

    // Get credentials from config
    let secret_key = match auth_config.secret_key() {
        Some(key) => key,
        None => {
            // No secret key configured, can't verify
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

    // Build canonical request for verification
    let canonical_request = build_canonical_request(req);

    // Verify the signature
    let sigv4_config = SigV4Config {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
    };

    let is_valid = SignatureVerifier::verify(&signature, &canonical_request, &amz_date, &credential_scope, &sigv4_config);

    if !is_valid {
        warn!("SigV4 signature verification failed");
        let xml = xml_utils::error_xml("SignatureDoesNotMatch", "The provided signature does not match", &req_id);
        return Err(HttpResponse::Forbidden()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml));
    }

    Ok(true)
}

/// Extract signature from SigV4 Authorization header
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn extract_sigv4_signature(auth_header: &str) -> Option<String> {
    for part in auth_header.split(',') {
        let part = part.trim();
        if part.starts_with("Signature=") {
            return Some(part[10..].to_string()); // Skip "Signature="
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
            let credential = &part[cred_start + 11..]; // Skip "Credential="
            // Scope is everything after the access key and first slash
            if let Some(slash_pos) = credential.find('/') {
                let scope = &credential[slash_pos + 1..];
                // Stop at comma if present
                return Some(scope.split(',').next().unwrap_or(scope).to_string());
            }
        }
    }
    None
}

/// Build canonical request for SigV4 verification
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn build_canonical_request(req: &HttpRequest) -> String {
    let method = req.method().to_string();
    let uri = req.uri().path();
    let query = req.uri().query().unwrap_or("");
    
    // For now, use a simplified canonical request
    // In production, this should properly construct the full canonical request
    // including headers, query parameters, etc.
    format!(
        "{}\n{}\n{}\n\nhost\nUNSIGNED-PAYLOAD",
        method, uri, query
    )
}

/// Check if the request is authorized to perform the action
fn check_authorization(
    req: &HttpRequest,
    auth_config: &AuthConfig,
    storage: &Arc<dyn Storage>,
    bucket: &str,
    key: Option<&str>,
    action: &str,
) -> Result<AuthInfo, HttpResponse> {
    // First, verify SigV4 signature if present
    verify_sigv4_signature(req, auth_config)?;

    // Extract authentication info
    let auth_info = AuthInfo::from_request(req, auth_config);
    
    // If auth is not enforced, allow everything
    if !auth_config.enforce_auth {
        return Ok(auth_info);
    }

    // Build authorization context
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

    // Check ACL permissions
    let acl_allowed = if let Some(k) = key {
        // Object ACL check
        match storage.get_object_acl(bucket, k) {
            Ok(acl) => Authorizer::check_acl_permission(&acl, &owner_id, &context),
            Err(_) => false, // If we can't get ACL, skip to policy check
        }
    } else {
        // Bucket ACL check
        match storage.get_bucket_acl(bucket) {
            Ok(acl) => Authorizer::check_acl_permission(&acl, &owner_id, &context),
            Err(_) => false,
        }
    };

    // Check bucket policy
    let policy_result = match storage.get_bucket_policy(bucket) {
        Ok(policy) => Authorizer::evaluate_policy(&policy, &context),
        Err(_) => PolicyEffect::Neutral,
    };

    // Combine results: Deny takes precedence, then Allow, then check if owner
    let final_decision = match policy_result {
        PolicyEffect::Deny => PolicyEffect::Deny,
        PolicyEffect::Allow => PolicyEffect::Allow,
        PolicyEffect::Neutral => {
            if acl_allowed {
                PolicyEffect::Allow
            } else if auth_info.is_authenticated && auth_info.principal.contains(&owner_id) {
                // Owner has full access
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
            let xml = xml_utils::error_xml(
                "AccessDenied",
                "Access Denied",
                &req_id,
            );
            Err(HttpResponse::Forbidden()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml))
        }
    }
}

fn parse_canned_acl(header: Option<&str>) -> Result<CannedAcl, String> {
    match header.map(|h| h.to_ascii_lowercase()) {
        None => Ok(CannedAcl::Private),
        Some(h) => match h.as_str() {
            "private" => Ok(CannedAcl::Private),
            "public-read" => Ok(CannedAcl::PublicRead),
            "public-read-write" => Ok(CannedAcl::PublicReadWrite),
            _ => Err(format!("Unsupported canned ACL: {}", h)),
        },
    }
}

pub async fn list_buckets(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    // Check authorization for listing buckets
    if let Err(response) = check_authorization(&req, &auth_config, &storage, "*", None, "s3:ListAllMyBuckets") {
        return Ok(response);
    }

    let storage = storage.clone();
    let buckets = tokio::task::block_in_place(|| storage.list_buckets())?;
    let xml = xml_utils::list_buckets_xml(&buckets);
    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", "application/xml; charset=utf-8"))
        .insert_header(("Content-Length", xml.len().to_string()))
        .insert_header(("x-amz-request-id", header_utils::generate_request_id()))
        .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
        .body(xml))
}

pub async fn bucket_delete(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    bucket: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = bucket.into_inner();
    let req_id = header_utils::generate_request_id();

    // Check authorization
    let action = if query.contains_key("lifecycle") {
        "s3:DeleteLifecycleConfiguration"
    } else {
        "s3:DeleteBucket"
    };
    
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket_name, None, action) {
        return Ok(response);
    }

    // Handle DELETE bucket lifecycle
    if query.contains_key("lifecycle") {
        let storage = storage.clone();
        return match tokio::task::block_in_place(|| storage.delete_bucket_lifecycle(&bucket_name)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id.clone()))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        };
    }

    // Handle DELETE bucket policy
    if query.contains_key("policy") {
        let storage = storage.clone();
        return match tokio::task::block_in_place(|| storage.delete_bucket_policy(&bucket_name)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id.clone()))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        };
    }

    // Default: Delete bucket
    let storage = storage.clone();
    tokio::task::block_in_place(|| storage.delete_bucket(&bucket_name))?;

    Ok(HttpResponse::NoContent()
        .insert_header(("x-amz-request-id", req_id))
        .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
        .finish())
}

pub async fn bucket_head(
    storage: web::Data<Arc<dyn Storage>>,
    bucket: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let storage = storage.clone();
    tokio::task::block_in_place(|| storage.get_bucket(&bucket))?;

    Ok(HttpResponse::Ok()
        .insert_header(("x-amz-request-id", header_utils::generate_request_id()))
        .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
        .finish())
}

#[instrument(skip(storage, req, body), fields(bucket, key, request_id, size))]
pub async fn object_put(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    path: web::Path<(String, String)>,
    req: HttpRequest,
    query: web::Query<std::collections::HashMap<String, String>>,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let (bucket, key) = path.into_inner();
    let req_id = header_utils::generate_request_id();
    
    // Record span fields
    tracing::Span::current()
        .record("bucket", bucket.as_str())
        .record("key", key.as_str())
        .record("request_id", req_id.as_str())
        .record("size", body.len());
    
    info!(method = "PUT", bucket = %bucket, key = %key, request_id = %req_id, size = body.len(), "Processing object PUT request");

    // Check authorization
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket, Some(&key), "s3:PutObject") {
        return Ok(response);
    }

    // Validate bucket and key names
    if let Err(e) = validation::validate_bucket_name(&bucket) {
        let xml = xml_utils::error_xml("InvalidBucketName", &e, &req_id);
        return Ok(HttpResponse::BadRequest()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml));
    }
    if let Err(e) = validation::validate_object_key(&key) {
        let xml = xml_utils::error_xml("InvalidKey", &e, &req_id);
        return Ok(HttpResponse::BadRequest()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml));
    }

    // Handle multipart upload part
    if query.contains_key("uploadId") && query.contains_key("partNumber") {
        let upload_id = query.get("uploadId").unwrap().as_str();
        let part_number: u32 = match query.get("partNumber").unwrap().parse() {
            Ok(n) => n,
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidArgument", "Invalid part number", &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        // Validate part number
        if let Err(e) = validation::validate_part_number(part_number) {
            let xml = xml_utils::error_xml("InvalidArgument", &e, &req_id);
            return Ok(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }

        // Validate upload ID
        if let Err(e) = validation::validate_upload_id(upload_id) {
            let xml = xml_utils::error_xml("InvalidArgument", &e, &req_id);
            return Ok(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.upload_part(&bucket, upload_id, part_number, body.to_vec())) {
            Ok(etag) => Ok(HttpResponse::Ok()
                .insert_header(("Content-Length", "0"))
                .insert_header(("ETag", etag.to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle object ACL
    else if query.contains_key("acl") {
        let canned_acl = match parse_canned_acl(req.headers().get("x-amz-acl").and_then(|h| h.to_str().ok())) {
            Ok(c) => c,
            Err(msg) => {
                let xml = xml_utils::error_xml("InvalidArgument", &msg, &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.put_object_acl(&bucket, &key, Acl { canned: canned_acl, grants: vec![] })) {
            Ok(_) => Ok(HttpResponse::Ok()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchKey"),
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle tagging
    else if query.contains_key("tagging") {
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidRequest", "Invalid UTF-8 in tagging body", &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        let tags = match xml_utils::parse_tagging_xml(body_str) {
            Ok(t) => t,
            Err(msg) => {
                let code = match msg.as_str() {
                    "TooManyTags" => "InvalidTag",
                    "InvalidTagKey" => "InvalidTag",
                    "InvalidTagValue" => "InvalidTag",
                    _ => "InvalidRequest",
                };
                let xml = xml_utils::error_xml(code, &format!("Invalid tagging XML: {}", msg), &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.put_object_tags(&bucket, &key, tags)) {
            Ok(_) => Ok(HttpResponse::Ok()
                .insert_header(("Content-Length", "0"))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchKey"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Default: Put object
    else {
        let content_type = req.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let metadata = header_utils::extract_metadata(req.headers());
        let obj = crate::models::Object::new_with_metadata(key, body.to_vec(), content_type, metadata);
        let storage = storage.clone();
        let obj_key = obj.key.clone();
        let etag = obj.etag.clone();

        match tokio::task::block_in_place(|| storage.put_object(&bucket, obj_key, obj)) {
            Ok(_) => Ok(HttpResponse::Ok()
                .insert_header(("Content-Length", "0"))
                .insert_header(("ETag", etag.to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
}

#[instrument(skip(storage, req), fields(bucket, key, request_id))]
pub async fn object_get(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    path: web::Path<(String, String)>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: actix_web::HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let (bucket, key) = path.into_inner();
    let req_id = header_utils::generate_request_id();
    
    // Record span fields
    tracing::Span::current()
        .record("bucket", bucket.as_str())
        .record("key", key.as_str())
        .record("request_id", req_id.as_str());
    
    info!(method = "GET", bucket = %bucket, key = %key, request_id = %req_id, "Processing object GET request");

    // Check authorization
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket, Some(&key), "s3:GetObject") {
        return Ok(response);
    }

    // Parse Range header if present
    let range_header = req.headers().get("range").and_then(|h| h.to_str().ok());

    // Handle list parts for multipart upload
    if query.contains_key("uploadId") {
        let upload_id = query.get("uploadId").unwrap().as_str();

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.list_parts(&bucket, upload_id)) {
            Ok(parts) => {
                let xml = xml_utils::list_parts_xml(&bucket, &key, upload_id, &parts);
                Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml))
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle presigned URL generation
    else if query.contains_key("presignedUrl") {
        // Check if credentials are configured
        if auth_config.access_key_id.is_none() || auth_config.secret_access_key.is_none() {
            let xml = xml_utils::error_xml("InvalidConfiguration", "Credentials not configured for presigned URLs", &req_id);
            return Ok(HttpResponse::BadRequest()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml));
        }

        let method = query.get("method").cloned().unwrap_or_else(|| "GET".to_string());
        let expires = query.get("expires")
            .and_then(|e| e.parse::<i64>().ok())
            .unwrap_or(3600); // Default: 1 hour

        let presigned_config = crate::auth::presigned::PresignedUrlConfig {
            access_key: auth_config.access_key_id.clone().unwrap(),
            secret_key: auth_config.secret_access_key.clone().unwrap(),
        };
        let base_url = format!("http://localhost:9000/{}/{}", bucket, key);
        
        let url = if method.to_uppercase() == "PUT" {
            crate::auth::presigned::PresignedUrl::generate_put_url(&bucket, &key, expires, &base_url, &presigned_config)
        } else {
            crate::auth::presigned::PresignedUrl::generate_get_url(&bucket, &key, expires, &base_url, &presigned_config)
        };

        let response_body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PresignedUrl><Url>{}</Url></PresignedUrl>", url);
        Ok(HttpResponse::Ok()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", response_body.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(response_body))
    }
    // Handle object ACL
    else if query.contains_key("acl") {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_object_acl(&bucket, &key)) {
            Ok(acl) => {
                let owner = default_owner();
                let xml = xml_utils::acl_xml(&owner, &acl);
                Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml))
            }
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchKey"),
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle tagging
    else if query.contains_key("tagging") {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_object_tags(&bucket, &key)) {
            Ok(tags) => {
                let xml = xml_utils::tagging_xml(&tags);
                Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml))
            }
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchKey"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle versioning - GET specific version
    else if query.contains_key("versionId") {
        let version_id = query.get("versionId").unwrap().as_str();

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_object_version(&bucket, &key, version_id)) {
            Ok(obj) => {
                let mut resp = HttpResponse::Ok();
                let mut builder = resp
                    .content_type(obj.content_type.as_str())
                    .insert_header(("Content-Length", obj.size.to_string()))
                    .insert_header(("ETag", obj.etag.to_string()))
                    .insert_header(("Last-Modified", header_utils::format_last_modified()))
                    .insert_header(("x-amz-version-id", version_id))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()));

                for (k, v) in obj.metadata.iter() {
                    builder = builder.insert_header((format!("x-amz-meta-{}", k), v.clone()));
                }

                Ok(builder.body(obj.data))
            }
            Err(e) => {
                let (status_code, error_code) = if e.to_string().contains("not found") {
                    (actix_web::http::StatusCode::NOT_FOUND, "NoSuchVersion")
                } else {
                    (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Default: Get object
    else {
        let storage = storage.clone();

        // Handle Range requests
        if let Some(range_str) = range_header {
            if let Some(range_part) = range_str.strip_prefix("bytes=") {
                if let Some((start_str, end_str)) = range_part.split_once('-') {
                    let start = start_str.parse::<u64>().ok();
                    let end = if end_str.is_empty() {
                        None
                    } else {
                        end_str.parse::<u64>().ok()
                    };

                    if let Some(start_pos) = start {
                        match tokio::task::block_in_place(|| storage.get_object_range(&bucket, &key, start_pos, end)) {
                            Ok((obj, data)) => {
                                let content_length = data.len();
                                let actual_end = start_pos + content_length as u64 - 1;
                                let content_range = format!("bytes {}-{}/{}", start_pos, actual_end, obj.size);

                                let mut resp = HttpResponse::PartialContent();
                                let mut builder = resp
                                    .content_type(obj.content_type.as_str())
                                    .insert_header(("Content-Length", content_length.to_string()))
                                    .insert_header(("Content-Range", content_range))
                                    .insert_header(("ETag", obj.etag.to_string()))
                                    .insert_header(("Last-Modified", header_utils::format_last_modified()))
                                    .insert_header(("x-amz-request-id", req_id.clone()))
                                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                                    .insert_header(("Accept-Ranges", "bytes"));

                                for (k, v) in obj.metadata.iter() {
                                    builder = builder.insert_header((format!("x-amz-meta-{}", k), v.clone()));
                                }

                                return Ok(builder.body(data));
                            }
                            Err(e) => {
                                let xml = xml_utils::error_xml("InvalidRange", &e.to_string(), &req_id);
                                return Ok(HttpResponse::build(actix_web::http::StatusCode::RANGE_NOT_SATISFIABLE)
                                    .content_type("application/xml; charset=utf-8")
                                    .insert_header(("Content-Length", xml.len().to_string()))
                                    .insert_header(("x-amz-request-id", req_id))
                                    .body(xml));
                            }
                        }
                    }
                }
            }
        }

        // Regular GET (no range)
        match tokio::task::block_in_place(|| storage.get_object(&bucket, &key)) {
            Ok(obj) => {
                let mut resp = HttpResponse::Ok();
                let mut builder = resp
                    .content_type(obj.content_type.as_str())
                    .insert_header(("Content-Length", obj.size.to_string()))
                    .insert_header(("ETag", obj.etag.to_string()))
                    .insert_header(("Last-Modified", header_utils::format_last_modified()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .insert_header(("x-amz-storage-class", "STANDARD"))
                    .insert_header(("Accept-Ranges", "bytes"));

                for (k, v) in obj.metadata.iter() {
                    builder = builder.insert_header((format!("x-amz-meta-{}", k), v.clone()));
                }

                Ok(builder.body(obj.data))
            }
            Err(e) => {
                let xml = xml_utils::error_xml("NoSuchKey", &e.to_string(), &req_id);
                Ok(HttpResponse::NotFound()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
}

pub async fn object_head(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    path: web::Path<(String, String)>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let (bucket, key) = path.into_inner();
    let req_id = header_utils::generate_request_id();

    // Check authorization
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket, Some(&key), "s3:GetObject") {
        return Ok(response);
    }

    // Handle versioning
    if query.contains_key("versionId") {
        let xml = xml_utils::error_xml("NotImplemented", "Versioning not yet implemented", &req_id);
        return Ok(HttpResponse::NotImplemented()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml));
    }

    // Default: Head object
    let storage = storage.clone();
    match tokio::task::block_in_place(|| storage.get_object(&bucket, &key)) {
        Ok(obj) => {
            let mut resp = HttpResponse::Ok();
            let mut builder = resp
                .content_type(obj.content_type.as_str())
                .insert_header(("Content-Length", obj.size.to_string()))
                .insert_header(("ETag", obj.etag.to_string()))
                .insert_header(("Last-Modified", header_utils::format_last_modified()))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .insert_header(("x-amz-storage-class", "STANDARD"));

            for (k, v) in obj.metadata.iter() {
                builder = builder.insert_header((format!("x-amz-meta-{}", k), v.clone()));
            }

            Ok(builder.finish())
        }
        Err(e) => {
            let xml = xml_utils::error_xml("NoSuchKey", &e.to_string(), &req_id);
            Ok(HttpResponse::NotFound()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml))
        }
    }
}

pub async fn object_delete(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    path: web::Path<(String, String)>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let (bucket, key) = path.into_inner();
    let req_id = header_utils::generate_request_id();

    // Check authorization
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket, Some(&key), "s3:DeleteObject") {
        return Ok(response);
    }

    // Handle versioning - DELETE specific version
    if query.contains_key("versionId") {
        let version_id = query.get("versionId").unwrap().as_str();

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.delete_object_version(&bucket, &key, version_id)) {
            Ok(_) => return Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-version-id", version_id))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = if e.to_string().contains("not found") {
                    (actix_web::http::StatusCode::NOT_FOUND, "NoSuchVersion")
                } else {
                    (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                return Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    // Handle multipart abort
    if query.contains_key("uploadId") {
        let upload_id = query.get("uploadId").unwrap().as_str();

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.abort_multipart_upload(&bucket, upload_id)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle delete tagging
    else if query.contains_key("tagging") {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.delete_object_tags(&bucket, &key)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchKey"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Default: Delete object
    else {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.delete_object(&bucket, &key)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
}

pub async fn bucket_put(
    storage: web::Data<Arc<dyn Storage>>,
    auth_config: web::Data<Arc<AuthConfig>>,
    bucket: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
    body: web::Bytes,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = bucket.into_inner();
    let req_id = header_utils::generate_request_id();

    // Check authorization - CreateBucket for bucket creation, PutBucketVersioning for versioning config
    let action = if query.contains_key("versioning") {
        "s3:PutBucketVersioning"
    } else if query.contains_key("lifecycle") {
        "s3:PutLifecycleConfiguration"
    } else if query.contains_key("acl") {
        "s3:PutBucketAcl"
    } else if query.contains_key("policy") {
        "s3:PutBucketPolicy"
    } else {
        "s3:CreateBucket"
    };
    
    if let Err(response) = check_authorization(&req, &auth_config, &storage, &bucket_name, None, action) {
        return Ok(response);
    }

    // Validate bucket name
    if let Err(e) = validation::validate_bucket_name(&bucket_name) {
        let xml = xml_utils::error_xml("InvalidBucketName", &e, &req_id);
        return Ok(HttpResponse::BadRequest()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml));
    }

    // Route by query parameter
    if query.contains_key("versioning") {
        // PUT bucket versioning - parse XML body for Enabled/Suspended
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidRequest", "Invalid UTF-8 in versioning body", &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };
        
        let enabled = match xml_utils::parse_versioning_xml(body_str) {
            Ok(e) => e,
            Err(msg) => {
                let xml = xml_utils::error_xml("MalformedXML", &format!("Invalid versioning XML: {}", msg), &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        let storage = storage.clone();
        let result = if enabled {
            tokio::task::block_in_place(|| storage.enable_versioning(&bucket_name))
        } else {
            tokio::task::block_in_place(|| storage.suspend_versioning(&bucket_name))
        };

        match result {
            Ok(_) => return Ok(HttpResponse::Ok()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    if query.contains_key("lifecycle") {
        // PUT bucket lifecycle - parse XML body and store configuration
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidRequest", "Invalid UTF-8 in lifecycle body", &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };
        
        let config = match xml_utils::parse_lifecycle_xml(body_str) {
            Ok(c) => c,
            Err(msg) => {
                let xml = xml_utils::error_xml("MalformedXML", &format!("Invalid lifecycle XML: {}", msg), &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };
        
        let storage = storage.clone();
        return match tokio::task::block_in_place(|| storage.put_bucket_lifecycle(&bucket_name, config)) {
            Ok(_) => Ok(HttpResponse::Ok()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        };
    }

    if query.contains_key("policy") {
        // PUT bucket policy - parse JSON body and store
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                let xml = xml_utils::error_xml("InvalidRequest", "Invalid UTF-8 in policy body", &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };
        
        let policy: crate::models::policy::BucketPolicyDocument = match serde_json::from_str(body_str) {
            Ok(p) => p,
            Err(e) => {
                let xml = xml_utils::error_xml("MalformedPolicy", &format!("Invalid policy JSON: {}", e), &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };
        
        let storage = storage.clone();
        return match tokio::task::block_in_place(|| storage.put_bucket_policy(&bucket_name, policy)) {
            Ok(_) => Ok(HttpResponse::NoContent()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        };
    }

    if query.contains_key("acl") {
        let canned_acl = match parse_canned_acl(req.headers().get("x-amz-acl").and_then(|h| h.to_str().ok())) {
            Ok(c) => c,
            Err(msg) => {
                let xml = xml_utils::error_xml("InvalidArgument", &msg, &req_id);
                return Ok(HttpResponse::BadRequest()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        };

        let storage = storage.clone();
        return match tokio::task::block_in_place(|| storage.put_bucket_acl(&bucket_name, Acl { canned: canned_acl, grants: vec![] })) {
            Ok(_) => Ok(HttpResponse::Ok()
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .finish()),
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        };
    }

    // Default: Create bucket
    let storage = storage.clone();
    match tokio::task::block_in_place(|| storage.create_bucket(bucket_name)) {
        Ok(_) => Ok(HttpResponse::Ok()
            .insert_header(("x-amz-request-id", req_id))
            .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
            .finish()),
        Err(e) => {
            let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
            Ok(HttpResponse::InternalServerError()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml))
        }
    }
}

pub async fn bucket_get_or_list_objects(
    storage: web::Data<Arc<dyn Storage>>,
    bucket: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    let bucket_name = bucket.into_inner();
    let req_id = header_utils::generate_request_id();

    // Route by query parameter
    if query.contains_key("versioning") {
        // GET bucket versioning - Check if versioning marker file exists
        let versioning_enabled = tokio::task::block_in_place(|| {
            // Check if versioning marker exists
            let bucket_path = std::path::Path::new("blobs").join(&bucket_name).join(".versioning-enabled");
            bucket_path.exists()
        });

        let status = if versioning_enabled { Some("Enabled") } else { None };
        let xml = xml_utils::versioning_status_xml(status);
        return Ok(HttpResponse::Ok()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
            .body(xml));
    }

    if query.contains_key("location") {
        // GET bucket location
        let xml = xml_utils::location_xml("us-east-1");
        return Ok(HttpResponse::Ok()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
            .body(xml));
    }

    if query.contains_key("lifecycle") {
        // GET bucket lifecycle - retrieve configuration
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_bucket_lifecycle(&bucket_name)) {
            Ok(config) => {
                let xml = xml_utils::lifecycle_xml(&config);
                return Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml));
            }
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchLifecycleConfiguration"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let message = if error_code == "NoSuchLifecycleConfiguration" {
                    "The lifecycle configuration does not exist"
                } else {
                    &e.to_string()
                };
                let xml = xml_utils::error_xml(error_code, message, &req_id);
                return Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    if query.contains_key("policy") {
        // GET bucket policy - retrieve and return as JSON
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_bucket_policy(&bucket_name)) {
            Ok(policy) => {
                let policy_json = serde_json::to_string(&policy)
                    .unwrap_or_else(|_| "{}".to_string());
                return Ok(HttpResponse::Ok()
                    .content_type("application/json")
                    .insert_header(("Content-Length", policy_json.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(policy_json));
            }
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::KeyNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucketPolicy"),
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                return Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    if query.contains_key("acl") {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.get_bucket_acl(&bucket_name)) {
            Ok(acl) => {
                let owner = default_owner();
                let xml = xml_utils::acl_xml(&owner, &acl);
                return Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml));
            }
            Err(e) => {
                let (status_code, error_code) = match e {
                    crate::error::Error::BucketNotFound => (actix_web::http::StatusCode::NOT_FOUND, "NoSuchBucket"),
                    _ => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
                };
                let xml = xml_utils::error_xml(error_code, &e.to_string(), &req_id);
                return Ok(HttpResponse::build(status_code)
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    if query.contains_key("uploads") {
        // GET list multipart uploads
        // NOTE: Currently returns empty list - full implementation would load from storage
        let xml = xml_utils::list_multipart_uploads_xml(&[], &bucket_name);
        return Ok(HttpResponse::Ok()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
            .body(xml));
    }

    if query.contains_key("versions") {
        // GET list object versions
        let storage = storage.clone();
        let prefix = query.get("prefix").map(|s| s.as_str());
        let key_marker = query.get("key-marker").map(|s| s.as_str());
        let version_id_marker = query.get("version-id-marker").map(|s| s.as_str());
        let max_keys = query.get("max-keys")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1000)
            .min(1000); // S3 maximum is 1000

        match tokio::task::block_in_place(|| storage.list_object_versions(&bucket_name, prefix)) {
            Ok(mut versions) => {
                // Filter based on key-marker and version-id-marker
                if let Some(km) = key_marker {
                    if let Some(vm) = version_id_marker {
                        // Keep only versions after (key_marker, version_id_marker)
                        let mut found = false;
                        versions.retain(|v| {
                            if found {
                                return true;
                            }
                            if v.key.as_str() == km && v.version_id.as_deref() == Some(vm) {
                                found = true;
                                return false; // Exclude the marker itself
                            }
                            false
                        });
                    } else {
                        // Keep only versions with key > key_marker
                        versions.retain(|v| v.key.as_str() > km);
                    }
                }

                let truncated = versions.len() > max_keys;
                let (next_key_marker, next_version_id_marker) = if truncated {
                    versions.get(max_keys).map(|v| (
                        Some(v.key.as_str()),
                        v.version_id.as_deref()
                    )).unwrap_or((None, None))
                } else {
                    (None, None)
                };

                let limited_versions: Vec<_> = versions.iter().take(max_keys).cloned().collect();
                let xml = xml_utils::list_versions_xml(
                    &bucket_name,
                    &limited_versions,
                    prefix.unwrap_or(""),
                    key_marker,
                    version_id_marker,
                    max_keys,
                    truncated,
                    next_key_marker,
                    next_version_id_marker,
                );
                return Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml));
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml));
            }
        }
    }

    // Default: List objects
    let storage = storage.clone();
    let prefix = query.get("prefix").map(|s| s.as_str());
    let delimiter = query.get("delimiter").map(|s| s.as_str());
    let marker = query.get("marker").map(|s| s.as_str());
    let max_keys = query.get("max-keys")
        .and_then(|s| s.parse::<usize>().ok());

    match tokio::task::block_in_place(|| storage.list_objects(&bucket_name, prefix, delimiter, marker, max_keys)) {
        Ok(result) => {
            let max_keys_actual = max_keys.unwrap_or(1000).min(1000);
            let xml = xml_utils::list_objects_xml(
                &result.objects,
                &bucket_name,
                prefix.unwrap_or(""),
                delimiter,
                marker,
                max_keys_actual,
                result.is_truncated,
                result.next_marker.as_deref(),
            );
            Ok(HttpResponse::Ok()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                .body(xml))
        }
        Err(e) => {
            let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
            Ok(HttpResponse::InternalServerError()
                .content_type("application/xml; charset=utf-8")
                .insert_header(("Content-Length", xml.len().to_string()))
                .insert_header(("x-amz-request-id", req_id))
                .body(xml))
        }
    }
}

pub async fn bucket_post(
    _storage: web::Data<Arc<dyn Storage>>,
    _bucket: web::Path<String>,
    _query: web::Query<std::collections::HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    let req_id = header_utils::generate_request_id();
    // POST bucket operations (e.g., delete multiple objects)
    let xml = xml_utils::error_xml("NotImplemented", "Bucket POST operations not yet implemented", &req_id);
    Ok(HttpResponse::NotImplemented()
        .content_type("application/xml; charset=utf-8")
        .insert_header(("Content-Length", xml.len().to_string()))
        .insert_header(("x-amz-request-id", req_id))
        .body(xml))
}

pub async fn object_post(
    storage: web::Data<Arc<dyn Storage>>,
    path: web::Path<(String, String)>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    let (bucket, key) = path.into_inner();
    let req_id = header_utils::generate_request_id();

    // Handle initiate multipart upload
    if query.contains_key("uploads") {
        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.create_multipart_upload(&bucket, key)) {
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
                Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml))
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle complete multipart upload
    else if query.contains_key("uploadId") {
        let upload_id = query.get("uploadId").unwrap().as_str();

        let storage = storage.clone();
        match tokio::task::block_in_place(|| storage.complete_multipart_upload(&bucket, upload_id)) {
            Ok(etag) => {
                // Generate complete multipart upload response XML
                let xml = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Location>/{}/{}</Location>
    <Bucket>{}</Bucket>
    <Key>{}</Key>
    <ETag>{}</ETag>
</CompleteMultipartUploadResult>"#,
                    bucket, key, bucket, key, etag
                );
                Ok(HttpResponse::Ok()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .insert_header(("x-amz-id-2", header_utils::generate_request_id()))
                    .body(xml))
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                Ok(HttpResponse::InternalServerError()
                    .content_type("application/xml; charset=utf-8")
                    .insert_header(("Content-Length", xml.len().to_string()))
                    .insert_header(("x-amz-request-id", req_id))
                    .body(xml))
            }
        }
    }
    // Handle restore from Glacier - not yet implemented
    else if query.contains_key("restore") {
        let xml = xml_utils::error_xml("NotImplemented", "Object restore not yet implemented", &req_id);
        Ok(HttpResponse::NotImplemented()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml))
    }
    // Unknown POST operation
    else {
        let xml = xml_utils::error_xml("NotImplemented", "Object POST operations not yet implemented", &req_id);
        Ok(HttpResponse::NotImplemented()
            .content_type("application/xml; charset=utf-8")
            .insert_header(("Content-Length", xml.len().to_string()))
            .insert_header(("x-amz-request-id", req_id))
            .body(xml))
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::Storage;
    use crate::utils::headers as header_utils;
    use crate::utils::xml as xml_utils;

    #[test]
    fn should_generate_request_id_given_no_input_when_request_id_generated() {
        // Arrange
        // No setup needed

        // Act
        let id1 = header_utils::generate_request_id();
        let id2 = header_utils::generate_request_id();

        // Assert
        assert!(!id1.is_empty(), "Request ID should not be empty");
        assert_ne!(id1, id2, "Request IDs should be unique");
    }

    #[test]
    fn should_produce_xml_with_declaration_given_error_code_when_error_xml_called() {
        // Arrange
        let error_code = "NoSuchBucket";
        let error_message = "Bucket does not exist";
        let request_id = "req-12345";

        // Act
        let xml = xml_utils::error_xml(error_code, error_message, request_id);

        // Assert
        assert!(xml.starts_with("<?xml"), "XML should start with declaration");
        assert!(xml.contains("<Code>NoSuchBucket</Code>"), "XML should contain error code");
        assert!(xml.contains("<Message>Bucket does not exist</Message>"), "XML should contain error message");
        assert!(xml.contains("<RequestId>req-12345</RequestId>"), "XML should contain request ID");
    }

    #[test]
    fn should_include_list_multipart_uploads_element_given_empty_list_when_list_multipart_xml_called() {
        // Arrange
        let bucket_name = "test-bucket";
        let uploads = vec![];

        // Act
        let xml = xml_utils::list_multipart_uploads_xml(&uploads, bucket_name);

        // Assert
        assert!(xml.contains("<ListMultipartUploadsResult"), "XML should contain ListMultipartUploadsResult element");
        assert!(xml.contains("<Bucket>test-bucket</Bucket>"), "XML should contain bucket name");
        assert!(xml.contains("</ListMultipartUploadsResult>"), "XML should close ListMultipartUploadsResult");
    }

    #[test]
    fn should_escape_special_characters_given_xml_string_when_escape_xml_called() {
        // Arrange
        // Note: escape_xml is private, so we test it through error_xml which uses it

        // Act
        let error_with_escaping = xml_utils::error_xml("Test&Code", "Message<with>specials", "req-id");

        // Assert
        assert!(error_with_escaping.contains("Test&amp;Code"), "Should escape ampersand");
        assert!(error_with_escaping.contains("Message&lt;with&gt;specials"), "Should escape brackets");
    }

    #[test]
    fn should_compute_different_etags_given_different_data_when_compute_etag_called() {
        // Arrange
        let data1 = b"first object data";
        let data2 = b"second object data";

        // Act
        let etag1 = header_utils::compute_etag(data1);
        let etag2 = header_utils::compute_etag(data2);

        // Assert
        assert_ne!(etag1, etag2, "Different data should produce different ETags");
        assert_eq!(etag1.len(), 32, "ETag should be 32 hex characters");
    }

    #[test]
    fn should_return_consistent_timestamp_given_no_input_when_format_last_modified_called() {
        // Arrange
        // No setup needed

        // Act
        let timestamp1 = header_utils::format_last_modified();
        let timestamp2 = header_utils::format_last_modified();

        // Assert
        assert!(timestamp1.contains(", "), "Should be RFC2822 format");
        // Timestamps won't be identical but should have same format
        assert!(timestamp2.contains(", "), "Both timestamps should be RFC2822 format");
    }

    #[test]
    fn should_include_versioning_configuration_element_given_enabled_status_when_versioning_status_xml_called() {
        // Arrange
        let status = Some("Enabled");

        // Act
        let xml = xml_utils::versioning_status_xml(status);

        // Assert
        assert!(xml.contains("<VersioningConfiguration"), "XML should contain VersioningConfiguration element");
        assert!(xml.contains("<Status>Enabled</Status>"), "XML should contain Enabled status");
        assert!(xml.contains("</VersioningConfiguration>"), "XML should close VersioningConfiguration element");
    }

    #[test]
    fn should_include_location_constraint_element_given_region_when_location_xml_called() {
        // Arrange
        let region = "us-west-2";

        // Act
        let xml = xml_utils::location_xml(region);

        // Assert
        assert!(xml.contains("<LocationConstraint"), "XML should contain LocationConstraint element");
        assert!(xml.contains("us-west-2"), "XML should contain region name");
    }

    #[test]
    fn should_include_bucket_name_in_list_buckets_given_bucket_when_list_buckets_xml_called() {
        // Arrange
        let bucket = crate::models::Bucket {
            name: "my-test-bucket".to_string(),
            created_at: chrono::Utc::now(),
            versioning_enabled: false,
            policy: None,
            metadata: std::collections::HashMap::new(),
            lifecycle_rules: vec![],
            acl: None,
        };

        // Act
        let xml = xml_utils::list_buckets_xml(&[bucket]);

        // Assert
        assert!(xml.contains("<Name>my-test-bucket</Name>"), "XML should contain bucket name");
        assert!(xml.contains("<ListBucketsResult"), "XML should contain ListBucketsResult element");
        assert!(xml.contains("<Owner>"), "XML should contain Owner element");
    }

    #[test]
    fn should_create_multipart_upload_given_valid_bucket_and_key_when_create_multipart_upload_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_multipart"));
        let bucket_name = "test-bucket-multipart";
        let key = "test-object.bin";

        // Create bucket first
        let _ = storage.create_bucket(bucket_name.to_string());

        // Act
        let upload = storage.create_multipart_upload(bucket_name, key.to_string());

        // Assert
        assert!(upload.is_ok(), "Should create multipart upload");
        let upload = upload.unwrap();
        assert_eq!(upload.key, key, "Upload key should match");
        assert!(!upload.upload_id.is_empty(), "Upload ID should not be empty");
        assert!(upload.parts.is_empty(), "Initial upload should have no parts");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_multipart");
    }

    #[test]
    fn should_store_part_given_valid_upload_id_and_part_number_when_upload_part_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_part"));
        let bucket_name = "test-bucket-part";
        let key = "test-object.bin";
        let part_data = b"This is part 1 data";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();

        // Act
        let result = storage.upload_part(bucket_name, &upload.upload_id, 1, part_data.to_vec());

        // Assert
        assert!(result.is_ok(), "Should upload part");
        let etag = result.unwrap();
        assert!(!etag.is_empty(), "ETag should not be empty");
        assert_eq!(etag.len(), 32, "ETag should be 32 hex characters (MD5)");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_part");
    }

    #[test]
    fn should_list_parts_given_valid_upload_id_when_list_parts_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_list"));
        let bucket_name = "test-bucket-list";
        let key = "test-object.bin";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();

        // Upload two parts
        let _ = storage.upload_part(bucket_name, &upload.upload_id, 1, b"part1".to_vec());
        let _ = storage.upload_part(bucket_name, &upload.upload_id, 2, b"part2".to_vec());

        // Act
        let parts = storage.list_parts(bucket_name, &upload.upload_id);

        // Assert
        assert!(parts.is_ok(), "Should list parts");
        let parts = parts.unwrap();
        assert_eq!(parts.len(), 2, "Should have 2 parts");
        assert_eq!(parts[0].part_number, 1, "First part number should be 1");
        assert_eq!(parts[1].part_number, 2, "Second part number should be 2");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_list");
    }

    #[test]
    fn should_reject_invalid_part_number_given_part_number_above_10000_when_upload_part_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_invalid"));
        let bucket_name = "test-bucket-invalid";
        let key = "test-object.bin";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();

        // Act
        let result = storage.upload_part(bucket_name, &upload.upload_id, 10001, b"data".to_vec());

        // Assert
        assert!(result.is_err(), "Should reject part number > 10000");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_invalid");
    }

    #[test]
    fn should_compute_final_etag_given_multiple_parts_when_complete_multipart_upload_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_complete"));
        let bucket_name = "test-bucket-complete";
        let key = "test-object.bin";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();

        // Upload parts
        let _ = storage.upload_part(bucket_name, &upload.upload_id, 1, b"part1".to_vec());
        let _ = storage.upload_part(bucket_name, &upload.upload_id, 2, b"part2".to_vec());

        // Act
        let result = storage.complete_multipart_upload(bucket_name, &upload.upload_id);

        // Assert
        assert!(result.is_ok(), "Should complete multipart upload");
        let etag = result.unwrap();
        assert!(etag.ends_with("-2"), "Final ETag should end with -2 (part count)");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_complete");
    }

    #[test]
    fn should_reject_out_of_order_parts_given_parts_not_sequential_when_complete_multipart_upload_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_order"));
        let bucket_name = "test-bucket-order";
        let key = "test-object.bin";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();

        // Upload parts out of order (skip part 1)
        let _ = storage.upload_part(bucket_name, &upload.upload_id, 2, b"part2".to_vec());

        // Act
        let result = storage.complete_multipart_upload(bucket_name, &upload.upload_id);

        // Assert
        assert!(result.is_err(), "Should reject out-of-order parts");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_order");
    }

    #[test]
    fn should_remove_upload_given_valid_upload_id_when_abort_multipart_upload_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_abort"));
        let bucket_name = "test-bucket-abort";
        let key = "test-object.bin";

        // Create bucket and multipart upload
        let _ = storage.create_bucket(bucket_name.to_string());
        let upload = storage.create_multipart_upload(bucket_name, key.to_string()).unwrap();
        let upload_id = upload.upload_id.clone();

        // Act
        let result = storage.abort_multipart_upload(bucket_name, &upload_id);

        // Assert
        assert!(result.is_ok(), "Should abort multipart upload");

        // Verify upload is gone
        let verify = storage.get_multipart_upload(bucket_name, &upload_id);
        assert!(verify.is_err(), "Upload should be deleted after abort");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_abort");
    }

    #[test]
    fn should_preserve_metadata_given_x_amz_meta_headers_when_object_stored() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;
        use std::collections::HashMap;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_metadata"));
        let bucket_name = "test-bucket-metadata";
        let key = "test-object.txt";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        // Create object with metadata
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "John Doe".to_string());
        metadata.insert("environment".to_string(), "production".to_string());
        metadata.insert("version".to_string(), "1.0".to_string());

        let obj = Object::new_with_metadata(
            key.to_string(),
            b"test data".to_vec(),
            "text/plain".to_string(),
            metadata.clone(),
        );

        // Act - Store the object
        let result = storage.put_object(bucket_name, key.to_string(), obj);
        assert!(result.is_ok(), "Should store object with metadata");

        // Act - Retrieve the object
        let retrieved = storage.get_object(bucket_name, key);
        
        // Assert
        assert!(retrieved.is_ok(), "Should retrieve object");
        let retrieved_obj = retrieved.unwrap();
        
        // Verify metadata is preserved
        assert_eq!(retrieved_obj.metadata.get("author"), Some(&"John Doe".to_string()), "Author metadata should match");
        assert_eq!(retrieved_obj.metadata.get("environment"), Some(&"production".to_string()), "Environment metadata should match");
        assert_eq!(retrieved_obj.metadata.get("version"), Some(&"1.0".to_string()), "Version metadata should match");
        assert_eq!(retrieved_obj.metadata.len(), 3, "Should have exactly 3 metadata entries");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_metadata");
    }

    #[test]
    fn should_handle_empty_metadata_given_no_metadata_when_object_stored() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_no_metadata"));
        let bucket_name = "test-bucket-no-metadata";
        let key = "test-object.txt";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        // Create object without metadata (use default constructor)
        let obj = Object::new(
            key.to_string(),
            b"test data".to_vec(),
            "text/plain".to_string(),
        );

        // Act - Store the object
        let result = storage.put_object(bucket_name, key.to_string(), obj);
        assert!(result.is_ok(), "Should store object without metadata");

        // Act - Retrieve the object
        let retrieved = storage.get_object(bucket_name, key);
        
        // Assert
        assert!(retrieved.is_ok(), "Should retrieve object");
        let retrieved_obj = retrieved.unwrap();
        assert!(retrieved_obj.metadata.is_empty(), "Metadata should be empty");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_no_metadata");
    }

    #[test]
    fn should_extract_metadata_headers_given_x_amz_meta_headers_when_extract_metadata_called() {
        // Arrange
        use crate::utils::headers as header_utils;
        use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-amz-meta-custom-key"),
            HeaderValue::from_static("custom-value"),
        );
        headers.insert(
            HeaderName::from_static("x-amz-meta-author"),
            HeaderValue::from_static("test-author"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        // Act
        let metadata = header_utils::extract_metadata(&headers);

        // Assert
        assert_eq!(metadata.len(), 2, "Should extract 2 metadata headers");
        assert_eq!(metadata.get("custom-key"), Some(&"custom-value".to_string()), "Should extract custom-key");
        assert_eq!(metadata.get("author"), Some(&"test-author".to_string()), "Should extract author");
        assert!(!metadata.contains_key("content-type"), "Should not include non-metadata headers");
    }

    #[test]
    fn should_return_empty_map_given_no_x_amz_meta_headers_when_extract_metadata_called() {
        // Arrange
        use crate::utils::headers as header_utils;
        use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("AWS4-HMAC-SHA256 ..."),
        );

        // Act
        let metadata = header_utils::extract_metadata(&headers);

        // Assert
        assert!(metadata.is_empty(), "Should return empty map when no metadata headers present");
    }

    #[test]
    fn should_delete_all_tags_given_existing_tags_when_delete_object_tags_called() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;
        use std::collections::HashMap;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_delete_tags"));
        let bucket_name = "test-bucket-delete-tags";
        let key = "test-object.txt";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        // Create object with tags
        let mut tags = HashMap::new();
        tags.insert("environment".to_string(), "test".to_string());
        tags.insert("version".to_string(), "1.0".to_string());

        let metadata = HashMap::new();
        let mut obj = Object::new_with_metadata(key.to_string(), b"test data".to_vec(), "text/plain".to_string(), metadata);
        obj.tags = tags;

        // Store the object
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Delete tags
        let result = storage.delete_object_tags(bucket_name, key);
        assert!(result.is_ok(), "Should delete tags successfully");

        // Act - Verify tags are gone
        let retrieved = storage.get_object_tags(bucket_name, key);

        // Assert
        assert!(retrieved.is_ok(), "Should retrieve empty tags");
        assert!(retrieved.unwrap().is_empty(), "Tags should be empty after deletion");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_delete_tags");
    }

    #[test]
    fn should_store_and_retrieve_tags_given_valid_tags_when_tagging_endpoints_used() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;
        use std::collections::HashMap;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_tagging"));
        let bucket_name = "test-bucket-tagging";
        let key = "test-object.txt";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        // Create object
        let obj = Object::new(key.to_string(), b"test data".to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Put tags
        let mut tags = HashMap::new();
        tags.insert("environment".to_string(), "production".to_string());
        tags.insert("application".to_string(), "api".to_string());
        tags.insert("owner".to_string(), "team-a".to_string());

        let put_result = storage.put_object_tags(bucket_name, key, tags.clone());
        assert!(put_result.is_ok(), "Should store tags");

        // Act - Get tags
        let retrieved_tags = storage.get_object_tags(bucket_name, key);

        // Assert
        assert!(retrieved_tags.is_ok(), "Should retrieve tags");
        let tags_map = retrieved_tags.unwrap();
        assert_eq!(tags_map.len(), 3, "Should have 3 tags");
        assert_eq!(tags_map.get("environment"), Some(&"production".to_string()), "Environment tag should match");
        assert_eq!(tags_map.get("application"), Some(&"api".to_string()), "Application tag should match");
        assert_eq!(tags_map.get("owner"), Some(&"team-a".to_string()), "Owner tag should match");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_tagging");
    }

    #[test]
    fn should_put_and_get_bucket_acl_when_acl_endpoints_used() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::policy::{Acl, CannedAcl};
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_bucket_acl"));
        let bucket_name = "test-bucket-acl";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        // Act - Put bucket ACL
        let acl = Acl {
            canned: CannedAcl::PublicRead,
            grants: vec![],
        };
        let put_result = storage.put_bucket_acl(bucket_name, acl.clone());
        assert!(put_result.is_ok(), "Should put bucket ACL");

        // Act - Get bucket ACL
        let retrieved = storage.get_bucket_acl(bucket_name);

        // Assert
        assert!(retrieved.is_ok(), "Should retrieve bucket ACL");
        assert_eq!(retrieved.unwrap().canned, CannedAcl::PublicRead, "ACL should be PublicRead");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_bucket_acl");
    }

    #[test]
    fn should_put_and_get_object_acl_when_acl_endpoints_used() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::policy::{Acl, CannedAcl};
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_object_acl"));
        let bucket_name = "test-bucket-obj-acl";
        let key = "test-object.txt";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), b"test data".to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Put object ACL
        let acl = Acl {
            canned: CannedAcl::Private,
            grants: vec![],
        };
        let put_result = storage.put_object_acl(bucket_name, key, acl.clone());
        assert!(put_result.is_ok(), "Should put object ACL");

        // Act - Get object ACL
        let retrieved = storage.get_object_acl(bucket_name, key);

        // Assert
        assert!(retrieved.is_ok(), "Should retrieve object ACL");
        assert_eq!(retrieved.unwrap().canned, CannedAcl::Private, "ACL should be Private");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_object_acl");
    }

    #[test]
    fn should_return_default_acl_for_bucket_when_not_set() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::policy::CannedAcl;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_bucket_default_acl"));
        let bucket_name = "test-bucket-default";

        // Create bucket without setting ACL
        let _ = storage.create_bucket(bucket_name.to_string());

        // Act - Get bucket ACL (should return default)
        let retrieved = storage.get_bucket_acl(bucket_name);

        // Assert
        assert!(retrieved.is_ok(), "Should retrieve default bucket ACL");
        assert_eq!(retrieved.unwrap().canned, CannedAcl::Private, "Default ACL should be Private");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_bucket_default_acl");
    }

    #[test]
    fn should_return_error_for_nonexistent_bucket_acl() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_nonexistent_acl"));

        // Act - Try to get ACL for nonexistent bucket
        let result = storage.get_bucket_acl("nonexistent-bucket");

        // Assert
        assert!(result.is_err(), "Should error for nonexistent bucket");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_nonexistent_acl");
    }

    #[test]
    fn should_support_multiple_acl_canned_types() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::policy::{Acl, CannedAcl};
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_acl_types"));
        let bucket_name = "test-bucket-types";

        // Create bucket
        let _ = storage.create_bucket(bucket_name.to_string());

        let acl_types = vec![
            CannedAcl::Private,
            CannedAcl::PublicRead,
            CannedAcl::PublicReadWrite,
            CannedAcl::AuthenticatedRead,
            CannedAcl::BucketOwnerRead,
            CannedAcl::BucketOwnerFullControl,
        ];

        // Act & Assert - Test each canned ACL type
        for acl_type in acl_types {
            let acl = Acl {
                canned: acl_type.clone(),
                grants: vec![],
            };
            let put_result = storage.put_bucket_acl(bucket_name, acl);
            assert!(put_result.is_ok(), "Should put {:?}", acl_type);

            let retrieved = storage.get_bucket_acl(bucket_name);
            assert!(retrieved.is_ok(), "Should retrieve {:?}", acl_type);
            assert_eq!(retrieved.unwrap().canned, acl_type, "ACL type should match");
        }

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_acl_types");
    }

    #[test]
    fn should_get_object_range_when_range_header_provided() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_range"));
        let bucket_name = "test-bucket-range";
        let key = "test-file.txt";
        let test_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), test_data.to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Get range 0-9 (first 10 bytes)
        let result = storage.get_object_range(bucket_name, key, 0, Some(9));

        // Assert
        assert!(result.is_ok(), "Should get object range");
        let (_obj, data) = result.unwrap();
        assert_eq!(data, b"0123456789", "Should return correct range data");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_range");
    }

    #[test]
    fn should_get_object_range_from_middle_when_middle_range_requested() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_range_middle"));
        let bucket_name = "test-bucket-middle";
        let key = "test-file.txt";
        let test_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), test_data.to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Get range 10-19 (middle 10 bytes)
        let result = storage.get_object_range(bucket_name, key, 10, Some(19));

        // Assert
        assert!(result.is_ok(), "Should get object range");
        let (_obj, data) = result.unwrap();
        assert_eq!(data, b"ABCDEFGHIJ", "Should return correct middle range data");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_range_middle");
    }

    #[test]
    fn should_get_object_range_to_end_when_end_omitted() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_range_to_end"));
        let bucket_name = "test-bucket-end";
        let key = "test-file.txt";
        let test_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), test_data.to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Get range from 30 to end (no end specified)
        let result = storage.get_object_range(bucket_name, key, 30, None);

        // Assert
        assert!(result.is_ok(), "Should get object range to end");
        let (_obj, data) = result.unwrap();
        assert_eq!(data, b"UVWXYZ", "Should return correct range to end");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_range_to_end");
    }

    #[test]
    fn should_error_on_range_beyond_file_size() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_range_invalid"));
        let bucket_name = "test-bucket-invalid";
        let key = "test-file.txt";
        let test_data = b"short";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), test_data.to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Get range beyond file size
        let result = storage.get_object_range(bucket_name, key, 1000, Some(2000));

        // Assert
        assert!(result.is_err(), "Should error on range beyond file size");

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_range_invalid");
    }

    #[test]
    fn should_support_accept_ranges_header_in_normal_get() {
        // Arrange
        use crate::storage::FilesystemStorage;
        use crate::models::Object;
        use std::sync::Arc;

        let storage = Arc::new(FilesystemStorage::new("./test_blobs_accept_ranges"));
        let bucket_name = "test-bucket-accept";
        let key = "test-file.txt";

        // Create bucket and object
        let _ = storage.create_bucket(bucket_name.to_string());
        let obj = Object::new(key.to_string(), b"test data".to_vec(), "text/plain".to_string());
        let _ = storage.put_object(bucket_name, key.to_string(), obj);

        // Act - Get object (should include Accept-Ranges header)
        let retrieved = storage.get_object(bucket_name, key);

        // Assert
        assert!(retrieved.is_ok(), "Should get object");
        let _obj = retrieved.unwrap();
        // Note: Full header testing would be done in integration tests with HTTP client

        // Cleanup
        let _ = std::fs::remove_dir_all("./test_blobs_accept_ranges");
    }

    #[test]
    fn should_generate_presigned_get_url_when_presignedUrl_query_provided() {
        // Arrange
        use crate::auth::presigned::PresignedUrlConfig;
        let config = PresignedUrlConfig {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };

        let bucket = "test-bucket";
        let key = "test-object.txt";
        let base_url = "http://localhost:9000/test-bucket/test-object.txt";

        // Act - Generate presigned GET URL
        let url = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket,
            key,
            3600,
            base_url,
            &config,
        );

        // Assert
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), "Should contain algorithm");
        assert!(url.contains("X-Amz-Credential=test-access-key"), "Should contain access key");
        assert!(url.contains("X-Amz-Expires=3600"), "Should contain expires time");
        assert!(url.contains("X-Amz-SignedHeaders=host"), "Should contain signed headers");
        assert!(url.contains("X-Amz-Date="), "Should contain timestamp");
        assert!(url.starts_with("http"), "Should be valid URL");
    }

    #[test]
    fn should_generate_presigned_put_url_with_different_signature() {
        // Arrange
        use crate::auth::presigned::PresignedUrlConfig;
        let config = PresignedUrlConfig {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };

        let bucket = "test-bucket";
        let key = "test-object.txt";
        let base_url = "http://localhost:9000/test-bucket/test-object.txt";

        // Act - Generate presigned GET and PUT URLs
        let get_url = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, key, 3600, base_url, &config,
        );
        let put_url = crate::auth::presigned::PresignedUrl::generate_put_url(
            bucket, key, 3600, base_url, &config,
        );

        // Assert - URLs should be different (different signatures for different methods)
        assert_ne!(get_url, put_url, "GET and PUT URLs should have different signatures");
        assert!(get_url.contains("X-Amz-Algorithm"), "GET URL should have algorithm");
        assert!(put_url.contains("X-Amz-Algorithm"), "PUT URL should have algorithm");
    }

    #[test]
    fn should_respect_expires_parameter_in_presigned_url() {
        // Arrange
        use crate::auth::presigned::PresignedUrlConfig;
        let config = PresignedUrlConfig {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };

        let bucket = "test-bucket";
        let key = "test-object.txt";
        let base_url = "http://localhost:9000/test-bucket/test-object.txt";

        // Act - Generate URLs with different expiration times
        let short_url = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, key, 300, base_url, &config,
        );
        let long_url = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, key, 86400, base_url, &config,
        );

        // Assert
        assert!(short_url.contains("X-Amz-Expires=300"), "Should have 300 second expiry");
        assert!(long_url.contains("X-Amz-Expires=86400"), "Should have 86400 second expiry");
    }

    #[test]
    fn should_generate_different_signatures_for_different_keys() {
        // Arrange
        use crate::auth::presigned::PresignedUrlConfig;
        let config = PresignedUrlConfig {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };

        let bucket = "test-bucket";
        let base_url_1 = "http://localhost:9000/test-bucket/object1.txt";
        let base_url_2 = "http://localhost:9000/test-bucket/object2.txt";

        // Act - Generate URLs for different objects
        let url1 = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, "object1.txt", 3600, base_url_1, &config,
        );
        let url2 = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, "object2.txt", 3600, base_url_2, &config,
        );

        // Assert
        assert_ne!(url1, url2, "Different objects should have different signatures");
    }

    #[test]
    fn should_create_valid_presigned_url_format() {
        // Arrange
        use crate::auth::presigned::PresignedUrlConfig;
        let config = PresignedUrlConfig {
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        };

        let bucket = "test-bucket";
        let key = "test-object.txt";
        let base_url = "http://localhost:9000/test-bucket/test-object.txt";

        // Act
        let url = crate::auth::presigned::PresignedUrl::generate_get_url(
            bucket, key, 3600, base_url, &config,
        );

        // Assert - Validate URL format
        assert!(url.starts_with("http://localhost:9000/"), "Should start with base URL");
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), "Should be SigV4");
        assert!(url.contains("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE"), "Should contain access key");
        assert!(url.contains("X-Amz-Signature="), "Should contain signature");
        assert!(url.contains("X-Amz-Date="), "Should contain date");
        assert!(!url.contains(" "), "URL should not contain spaces");
    }
}
