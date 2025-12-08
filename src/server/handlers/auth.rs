use super::ResponseBuilder;
use crate::auth::{AuthConfig, AuthInfo, SigV4Config, SignatureVerifier};
use crate::models::policy::{AuthContext, Authorizer, PolicyEffect};
use crate::models::Owner;
use crate::storage::Storage;
use crate::utils::{headers as header_utils, xml as xml_utils};
use hex;
use http::StatusCode;
use hyper::{Body, Response};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::warn;

fn default_owner(config: &AuthConfig) -> Owner {
    let owner = config
        .access_key()
        .map(|k| k.to_string())
        .unwrap_or_else(|| "peas-emulator".to_string());

    Owner {
        id: owner.clone(),
        display_name: owner,
    }
}

/// Verify SigV4 signature in the request
#[allow(clippy::result_large_err)]
pub(crate) fn verify_sigv4_signature(
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

    let signed_headers = match extract_signed_headers(auth_header) {
        Some(headers) if !headers.is_empty() => headers,
        _ => {
            let xml = xml_utils::error_xml(
                "InvalidRequest",
                "Missing signed headers in authorization header",
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

    let canonical_request = build_canonical_request(req, &signed_headers);
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

/// Verify presigned URL query parameters
#[allow(clippy::result_large_err)]
pub(crate) fn verify_presigned_url(
    req: &crate::server::http::Request,
    bucket: &str,
    key: &str,
    auth_config: &AuthConfig,
) -> Result<bool, Response<Body>> {
    if !auth_config.enforce_auth {
        return Ok(true);
    }

    let query_params = &req.query_params;

    // Check if this is a presigned URL request
    let has_presigned_query = query_params.contains_key("X-Amz-Signature")
        || query_params.contains_key("Signature");

    if !has_presigned_query {
        return Ok(true);
    }

    let req_id = header_utils::generate_request_id();

    // Parse presigned URL parameters
    match crate::auth::PresignedUrl::from_query_params(bucket, key, &req.method().to_string(), query_params) {
        Ok(presigned) => {
            // Get the host from request headers
            let host = req
                .header("host")
                .unwrap_or("localhost:9000")
                .to_string();

            // Get secret key for validation
            let secret_key = match auth_config.secret_key() {
                Some(key) => key,
                None => {
                    warn!(
                        "Presigned URL validation requested but no secret key configured"
                    );
                    return Ok(true);
                }
            };

            let presigned_config = crate::auth::PresignedUrlConfig {
                access_key: auth_config
                    .access_key()
                    .unwrap_or("peas-emulator")
                    .to_string(),
                secret_key: secret_key.to_string(),
            };

            // Validate the presigned URL
            if let Err(e) = presigned.validate(&host, &presigned_config) {
                warn!("Presigned URL validation failed: {}", e);
                let xml = xml_utils::error_xml(
                    "InvalidSignature",
                    &format!("Presigned URL validation failed: {}", e),
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
        Err(e) => {
            warn!("Failed to parse presigned URL: {}", e);
            let xml = xml_utils::error_xml(
                "InvalidRequest",
                &format!("Invalid presigned URL parameters: {}", e),
                &req_id,
            );
            let resp = ResponseBuilder::new(StatusCode::BAD_REQUEST)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes());
            Err(resp.build())
        }
    }
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

/// Extract the SignedHeaders list from SigV4 Authorization header
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn extract_signed_headers(auth_header: &str) -> Option<Vec<String>> {
    for part in auth_header.split(',') {
        let part = part.trim();
        if let Some(headers) = part.strip_prefix("SignedHeaders=") {
            let parsed: Vec<String> = headers
                .split(';')
                .map(|h| h.trim().to_lowercase())
                .filter(|h| !h.is_empty())
                .collect();
            return Some(parsed);
        }
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Build canonical request for SigV4 verification using the same rules as the TS SDK signer
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn build_canonical_request(
    req: &dyn crate::auth::HttpRequestLike,
    signed_headers: &[String],
) -> String {
    let method = req.method();

    // The TS SDK signer builds the canonical URI as `pathname + search` and leaves the canonical
    // query string blank, so we must mirror that behavior exactly here.
    let path = req.path();
    let path_with_query = if let Some(q) = req.query() {
        if q.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, q)
        }
    } else {
        path.to_string()
    };

    // Canonical headers: lower-case, trimmed, single-spaced, in the SignedHeaders order.
    let mut canonical_headers: Vec<String> = signed_headers
        .iter()
        .map(|name| {
            let value = req.header(name).unwrap_or("");
            let normalized_value = value
                .trim()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            format!("{}:{}", name, normalized_value)
        })
        .collect();

    // Ensure deterministic ordering; the signer already sorts the names, but sort again for safety.
    canonical_headers.sort();

    let canonical_headers_str = canonical_headers.join("\n");
    let signed_headers_str = {
        let mut names = signed_headers.to_vec();
        names.sort();
        names.join(";")
    };

    let payload_hash = sha256_hex(req.body());

    format!(
        "{}\n{}\n\n{}\n\n{}\n{}",
        method, path_with_query, canonical_headers_str, signed_headers_str, payload_hash
    )
}

/// Check if the request is authorized to perform the action
#[allow(clippy::result_large_err)]
pub(crate) fn check_authorization(
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

    let owner_id = default_owner(auth_config).id;
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
