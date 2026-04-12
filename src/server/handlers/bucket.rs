use super::auth::check_authorization;
use super::ResponseBuilder;
use crate::auth::AuthConfig;
use crate::services::{
    bucket as bucket_service, empty_success_response, object as object_service,
    storage_error_response, xml_error_response, xml_success_response,
};
use crate::storage::Storage;
use crate::utils::{headers as header_utils, validation, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::sync::Arc;

fn escape_xml_str(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
}

fn parse_delete_keys(xml: &str) -> Vec<(String, Option<String>)> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut in_key = false;
    let mut in_version = false;
    let mut current_key: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut objects = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Key" => in_key = true,
                b"VersionId" => in_version = true,
                _ => {}
            },
            Ok(Event::Text(t)) => {
                if in_key {
                    current_key = Some(t.unescape().unwrap_or_default().to_string());
                } else if in_version {
                    current_version = Some(t.unescape().unwrap_or_default().to_string());
                }
            }
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"Key" => in_key = false,
                b"VersionId" => in_version = false,
                b"Object" => {
                    if let Some(k) = current_key.take() {
                        objects.push((k, current_version.take()));
                    } else {
                        current_version = None;
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    objects
}

const S3_REQUEST_PAYMENT_KEY: &str = "s3_requester_pays";
const S3_WEBSITE_XML_KEY: &str = "s3_website_xml";
const S3_CORS_XML_KEY: &str = "s3_cors_xml";

fn bucket_get_action(req: &crate::server::http::Request) -> &'static str {
    if req.has_query_param("requestPayment") {
        "s3:GetBucketRequestPayment"
    } else if req.has_query_param("website") {
        "s3:GetBucketWebsite"
    } else if req.has_query_param("cors") {
        "s3:GetBucketCors"
    } else if req.has_query_param("lifecycle") {
        "s3:GetLifecycleConfiguration"
    } else if req.has_query_param("policy") {
        "s3:GetBucketPolicy"
    } else if req.has_query_param("acl") {
        "s3:GetBucketAcl"
    } else if req.has_query_param("versioning") {
        "s3:GetBucketVersioning"
    } else if req.has_query_param("uploads") {
        "s3:ListBucketMultipartUploads"
    } else if req.has_query_param("versions") {
        "s3:ListBucketVersions"
    } else {
        "s3:ListBucket"
    }
}

fn metadata_value(xml: &str, tag: &[u8]) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut in_tag = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == tag => in_tag = true,
            Ok(Event::End(e)) if e.name().as_ref() == tag => in_tag = false,
            Ok(Event::Text(t)) if in_tag => {
                return Some(t.unescape().unwrap_or_default().to_string());
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    None
}

fn parse_multipart_form_upload(
    content_type: &str,
    body: &[u8],
) -> Option<(String, Vec<u8>, String)> {
    let boundary = content_type
        .split(';')
        .map(|part| part.trim())
        .find_map(|part| part.strip_prefix("boundary="))?;
    let boundary_marker = format!("--{}", boundary);
    let boundary_bytes = boundary_marker.as_bytes();

    let mut key: Option<String> = None;
    let mut file: Option<Vec<u8>> = None;
    let mut file_content_type = "application/octet-stream".to_string();

    for raw_part in split_bytes(body, boundary_bytes) {
        let part = raw_part.strip_prefix(b"\r\n").unwrap_or(raw_part);
        if part.is_empty() || part == b"--\r\n" || part == b"--" {
            continue;
        }
        let part = part
            .strip_suffix(b"--\r\n")
            .or_else(|| part.strip_suffix(b"--"))
            .unwrap_or(part);
        let Some((raw_headers, raw_body)) = split_once_bytes(part, b"\r\n\r\n") else {
            continue;
        };
        let field_body = raw_body.strip_suffix(b"\r\n").unwrap_or(raw_body);
        let raw_headers = std::str::from_utf8(raw_headers).ok()?;

        let mut field_name: Option<String> = None;
        let mut filename: Option<String> = None;
        for header in raw_headers.split("\r\n") {
            let lower = header.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                for token in header.split(';').skip(1).map(|token| token.trim()) {
                    if let Some(name) = token.strip_prefix("name=\"") {
                        field_name = Some(name.trim_end_matches('"').to_string());
                    } else if let Some(name) = token.strip_prefix("filename=\"") {
                        filename = Some(name.trim_end_matches('"').to_string());
                    }
                }
            } else if lower.starts_with("content-type:") {
                file_content_type = header
                    .split_once(':')
                    .map(|(_, value)| value.trim().to_string())
                    .unwrap_or_else(|| "application/octet-stream".to_string());
            }
        }

        match field_name.as_deref() {
            Some("key") => key = Some(String::from_utf8(field_body.to_vec()).ok()?),
            Some("file") if filename.is_some() => file = Some(field_body.to_vec()),
            _ => {}
        }
    }

    Some((key?, file?, file_content_type))
}

fn split_bytes<'a>(haystack: &'a [u8], needle: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;

    while let Some(offset) = find_subslice(&haystack[start..], needle) {
        let end = start + offset;
        parts.push(&haystack[start..end]);
        start = end + needle.len();
    }

    parts.push(&haystack[start..]);
    parts
}

fn split_once_bytes<'a>(haystack: &'a [u8], needle: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let index = find_subslice(haystack, needle)?;
    Some((&haystack[..index], &haystack[index + needle.len()..]))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack.windows(needle.len()).position(|window| window == needle)
}

fn with_bucket_metadata<F>(
    storage: &dyn Storage,
    bucket: &str,
    update: F,
) -> crate::error::Result<crate::models::Bucket>
where
    F: FnOnce(&mut std::collections::HashMap<String, String>),
{
    let mut bucket_record = bucket_service::get_bucket(storage, bucket)?;
    update(&mut bucket_record.metadata);
    bucket_service::update_bucket_metadata(storage, bucket, bucket_record.metadata)
}

fn build_list_objects_v2_entries(
    objects: Vec<crate::models::Object>,
    prefix: &str,
    delimiter: Option<&str>,
) -> Vec<xml_utils::ListObjectsV2Entry> {
    let mut entries = Vec::new();
    let mut seen_common_prefixes = std::collections::HashSet::new();
    let delimiter = delimiter.filter(|value| !value.is_empty());

    for object in objects {
        if let Some(delimiter) = delimiter {
            if let Some(stripped_key) = object.key.strip_prefix(prefix) {
                if let Some(index) = stripped_key.find(delimiter) {
                    let common_prefix =
                        format!("{}{}", prefix, &stripped_key[..index + delimiter.len()]);
                    if seen_common_prefixes.insert(common_prefix.clone()) {
                        entries.push(xml_utils::ListObjectsV2Entry::CommonPrefix(common_prefix));
                    }
                    continue;
                }
            }
        }

        entries.push(xml_utils::ListObjectsV2Entry::Object(object));
    }

    entries
}

fn list_objects_v2_start_index(
    entries: &[xml_utils::ListObjectsV2Entry],
    continuation_token: Option<&str>,
    start_after: Option<&str>,
) -> usize {
    if let Some(token) = continuation_token {
        if let Some(position) = entries.iter().position(|entry| entry.token() == token) {
            return position + 1;
        }

        if let Some(position) = entries.iter().position(|entry| entry.token() > token) {
            return position;
        }

        return entries.len();
    }

    if let Some(start_after) = start_after {
        return entries
            .iter()
            .position(|entry| entry.token() > start_after)
            .unwrap_or(entries.len());
    }

    0
}

pub async fn list_buckets(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    req: crate::server::http::Request,
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

    let buckets = tokio::task::block_in_place(|| bucket_service::list_buckets(storage.as_ref()))?;
    let xml = xml_utils::list_buckets_xml(&buckets);

    Ok(xml_success_response(StatusCode::OK, xml, &req_id))
}

pub async fn bucket_head(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(req, &auth_config, &storage, bucket, None, "s3:ListBucket") {
        return Ok(response);
    }

    match tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket)) {
        Ok(_) => Ok(empty_success_response(StatusCode::OK, &req_id)),
        Err(e) => Ok(storage_error_response(&e, &req_id)),
    }
}

pub async fn bucket_delete(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    let action = if req.has_query_param("lifecycle") {
        "s3:DeleteLifecycleConfiguration"
    } else if req.has_query_param("policy") {
        "s3:DeleteBucketPolicy"
    } else if req.has_query_param("website") {
        "s3:DeleteBucketWebsite"
    } else if req.has_query_param("cors") {
        "s3:DeleteBucketCors"
    } else {
        "s3:DeleteBucket"
    };

    if let Err(response) = check_authorization(req, &auth_config, &storage, bucket, None, action) {
        return Ok(response);
    }

    if req.has_query_param("website") {
        match tokio::task::block_in_place(|| {
            with_bucket_metadata(storage.as_ref(), bucket, |metadata| {
                metadata.remove(S3_WEBSITE_XML_KEY);
            })
        }) {
            Ok(_) => Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id)),
            Err(e) => Ok(storage_error_response(&e, &req_id)),
        }
    } else if req.has_query_param("cors") {
        match tokio::task::block_in_place(|| {
            with_bucket_metadata(storage.as_ref(), bucket, |metadata| {
                metadata.remove(S3_CORS_XML_KEY);
            })
        }) {
            Ok(_) => Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id)),
            Err(e) => Ok(storage_error_response(&e, &req_id)),
        }
    } else if req.has_query_param("lifecycle") {
        match tokio::task::block_in_place(|| {
            bucket_service::delete_bucket_lifecycle(storage.as_ref(), bucket)
        }) {
            Ok(_) => Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id)),
            Err(e) => Ok(storage_error_response(&e, &req_id)),
        }
    } else if req.has_query_param("policy") {
        match tokio::task::block_in_place(|| {
            bucket_service::delete_bucket_policy(storage.as_ref(), bucket)
        }) {
            Ok(_) => Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id)),
            Err(e) => Ok(storage_error_response(&e, &req_id)),
        }
    } else if req.has_query_param("versioning") || req.has_query_param("acl") {
        Ok(xml_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Cannot delete versioning or ACL via DELETE",
            &req_id,
        ))
    } else {
        tokio::task::block_in_place(|| bucket_service::delete_bucket(storage.as_ref(), bucket))?;
        Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id))
    }
}

#[allow(clippy::needless_return)]
pub async fn bucket_put(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    let action = if req.has_query_param("versioning") {
        "s3:PutBucketVersioning"
    } else if req.has_query_param("lifecycle") {
        "s3:PutLifecycleConfiguration"
    } else if req.has_query_param("requestPayment") {
        "s3:PutBucketRequestPayment"
    } else if req.has_query_param("website") {
        "s3:PutBucketWebsite"
    } else if req.has_query_param("cors") {
        "s3:PutBucketCors"
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
        return Ok(xml_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            &e,
            &req_id,
        ));
    }

    if req.has_query_param("lifecycle") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let cfg = match xml_utils::parse_lifecycle_xml(&body) {
            Ok(c) => c,
            Err(msg) => {
                return Ok(xml_error_response(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &msg,
                    &req_id,
                ));
            }
        };

        match tokio::task::block_in_place(|| {
            bucket_service::put_bucket_lifecycle(storage.as_ref(), bucket, cfg)
        }) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(crate::error::Error::BucketNotFound) => Ok(xml_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "Bucket not found",
                &req_id,
            )),
            Err(e) => Ok(xml_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
                &req_id,
            )),
        }
    } else if req.has_query_param("requestPayment") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let payer = metadata_value(&body, b"Payer").unwrap_or_default();
        if payer != "Requester" && payer != "BucketOwner" {
            return Ok(xml_error_response(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "RequestPaymentConfiguration must contain a valid Payer value",
                &req_id,
            ));
        }

        match tokio::task::block_in_place(|| {
            with_bucket_metadata(storage.as_ref(), bucket, |metadata| {
                metadata.insert(S3_REQUEST_PAYMENT_KEY.to_string(), payer);
            })
        }) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(crate::error::Error::BucketNotFound) => Ok(xml_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "Bucket not found",
                &req_id,
            )),
            Err(e) => Ok(xml_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
                &req_id,
            )),
        }
    } else if req.has_query_param("website") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        match tokio::task::block_in_place(|| {
            with_bucket_metadata(storage.as_ref(), bucket, |metadata| {
                metadata.insert(S3_WEBSITE_XML_KEY.to_string(), body);
            })
        }) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(crate::error::Error::BucketNotFound) => Ok(xml_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "Bucket not found",
                &req_id,
            )),
            Err(e) => Ok(xml_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
                &req_id,
            )),
        }
    } else if req.has_query_param("cors") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        match tokio::task::block_in_place(|| {
            with_bucket_metadata(storage.as_ref(), bucket, |metadata| {
                metadata.insert(S3_CORS_XML_KEY.to_string(), body);
            })
        }) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(crate::error::Error::BucketNotFound) => Ok(xml_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "Bucket not found",
                &req_id,
            )),
            Err(e) => Ok(xml_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
                &req_id,
            )),
        }
    } else if req.has_query_param("versioning") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let enabled = match xml_utils::parse_versioning_xml(&body) {
            Ok(e) => e,
            Err(msg) => {
                return Ok(xml_error_response(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &msg,
                    &req_id,
                ));
            }
        };
        if enabled {
            match tokio::task::block_in_place(|| {
                bucket_service::set_versioning(storage.as_ref(), bucket, true)
            }) {
                Ok(_) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .empty())
                }
                Err(crate::error::Error::BucketNotFound) => {
                    return Ok(xml_error_response(
                        StatusCode::NOT_FOUND,
                        "NoSuchBucket",
                        "Bucket not found",
                        &req_id,
                    ));
                }
                Err(e) => {
                    return Ok(xml_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                        &req_id,
                    ));
                }
            }
        } else {
            match tokio::task::block_in_place(|| {
                bucket_service::set_versioning(storage.as_ref(), bucket, false)
            }) {
                Ok(_) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .empty())
                }
                Err(crate::error::Error::BucketNotFound) => {
                    return Ok(xml_error_response(
                        StatusCode::NOT_FOUND,
                        "NoSuchBucket",
                        "Bucket not found",
                        &req_id,
                    ));
                }
                Err(e) => {
                    return Ok(xml_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &e.to_string(),
                        &req_id,
                    ));
                }
            }
        }
    } else if req.has_query_param("acl") {
        let canned_acl_str = req.header("x-amz-acl").unwrap_or("private");
        let canned_acl: crate::models::policy::CannedAcl =
            serde_json::from_value(serde_json::json!(canned_acl_str)).unwrap_or_default();
        let acl = crate::models::policy::Acl {
            canned: canned_acl,
            grants: vec![],
        };
        match tokio::task::block_in_place(|| {
            bucket_service::put_bucket_acl(storage.as_ref(), bucket, acl)
        }) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty())
            }
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("policy") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let policy: crate::models::policy::BucketPolicyDocument =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON policy: {}", e))?;
        match tokio::task::block_in_place(|| {
            bucket_service::put_bucket_policy(storage.as_ref(), bucket, policy)
        }) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty())
            }
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else {
        tokio::task::block_in_place(|| {
            bucket_service::create_bucket(storage.as_ref(), bucket.to_string())
        })?;
        Ok(ResponseBuilder::new(StatusCode::OK)
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty())
    }
}

#[allow(clippy::needless_return)]
pub async fn bucket_get_or_list_objects(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if let Err(response) = check_authorization(
        req,
        &auth_config,
        &storage,
        bucket,
        None,
        bucket_get_action(req),
    ) {
        return Ok(response);
    }

    if req.has_query_param("requestPayment") {
        match tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket)) {
            Ok(bucket_record) => {
                let payer = bucket_record
                    .metadata
                    .get(S3_REQUEST_PAYMENT_KEY)
                    .map(|value| value.as_str())
                    .unwrap_or("BucketOwner");
                let xml = format!(
                    "{}\n<RequestPaymentConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n  <Payer>{}</Payer>\n</RequestPaymentConfiguration>",
                    xml_utils::xml_declaration(),
                    payer
                );
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("website") {
        match tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket)) {
            Ok(bucket_record) => match bucket_record.metadata.get(S3_WEBSITE_XML_KEY) {
                Some(xml) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .content_type("application/xml; charset=utf-8")
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .body(xml.clone().into_bytes())
                        .build());
                }
                None => {
                    return Ok(xml_error_response(
                        StatusCode::NOT_FOUND,
                        "NoSuchWebsiteConfiguration",
                        "The specified bucket does not have a website configuration",
                        &req_id,
                    ))
                }
            },
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("cors") {
        match tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket)) {
            Ok(bucket_record) => match bucket_record.metadata.get(S3_CORS_XML_KEY) {
                Some(xml) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .content_type("application/xml; charset=utf-8")
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .body(xml.clone().into_bytes())
                        .build());
                }
                None => {
                    return Ok(xml_error_response(
                        StatusCode::NOT_FOUND,
                        "NoSuchCORSConfiguration",
                        "The CORS configuration does not exist",
                        &req_id,
                    ))
                }
            },
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("lifecycle") {
        match tokio::task::block_in_place(|| {
            bucket_service::get_bucket_lifecycle(storage.as_ref(), bucket)
        }) {
            Ok(cfg) => {
                let xml = xml_utils::lifecycle_xml(&cfg);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(crate::error::Error::KeyNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchLifecycleConfiguration",
                    "No lifecycle configuration present",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("policy") {
        match tokio::task::block_in_place(|| {
            bucket_service::get_bucket_policy(storage.as_ref(), bucket)
        }) {
            Ok(policy) => {
                let json = serde_json::to_string(&policy)
                    .map_err(|e| format!("JSON serialization error: {}", e))?;
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/json; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(json.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml(
                    "NoSuchBucketPolicy",
                    "The bucket policy does not exist",
                    &req_id,
                );
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    } else if req.has_query_param("acl") {
        match tokio::task::block_in_place(|| {
            bucket_service::get_bucket_acl(storage.as_ref(), bucket)
        }) {
            Ok(acl) => {
                let owner = crate::models::policy::Owner {
                    id: "peas-emulator".to_string(),
                    display_name: "S3 Emulator".to_string(),
                };
                let xml = xml_utils::acl_xml(&owner, &acl);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ))
            }
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &e.to_string(),
                    &req_id,
                ))
            }
        }
    } else if req.has_query_param("versioning") {
        match tokio::task::block_in_place(|| bucket_service::get_bucket(storage.as_ref(), bucket)) {
            Ok(b) => {
                let status = if b.versioning_enabled {
                    Some("Enabled")
                } else {
                    Some("Suspended")
                };
                let xml = xml_utils::versioning_status_xml(status);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    } else if req.has_query_param("uploads") {
        match tokio::task::block_in_place(|| {
            bucket_service::list_multipart_uploads(storage.as_ref(), bucket)
        }) {
            Ok(uploads) => {
                let xml = xml_utils::list_multipart_uploads_xml(&uploads, bucket);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::NoSuchUpload) => {
                let xml = xml_utils::error_xml("NoSuchUpload", "Upload not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    } else if req.has_query_param("versions") {
        let prefix = req.query_param("prefix");
        let key_marker = req.query_param("key-marker");
        let version_id_marker = req.query_param("version-id-marker");
        let max_keys = req
            .query_param("max-keys")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1000);

        match tokio::task::block_in_place(|| {
            object_service::list_object_versions(storage.as_ref(), bucket, prefix)
        }) {
            Ok(mut versions) => {
                versions.sort_by(|left, right| {
                    right
                        .last_modified
                        .cmp(&left.last_modified)
                        .then_with(|| left.key.cmp(&right.key))
                        .then_with(|| left.version_id.cmp(&right.version_id))
                });

                let truncated = versions.len() > max_keys;
                if truncated {
                    versions.truncate(max_keys);
                }

                let next_key_marker = if truncated {
                    versions.last().map(|version| version.key.as_str())
                } else {
                    None
                };
                let next_version_id_marker = if truncated {
                    versions
                        .last()
                        .and_then(|version| version.version_id.as_deref())
                } else {
                    None
                };

                let xml = xml_utils::list_versions_xml(
                    bucket,
                    &versions,
                    prefix.unwrap_or(""),
                    key_marker,
                    version_id_marker,
                    max_keys,
                    truncated,
                    next_key_marker,
                    next_version_id_marker,
                );

                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    } else if req.query_param("list-type") == Some("2") {
        let prefix = req.query_param("prefix").unwrap_or("");
        let delimiter = req
            .query_param("delimiter")
            .filter(|value| !value.is_empty());
        let continuation_token = req
            .query_param("continuation-token")
            .filter(|value| !value.is_empty());
        let start_after = req
            .query_param("start-after")
            .filter(|value| !value.is_empty());
        let max_keys = req
            .query_param("max-keys")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1000);
        let encoding_type = req.query_param("encoding-type");
        let fetch_owner = matches!(
            req.query_param("fetch-owner"),
            Some(value) if value.is_empty() || value.eq_ignore_ascii_case("true")
        );

        match tokio::task::block_in_place(|| {
            object_service::list_objects(storage.as_ref(), bucket, Some(prefix), None, None, None)
        }) {
            Ok(result) => {
                let entries = build_list_objects_v2_entries(result.objects, prefix, delimiter);
                let start_index =
                    list_objects_v2_start_index(&entries, continuation_token, start_after);
                let page_end = (start_index.saturating_add(max_keys)).min(entries.len());
                let page_entries = if start_index < entries.len() {
                    &entries[start_index..page_end]
                } else {
                    &entries[0..0]
                };
                let truncated = page_end < entries.len();
                let next_continuation_token = if truncated {
                    if page_end > start_index {
                        Some(page_entries.last().unwrap().token())
                    } else {
                        Some(entries[start_index].token())
                    }
                } else {
                    None
                };

                let xml = xml_utils::list_objects_v2_xml(
                    page_entries,
                    bucket,
                    prefix,
                    delimiter,
                    max_keys,
                    page_entries.len(),
                    truncated,
                    continuation_token,
                    next_continuation_token,
                    start_after,
                    encoding_type,
                    fetch_owner,
                );

                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(e) => {
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    }

    // Default: List objects
    let prefix = req.query_param("prefix");
    let delimiter = req.query_param("delimiter");
    let marker = req.query_param("marker");
    let max_keys = req
        .query_param("max-keys")
        .and_then(|s| s.parse::<usize>().ok());

    match tokio::task::block_in_place(|| {
        object_service::list_objects(
            storage.as_ref(),
            bucket,
            prefix,
            delimiter,
            marker,
            max_keys,
        )
    }) {
        Ok(mut result) => {
            // Filter out expired objects (lifecycle eager enforcement)
            result.objects.retain(|obj| {
                match tokio::task::block_in_place(|| {
                    crate::lifecycle::check_object_expiration(&storage, bucket, &obj.key)
                }) {
                    Ok(is_expired) => !is_expired,
                    Err(_) => true,
                }
            });

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
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Multi-object delete: POST /bucket?delete
    if req.has_query_param("delete") {
        if !tokio::task::block_in_place(|| bucket_service::bucket_exists(storage.as_ref(), bucket))?
        {
            let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
            return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build());
        }

        let body_str = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let objects = parse_delete_keys(&body_str);

        for (key, _) in &objects {
            if let Err(response) = check_authorization(
                req,
                &auth_config,
                &storage,
                bucket,
                Some(key.as_str()),
                "s3:DeleteObject",
            ) {
                return Ok(response);
            }
        }

        for (key, version) in &objects {
            let _ = tokio::task::block_in_place(|| {
                if let Some(v) = version {
                    object_service::delete_object_version(storage.as_ref(), bucket, key, v)
                } else {
                    object_service::delete_object(storage.as_ref(), bucket, key)
                }
            });
        }

        let mut resp_xml = xml_utils::xml_declaration();
        resp_xml.push_str("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
        for (key, version) in objects {
            resp_xml.push_str("<Deleted>");
            resp_xml.push_str(&format!("<Key>{}</Key>", escape_xml_str(&key)));
            if let Some(v) = version {
                resp_xml.push_str(&format!("<VersionId>{}</VersionId>", escape_xml_str(&v)));
            }
            resp_xml.push_str("</Deleted>");
        }
        resp_xml.push_str("</DeleteResult>");

        return Ok(ResponseBuilder::new(StatusCode::OK)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .body(resp_xml.into_bytes())
            .build());
    }

    if let Some(content_type) = req.header("content-type") {
        if content_type.starts_with("multipart/form-data") {
            if !tokio::task::block_in_place(|| bucket_service::bucket_exists(storage.as_ref(), bucket))?
            {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchBucket",
                    "Bucket not found",
                    &req_id,
                ));
            }

            if let Some((key, data, file_content_type)) =
                parse_multipart_form_upload(content_type, &req.body)
            {
                if let Err(response) = check_authorization(
                    req,
                    &auth_config,
                    &storage,
                    bucket,
                    Some(key.as_str()),
                    "s3:PutObject",
                ) {
                    return Ok(response);
                }

                let object = crate::models::Object::new(
                    key.clone(),
                    data,
                    file_content_type,
                );
                tokio::task::block_in_place(|| {
                    object_service::put_object(storage.as_ref(), bucket, key.clone(), object)
                })?;

                return Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                    .header("Location", &format!("/{}/{}", bucket, key))
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
            }

            return Ok(xml_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Unable to parse multipart form upload",
                &req_id,
            ));
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::models::Object;
    use crate::server::RequestExt;
    use crate::storage::FilesystemStorage;
    use chrono::{TimeZone, Utc};
    use hyper::{Body, Request as HyperRequest, StatusCode};
    use std::fs;
    use std::sync::Arc;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir =
            std::env::temp_dir().join(format!("peas-list-versions-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    fn auth_disabled_config() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: std::time::Duration::from_secs(3600),
            api_port: 9000,
            ui_port: 9001,
        })
    }

    fn auth_enabled_config() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: Some("test-access-key".to_string()),
            secret_access_key: Some("test-secret-key".to_string()),
            enforce_auth: true,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: std::time::Duration::from_secs(3600),
            api_port: 9000,
            ui_port: 9001,
        })
    }

    async fn parsed_request(uri: &str) -> RequestExt {
        let request = HyperRequest::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");

        RequestExt::from_hyper(request)
            .await
            .expect("request should parse")
    }

    async fn parsed_request_with_method(method: &str, uri: &str, body: &[u8]) -> RequestExt {
        let request = HyperRequest::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body.to_vec()))
            .expect("request should build");

        RequestExt::from_hyper(request)
            .await
            .expect("request should parse")
    }

    async fn browser_upload_request(
        boundary: &str,
        key: &str,
        file_content_type: &str,
        file_name: &str,
        file_data: &[u8],
    ) -> RequestExt {
        let mut body = Vec::new();
        body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{key}\r\n"
        )
        .as_bytes());
        body.extend_from_slice(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\nContent-Type: {file_content_type}\r\n\r\n"
        )
        .as_bytes());
        body.extend_from_slice(file_data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        RequestExt::from_hyper(
            HyperRequest::builder()
                .method("POST")
                .uri("http://localhost/bucket")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .expect("request should build"),
        )
        .await
        .expect("request should parse")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_list_version_history_when_versions_query_is_requested() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();
        storage.enable_versioning("bucket").unwrap();

        let mut first = Object::new(
            "doc.txt".to_string(),
            b"v1".to_vec(),
            "text/plain".to_string(),
        );
        first.last_modified = Utc.with_ymd_and_hms(2024, 4, 10, 12, 0, 0).unwrap();
        storage
            .put_object("bucket", "doc.txt".to_string(), first)
            .unwrap();

        let first_version_id = storage
            .get_object("bucket", "doc.txt")
            .unwrap()
            .version_id
            .clone()
            .expect("first version id should exist");

        let mut second = Object::new(
            "doc.txt".to_string(),
            b"v2".to_vec(),
            "text/plain".to_string(),
        );
        second.last_modified = Utc.with_ymd_and_hms(2024, 4, 10, 12, 5, 0).unwrap();
        storage
            .put_object("bucket", "doc.txt".to_string(), second)
            .unwrap();

        let current_version_id = storage
            .get_object("bucket", "doc.txt")
            .unwrap()
            .version_id
            .clone()
            .expect("current version id should exist");

        let req = parsed_request("http://localhost/bucket?versions").await;

        // Act
        let resp = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &req,
            "req-129".to_string(),
        )
        .await
        .expect("versions listing should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        let body = String::from_utf8(body.to_vec()).expect("body should be utf8");
        assert!(body.contains("<ListVersionsResult"));
        assert!(body.contains(&first_version_id));
        assert!(body.contains(&current_version_id));
        assert!(body.contains("<IsLatest>true</IsLatest>"));
        assert!(body.contains("doc.txt"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_list_objects_v2_with_continuation_token_when_list_type_two_is_requested() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        for (key, payload) in [
            ("alpha.txt", b"alpha".as_slice()),
            ("beta.txt", b"beta".as_slice()),
            ("gamma.txt", b"gamma".as_slice()),
        ] {
            storage
                .put_object(
                    "bucket",
                    key.to_string(),
                    Object::new(key.to_string(), payload.to_vec(), "text/plain".to_string()),
                )
                .unwrap();
        }

        let first_req = parsed_request("http://localhost/bucket?list-type=2&max-keys=2").await;

        // Act
        let first_resp = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &first_req,
            "req-130".to_string(),
        )
        .await
        .expect("first listing should complete");

        // Assert
        assert_eq!(first_resp.status(), StatusCode::OK);

        let first_body = hyper::body::to_bytes(first_resp.into_body())
            .await
            .expect("body should read");
        let first_body = String::from_utf8(first_body.to_vec()).expect("body should be utf8");
        assert!(first_body.contains("<ListBucketResult"));
        assert!(first_body.contains("<KeyCount>2</KeyCount>"));
        assert!(first_body.contains("<IsTruncated>true</IsTruncated>"));
        assert!(first_body.contains("<NextContinuationToken>beta.txt</NextContinuationToken>"));
        assert!(first_body.contains("alpha.txt"));
        assert!(first_body.contains("beta.txt"));

        let second_req =
            parsed_request("http://localhost/bucket?list-type=2&continuation-token=beta.txt").await;
        let second_resp = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &second_req,
            "req-131".to_string(),
        )
        .await
        .expect("second listing should complete");

        assert_eq!(second_resp.status(), StatusCode::OK);

        let second_body = hyper::body::to_bytes(second_resp.into_body())
            .await
            .expect("body should read");
        let second_body = String::from_utf8(second_body.to_vec()).expect("body should be utf8");
        assert!(second_body.contains("<KeyCount>1</KeyCount>"));
        assert!(second_body.contains("gamma.txt"));
        assert!(!second_body.contains("<Key>alpha.txt</Key>"));
        assert!(!second_body.contains("<Key>beta.txt</Key>"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_list_objects_v2_with_common_prefixes_when_delimiter_is_provided() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        for (key, payload) in [
            ("docs/readme.txt", b"readme".as_slice()),
            ("docs/2024/alpha.txt", b"alpha".as_slice()),
            ("docs/2025/bravo.txt", b"bravo".as_slice()),
        ] {
            storage
                .put_object(
                    "bucket",
                    key.to_string(),
                    Object::new(key.to_string(), payload.to_vec(), "text/plain".to_string()),
                )
                .unwrap();
        }

        let req =
            parsed_request("http://localhost/bucket?list-type=2&prefix=docs%2F&delimiter=%2F")
                .await;

        // Act
        let resp = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &req,
            "req-132".to_string(),
        )
        .await
        .expect("delimiter listing should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        let body = String::from_utf8(body.to_vec()).expect("body should be utf8");
        assert!(body.contains("<ListBucketResult"));
        assert!(body.contains("<KeyCount>3</KeyCount>"));
        assert!(body.contains("docs/readme.txt"));
        assert!(body.contains("<CommonPrefixes>"));
        assert!(body.contains("<Prefix>docs/2024/</Prefix>"));
        assert!(body.contains("<Prefix>docs/2025/</Prefix>"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_round_trip_request_payment_website_and_cors_bucket_configs() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let request_payment_xml = br#"<?xml version="1.0" encoding="UTF-8"?><RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Payer>Requester</Payer></RequestPaymentConfiguration>"#;
        let website_xml = br#"<?xml version="1.0" encoding="UTF-8"?><WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>"#;
        let cors_xml = br#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"#;

        let put_request_payment = parsed_request_with_method(
            "PUT",
            "http://localhost/bucket?requestPayment",
            request_payment_xml,
        )
        .await;
        let put_website =
            parsed_request_with_method("PUT", "http://localhost/bucket?website", website_xml).await;
        let put_cors =
            parsed_request_with_method("PUT", "http://localhost/bucket?cors", cors_xml).await;

        assert_eq!(
            bucket_put(
                storage.clone(),
                auth_disabled_config(),
                "bucket",
                &put_request_payment,
                "req-133".to_string(),
            )
            .await
            .expect("request payment put should complete")
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            bucket_put(
                storage.clone(),
                auth_disabled_config(),
                "bucket",
                &put_website,
                "req-134".to_string(),
            )
            .await
            .expect("website put should complete")
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            bucket_put(
                storage.clone(),
                auth_disabled_config(),
                "bucket",
                &put_cors,
                "req-135".to_string(),
            )
            .await
            .expect("cors put should complete")
            .status(),
            StatusCode::OK
        );

        let request_payment = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &parsed_request("http://localhost/bucket?requestPayment").await,
            "req-136".to_string(),
        )
        .await
        .expect("request payment get should complete");
        let request_payment_body = String::from_utf8(
            hyper::body::to_bytes(request_payment.into_body())
                .await
                .expect("body should read")
                .to_vec(),
        )
        .expect("body should be utf8");
        assert!(request_payment_body.contains("<Payer>Requester</Payer>"));

        let website = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &parsed_request("http://localhost/bucket?website").await,
            "req-137".to_string(),
        )
        .await
        .expect("website get should complete");
        let website_body = String::from_utf8(
            hyper::body::to_bytes(website.into_body())
                .await
                .expect("body should read")
                .to_vec(),
        )
        .expect("body should be utf8");
        assert!(website_body.contains("index.html"));

        let cors = bucket_get_or_list_objects(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &parsed_request("http://localhost/bucket?cors").await,
            "req-138".to_string(),
        )
        .await
        .expect("cors get should complete");
        let cors_body = String::from_utf8(
            hyper::body::to_bytes(cors.into_body())
                .await
                .expect("body should read")
                .to_vec(),
        )
        .expect("body should be utf8");
        assert!(cors_body.contains("<AllowedMethod>GET</AllowedMethod>"));

        assert_eq!(
            bucket_delete(
                storage.clone(),
                auth_disabled_config(),
                "bucket",
                &parsed_request("http://localhost/bucket?website").await,
                "req-139".to_string(),
            )
            .await
            .expect("website delete should complete")
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            bucket_delete(
                storage.clone(),
                auth_disabled_config(),
                "bucket",
                &parsed_request("http://localhost/bucket?cors").await,
                "req-140".to_string(),
            )
            .await
            .expect("cors delete should complete")
            .status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_accept_browser_post_uploads() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let boundary = "----peas-boundary";
        let request = browser_upload_request(
            boundary,
            "upload.txt",
            "text/plain",
            "upload.txt",
            b"browser upload",
        )
        .await;

        let response = bucket_post(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &request,
            "req-post".to_string(),
        )
        .await
        .expect("bucket post should succeed");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = storage.get_object("bucket", "upload.txt").unwrap();
        assert_eq!(stored.data, b"browser upload");
        assert_eq!(stored.content_type, "text/plain");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_preserve_exact_binary_bytes_for_browser_post_uploads() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let request = browser_upload_request(
            "----peas-boundary",
            "binary.bin",
            "application/octet-stream",
            "binary.bin",
            &[0x00, 0x7f, 0x80, 0xff, b'A', b'\r', b'\n', b' '],
        )
        .await;

        let response = bucket_post(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &request,
            "req-post-binary".to_string(),
        )
        .await
        .expect("bucket post should succeed");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = storage.get_object("bucket", "binary.bin").unwrap();
        assert_eq!(stored.data, vec![0x00, 0x7f, 0x80, 0xff, b'A', b'\r', b'\n', b' ']);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_preserve_trailing_whitespace_for_browser_post_uploads() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let payload = b"line one\r\nline two\r\n\r\n ";
        let request = browser_upload_request(
            "----peas-boundary",
            "whitespace.txt",
            "text/plain",
            "whitespace.txt",
            payload,
        )
        .await;

        let response = bucket_post(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            &request,
            "req-post-whitespace".to_string(),
        )
        .await
        .expect("bucket post should succeed");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let stored = storage.get_object("bucket", "whitespace.txt").unwrap();
        assert_eq!(stored.data, payload);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_require_auth_for_bucket_list_and_head_routes() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let list_req = parsed_request("http://localhost/bucket").await;
        let list_response = bucket_get_or_list_objects(
            storage.clone(),
            auth_enabled_config(),
            "bucket",
            &list_req,
            "req-auth-list".to_string(),
        )
        .await
        .expect("list request should respond");
        assert_eq!(list_response.status(), StatusCode::FORBIDDEN);

        let head_req = parsed_request_with_method("HEAD", "http://localhost/bucket", &[]).await;
        let head_response = bucket_head(
            storage,
            auth_enabled_config(),
            "bucket",
            &head_req,
            "req-auth-head".to_string(),
        )
        .await
        .expect("head request should respond");
        assert_eq!(head_response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_require_auth_for_bucket_post_delete_and_browser_upload() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();
        storage
            .put_object(
                "bucket",
                "delete-me.txt".to_string(),
                Object::new(
                    "delete-me.txt".to_string(),
                    b"payload".to_vec(),
                    "text/plain".to_string(),
                ),
            )
            .unwrap();

        let delete_body = br#"<Delete><Object><Key>delete-me.txt</Key></Object></Delete>"#;
        let delete_request = parsed_request_with_method(
            "POST",
            "http://localhost/bucket?delete",
            delete_body,
        )
        .await;
        let delete_response = bucket_post(
            storage.clone(),
            auth_enabled_config(),
            "bucket",
            &delete_request,
            "req-auth-delete".to_string(),
        )
        .await
        .expect("delete request should respond");
        assert_eq!(delete_response.status(), StatusCode::FORBIDDEN);

        let boundary = "----peas-boundary";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nupload.txt\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\nContent-Type: text/plain\r\n\r\nbrowser upload\r\n--{boundary}--\r\n"
        );
        let upload_request = crate::server::RequestExt::from_hyper(
            hyper::Request::builder()
                .method("POST")
                .uri("http://localhost/bucket")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(hyper::Body::from(body))
                .expect("request should build"),
        )
        .await
        .expect("request should parse");
        let upload_response = bucket_post(
            storage,
            auth_enabled_config(),
            "bucket",
            &upload_request,
            "req-auth-upload".to_string(),
        )
        .await
        .expect("upload request should respond");
        assert_eq!(upload_response.status(), StatusCode::FORBIDDEN);
    }
}
