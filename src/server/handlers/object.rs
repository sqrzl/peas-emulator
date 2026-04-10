use super::auth::{check_authorization, verify_presigned_url};
use super::ResponseBuilder;
use crate::auth::AuthConfig;
use crate::services::{storage_error_response, xml_error_response, xml_success_response};
use crate::storage::Storage;
use crate::utils::{headers as header_utils, validation, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};
use std::collections::HashMap;
use std::sync::Arc;
use urlencoding::decode;

fn parse_range(range_header: &str) -> Option<(u64, Option<u64>)> {
    // Expect formats like "bytes=start-end" or "bytes=start-"
    let range = range_header.strip_prefix("bytes=")?;
    let (start_str, end_str_opt) = range.split_once('-')?;
    let start = start_str.parse::<u64>().ok()?;
    let end = if let Some(end_str) = end_str_opt.strip_prefix(' ') {
        end_str.parse::<u64>().ok()
    } else {
        end_str_opt.parse::<u64>().ok()
    };
    Some((start, end))
}

fn parse_tagging_header(tag_header: &str) -> Result<HashMap<String, String>, String> {
    let mut tags = HashMap::new();
    for pair in tag_header.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| "Invalid tagging format".to_string())?;
        let key = decode(k).map_err(|e| e.to_string())?.into_owned();
        let value = decode(v).map_err(|e| e.to_string())?.into_owned();
        tags.insert(key, value);
    }
    Ok(tags)
}

fn copy_source_range_data(
    source_obj: &crate::models::Object,
    range_header: &str,
) -> Result<Vec<u8>, String> {
    let (start, end_opt) =
        parse_range(range_header).ok_or_else(|| "Invalid copy source range".to_string())?;

    let source_len = source_obj.data.len() as u64;
    if source_len == 0 || start >= source_len {
        return Err("Invalid copy source range".to_string());
    }

    let end = end_opt.unwrap_or(source_len - 1).min(source_len - 1);
    if end < start {
        return Err("Invalid copy source range".to_string());
    }

    let start_idx = start as usize;
    let end_idx = end as usize;
    Ok(source_obj.data[start_idx..=end_idx].to_vec())
}

fn add_version_header(builder: ResponseBuilder, version_id: Option<&str>) -> ResponseBuilder {
    if let Some(version_id) = version_id {
        builder.header("x-amz-version-id", version_id)
    } else {
        builder
    }
}

fn normalize_etag(value: &str) -> &str {
    let value = value.trim();
    let value = value.strip_prefix("W/").unwrap_or(value);
    value.trim_matches('"')
}

fn etag_list_matches(header_value: &str, etag: &str) -> bool {
    let normalized_etag = normalize_etag(etag);

    header_value
        .split(',')
        .map(normalize_etag)
        .any(|candidate| candidate == "*" || candidate == normalized_etag)
}

fn object_response_headers(
    mut builder: ResponseBuilder,
    obj: &crate::models::Object,
    req_id: &str,
) -> ResponseBuilder {
    let last_modified = header_utils::format_last_modified_at(&obj.last_modified);

    builder = builder
        .header("ETag", &obj.etag)
        .header("Last-Modified", &last_modified)
        .header("x-amz-request-id", req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .header("x-amz-storage-class", &obj.storage_class)
        .header("Accept-Ranges", "bytes");

    builder = add_version_header(builder, obj.version_id.as_deref());

    for (k, v) in obj.metadata.iter() {
        builder = builder.header(&format!("x-amz-meta-{}", k), v);
    }

    builder
}

fn precondition_failed_response(req_id: &str) -> Response<Body> {
    let xml = xml_utils::error_xml(
        "PreconditionFailed",
        "At least one of the pre-conditions you specified did not hold",
        req_id,
    );

    ResponseBuilder::new(StatusCode::PRECONDITION_FAILED)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", req_id)
        .body(xml.into_bytes())
        .build()
}

fn not_modified_response(obj: &crate::models::Object, req_id: &str) -> Response<Body> {
    object_response_headers(ResponseBuilder::new(StatusCode::NOT_MODIFIED), obj, req_id).empty()
}

fn check_object_conditionals(
    req: &crate::server::http::Request,
    obj: &crate::models::Object,
    req_id: &str,
) -> Option<Response<Body>> {
    if let Some(if_match) = req.header("if-match") {
        if !etag_list_matches(if_match, &obj.etag) {
            return Some(precondition_failed_response(req_id));
        }
    }

    if let Some(if_unmodified_since) = req.header("if-unmodified-since") {
        if let Ok(since_dt) = chrono::DateTime::parse_from_rfc2822(if_unmodified_since) {
            if obj.last_modified > since_dt.with_timezone(&chrono::Utc) {
                return Some(precondition_failed_response(req_id));
            }
        }
    }

    if let Some(if_none_match) = req.header("if-none-match") {
        if etag_list_matches(if_none_match, &obj.etag) {
            return Some(not_modified_response(obj, req_id));
        }
    }

    if let Some(if_modified_since) = req.header("if-modified-since") {
        if let Ok(since_dt) = chrono::DateTime::parse_from_rfc2822(if_modified_since) {
            if obj.last_modified <= since_dt.with_timezone(&chrono::Utc) {
                return Some(not_modified_response(obj, req_id));
            }
        }
    }

    None
}

fn check_copy_conditionals(
    req: &crate::server::http::Request,
    source_obj: &crate::models::Object,
    req_id: &str,
) -> Option<Response<Body>> {
    // x-amz-copy-source-if-match: copy if source ETag matches
    if let Some(match_etag) = req.header("x-amz-copy-source-if-match") {
        if source_obj.etag != match_etag {
            let xml = xml_utils::error_xml(
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                req_id,
            );
            return Some(
                ResponseBuilder::new(StatusCode::PRECONDITION_FAILED)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", req_id)
                    .body(xml.into_bytes())
                    .build(),
            );
        }
    }

    // x-amz-copy-source-if-none-match: copy if source ETag does NOT match
    if let Some(none_match) = req.header("x-amz-copy-source-if-none-match") {
        if source_obj.etag == none_match {
            let xml = xml_utils::error_xml(
                "PreconditionFailed",
                "At least one of the pre-conditions you specified did not hold",
                req_id,
            );
            return Some(
                ResponseBuilder::new(StatusCode::PRECONDITION_FAILED)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", req_id)
                    .body(xml.into_bytes())
                    .build(),
            );
        }
    }

    // x-amz-copy-source-if-modified-since: copy if modified after date
    if let Some(modified_since) = req.header("x-amz-copy-source-if-modified-since") {
        if let Ok(since_dt) = chrono::DateTime::parse_from_rfc2822(modified_since) {
            if source_obj.last_modified <= since_dt.with_timezone(&chrono::Utc) {
                return Some(
                    ResponseBuilder::new(StatusCode::NOT_MODIFIED)
                        .header("x-amz-request-id", req_id)
                        .empty(),
                );
            }
        }
    }

    // x-amz-copy-source-if-unmodified-since: copy if NOT modified after date
    if let Some(unmodified_since) = req.header("x-amz-copy-source-if-unmodified-since") {
        if let Ok(since_dt) = chrono::DateTime::parse_from_rfc2822(unmodified_since) {
            if source_obj.last_modified > since_dt.with_timezone(&chrono::Utc) {
                let xml = xml_utils::error_xml(
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                    req_id,
                );
                return Some(
                    ResponseBuilder::new(StatusCode::PRECONDITION_FAILED)
                        .content_type("application/xml; charset=utf-8")
                        .header("x-amz-request-id", req_id)
                        .body(xml.into_bytes())
                        .build(),
                );
            }
        }
    }

    None
}

pub async fn object_get(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &crate::server::http::Request,
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

    // Verify presigned URL if present
    if let Err(response) = verify_presigned_url(req, bucket, key, &auth_config) {
        return Ok(response);
    }

    // Check if object should be deleted due to lifecycle rules (eager enforcement)
    let is_expired = tokio::task::block_in_place(|| {
        crate::lifecycle::check_object_expiration(&storage, bucket, key)
    });

    if is_expired.is_ok() && is_expired.unwrap() {
        // Object was deleted due to lifecycle expiration
        return Ok(xml_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "Key not found",
            &req_id,
        ));
    }

    if req.has_query_param("tagging") {
        match tokio::task::block_in_place(|| storage.get_object_tags(bucket, key)) {
            Ok(tags) => {
                let xml = xml_utils::tagging_xml(&tags);
                return Ok(xml_success_response(StatusCode::OK, xml, &req_id));
            }
            Err(e) => return Ok(storage_error_response(&e, &req_id)),
        }
    }

    if req.has_query_param("acl") {
        match tokio::task::block_in_place(|| storage.get_object_acl(bucket, key)) {
            Ok(acl) => {
                let owner = crate::models::policy::Owner {
                    id: "peas-emulator".to_string(),
                    display_name: "S3 Emulator".to_string(),
                };
                let xml = xml_utils::acl_xml(&owner, &acl);
                return Ok(xml_success_response(StatusCode::OK, xml, &req_id));
            }
            Err(e) => return Ok(storage_error_response(&e, &req_id)),
        }
    }

    if let Some(version_id) = req.query_param("versionId") {
        match tokio::task::block_in_place(|| storage.get_object_version(bucket, key, version_id)) {
            Ok(obj) => {
                if let Some(response) = check_object_conditionals(req, &obj, &req_id) {
                    return Ok(response);
                }

                let builder = object_response_headers(
                    ResponseBuilder::new(StatusCode::OK)
                        .content_type(&obj.content_type)
                        .header("Content-Length", &obj.size.to_string()),
                    &obj,
                    &req_id,
                );

                return Ok(builder.body(obj.data).build());
            }
            Err(e) => return Ok(storage_error_response(&e, &req_id)),
        }
    }

    if req.has_query_param("uploadId") {
        let upload_id = req.query_param("uploadId").unwrap_or("");
        match tokio::task::block_in_place(|| storage.list_parts(bucket, upload_id)) {
            Ok(parts) => {
                let xml = xml_utils::list_parts_xml(bucket, key, upload_id, &parts);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
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

    let range_header = req.header("range").map(|s| s.to_string());

    // Range support
    if let Some(range_str) = range_header {
        let range = parse_range(&range_str);
        match range {
            Some((start, end_opt)) => {
                match tokio::task::block_in_place(|| {
                    storage.get_object_range(bucket, key, start, end_opt)
                }) {
                    Ok((obj, data)) => {
                        if let Some(response) = check_object_conditionals(req, &obj, &req_id) {
                            return Ok(response);
                        }

                        let len = data.len() as u64;
                        let end_idx = start + len.saturating_sub(1);
                        let builder = object_response_headers(
                            ResponseBuilder::new(StatusCode::PARTIAL_CONTENT)
                                .content_type(&obj.content_type)
                                .header("Content-Length", &len.to_string())
                                .header(
                                    "Content-Range",
                                    &format!("bytes {}-{}/{}", start, end_idx, obj.size),
                                ),
                            &obj,
                            &req_id,
                        );

                        Ok(builder.body(data).build())
                    }
                    Err(e) => Ok(xml_error_response(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "InvalidRange",
                        &e.to_string(),
                        &req_id,
                    )),
                }
            }
            None => Ok(xml_error_response(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "Invalid Range header",
                &req_id,
            )),
        }
    } else {
        // Default: Get full object
        match tokio::task::block_in_place(|| storage.get_object(bucket, key)) {
            Ok(obj) => {
                if let Some(response) = check_object_conditionals(req, &obj, &req_id) {
                    return Ok(response);
                }

                let builder = object_response_headers(
                    ResponseBuilder::new(StatusCode::OK)
                        .content_type(&obj.content_type)
                        .header("Content-Length", &obj.size.to_string()),
                    &obj,
                    &req_id,
                );

                Ok(builder.body(obj.data).build())
            }
            Err(e) => Ok(xml_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                &e.to_string(),
                &req_id,
            )),
        }
    }
}

pub async fn object_put(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &crate::server::http::Request,
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

    // Verify presigned URL if present
    if let Err(response) = verify_presigned_url(req, bucket, key, &auth_config) {
        return Ok(response);
    }

    if req.has_query_param("tagging") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let tags = match xml_utils::parse_tagging_xml(&body) {
            Ok(t) => t,
            Err(msg) => {
                return Ok(xml_error_response(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    &msg,
                    &req_id,
                ));
            }
        };
        match tokio::task::block_in_place(|| storage.put_object_tags(bucket, key, tags)) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
            }
            Err(crate::error::Error::KeyNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "Key not found",
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

    if req.has_query_param("acl") {
        let canned_acl_str = req.header("x-amz-acl").unwrap_or("private");
        let canned_acl: crate::models::policy::CannedAcl =
            serde_json::from_value(serde_json::json!(canned_acl_str)).unwrap_or_default();
        let acl = crate::models::policy::Acl {
            canned: canned_acl,
            grants: vec![],
        };
        match tokio::task::block_in_place(|| storage.put_object_acl(bucket, key, acl)) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
            }
            Err(crate::error::Error::KeyNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "Key not found",
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

    if req.has_query_param("uploadId") && req.query_param("partNumber").is_some() {
        let upload_id = req.query_param("uploadId").unwrap_or("");
        let part_number: u32 = match req.query_param("partNumber") {
            Some(pn) => pn.parse().unwrap_or(0),
            None => 0,
        };
        match tokio::task::block_in_place(|| {
            storage.upload_part(bucket, upload_id, part_number, req.body.to_vec())
        }) {
            Ok(etag) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("ETag", &etag)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
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

    if req.header("x-amz-copy-source").is_some() {
        let copy_source = req.header("x-amz-copy-source").unwrap_or("");
        let (source_bucket, source_key) = match copy_source.split_once('/') {
            Some((b, k)) => (b, k),
            None => {
                return Ok(xml_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "Invalid copy source format",
                    &req_id,
                ));
            }
        };

        let metadata_directive = req
            .header("x-amz-metadata-directive")
            .unwrap_or("COPY")
            .to_uppercase();
        let tagging_directive = req
            .header("x-amz-tagging-directive")
            .unwrap_or("COPY")
            .to_uppercase();
        let tagging_header = req.header("x-amz-tagging");

        match tokio::task::block_in_place(|| storage.get_object(source_bucket, source_key)) {
            Ok(src_obj) => {
                // Check copy conditionals before proceeding
                if let Some(response) = check_copy_conditionals(req, &src_obj, &req_id) {
                    return Ok(response);
                }

                let copy_data = if let Some(range_header) = req.header("x-amz-copy-source-range") {
                    match copy_source_range_data(&src_obj, range_header) {
                        Ok(data) => data,
                        Err(msg) => {
                            return Ok(xml_error_response(
                                StatusCode::RANGE_NOT_SATISFIABLE,
                                "InvalidRange",
                                &msg,
                                &req_id,
                            ));
                        }
                    }
                } else {
                    src_obj.data.clone()
                };

                let metadata = if metadata_directive == "REPLACE" {
                    header_utils::extract_metadata_from_http_headers(req)
                } else {
                    src_obj.metadata.clone()
                };

                let tags = if let Some(tag_str) = tagging_header {
                    if tagging_directive == "REPLACE" || tagging_directive == "COPY" {
                        Some(
                            parse_tagging_header(tag_str)
                                .map_err(|e| format!("Invalid tags: {}", e))?,
                        )
                    } else {
                        None
                    }
                } else if tagging_directive == "COPY" {
                    Some(src_obj.tags.clone())
                } else {
                    None
                };

                let mut dest_obj = crate::models::Object::new_with_metadata(
                    key.to_string(),
                    copy_data,
                    src_obj.content_type.clone(),
                    metadata,
                );
                if let Some(t) = tags.clone() {
                    dest_obj.tags = t;
                } else {
                    dest_obj.tags = src_obj.tags.clone();
                }

                let dest_key = dest_obj.key.clone();
                let etag = dest_obj.etag.clone();
                let dest_last_modified = dest_obj.last_modified.clone();

                match tokio::task::block_in_place(|| storage.put_object(bucket, dest_key, dest_obj))
                {
                    Ok(_) => {
                        let stored_version_id =
                            tokio::task::block_in_place(|| storage.get_object(bucket, key))
                                .ok()
                                .and_then(|obj| obj.version_id);

                        let xml = format!(
                            r#"<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ETag>{}</ETag>
    <LastModified>{}</LastModified>
</CopyObjectResult>"#,
                            etag,
                            header_utils::format_last_modified_at(&dest_last_modified)
                        );
                        let mut builder = ResponseBuilder::new(StatusCode::OK)
                            .content_type("application/xml; charset=utf-8")
                            .header("x-amz-request-id", &req_id);
                        builder = add_version_header(builder, stored_version_id.as_deref());
                        return Ok(builder.body(xml.into_bytes()).build());
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
            Err(crate::error::Error::KeyNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "Copy source not found",
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

    if let Err(e) = validation::validate_bucket_name(bucket) {
        return Ok(xml_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            &e,
            &req_id,
        ));
    }

    if let Err(e) = validation::validate_object_key(key) {
        return Ok(xml_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidKey",
            &e,
            &req_id,
        ));
    }

    let content_type = req
        .header("content-type")
        .unwrap_or("application/octet-stream")
        .to_string();

    let tagging_header = req.header("x-amz-tagging");
    let tags = if let Some(tag_str) = tagging_header {
        match parse_tagging_header(tag_str) {
            Ok(t) => Some(t),
            Err(e) => {
                return Ok(xml_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidTag",
                    &e,
                    &req_id,
                ));
            }
        }
    } else {
        None
    };

    let metadata = header_utils::extract_metadata_from_http_headers(req);
    let mut obj = crate::models::Object::new_with_metadata(
        key.to_string(),
        req.body.to_vec(),
        content_type,
        metadata,
    );
    if let Some(t) = tags.clone() {
        obj.tags = t;
    }
    let obj_key = obj.key.clone();
    let etag = obj.etag.clone();

    match tokio::task::block_in_place(|| storage.put_object(bucket, obj_key, obj)) {
        Ok(_) => {
            let stored_version_id = tokio::task::block_in_place(|| storage.get_object(bucket, key))
                .ok()
                .and_then(|obj| obj.version_id);

            let mut builder = ResponseBuilder::new(StatusCode::OK)
                .header("Content-Length", "0")
                .header("ETag", &etag.to_string())
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id());

            builder = add_version_header(builder, stored_version_id.as_deref());

            Ok(builder.empty())
        }
        Err(e) => Ok(xml_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &e.to_string(),
            &req_id,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthConfig;
    use crate::models::Object;
    use crate::server::RequestExt;
    use crate::storage::FilesystemStorage;
    use chrono::{TimeZone, Utc};
    use hyper::{Body, Request as HyperRequest, StatusCode};
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir =
            std::env::temp_dir().join(format!("peas-copy-range-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    fn auth_disabled_config() -> Arc<AuthConfig> {
        Arc::new(AuthConfig {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        })
    }

    async fn parsed_request(headers: &[(&str, &str)]) -> RequestExt {
        let mut builder = HyperRequest::builder()
            .method("PUT")
            .uri("http://localhost/");

        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        RequestExt::from_hyper(builder.body(Body::empty()).expect("request should build"))
            .await
            .expect("request should parse")
    }

    async fn parsed_request_with_method(method: &str, headers: &[(&str, &str)]) -> RequestExt {
        let mut builder = HyperRequest::builder()
            .method(method)
            .uri("http://localhost/");

        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        RequestExt::from_hyper(builder.body(Body::empty()).expect("request should build"))
            .await
            .expect("request should parse")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_copy_only_requested_range_when_copy_source_range_is_provided() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("source".to_string()).unwrap();
        storage.create_bucket("dest".to_string()).unwrap();

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("owner".to_string(), "alice".to_string());
        storage
            .put_object(
                "source",
                "source.txt".to_string(),
                Object::new_with_metadata(
                    "source.txt".to_string(),
                    b"abcdefghij".to_vec(),
                    "text/plain".to_string(),
                    metadata,
                ),
            )
            .unwrap();

        // Act
        let req = parsed_request(&[
            ("x-amz-copy-source", "source/source.txt"),
            ("x-amz-copy-source-range", "bytes=2-5"),
        ])
        .await;

        let resp = object_put(
            storage.clone(),
            auth_disabled_config(),
            "dest",
            "copied.txt",
            &req,
            "req-123".to_string(),
        )
        .await
        .expect("copy should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let copied = storage.get_object("dest", "copied.txt").unwrap();
        assert_eq!(copied.data, b"cdef".to_vec());
        assert_eq!(copied.size, 4);
        assert_eq!(copied.content_type, "text/plain");
        assert_eq!(copied.metadata.get("owner"), Some(&"alice".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_reject_invalid_copy_source_range_when_range_exceeds_source_size() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("source".to_string()).unwrap();
        storage.create_bucket("dest".to_string()).unwrap();

        storage
            .put_object(
                "source",
                "source.txt".to_string(),
                Object::new(
                    "source.txt".to_string(),
                    b"abcdefghij".to_vec(),
                    "text/plain".to_string(),
                ),
            )
            .unwrap();

        // Act
        let req = parsed_request(&[
            ("x-amz-copy-source", "source/source.txt"),
            ("x-amz-copy-source-range", "bytes=20-30"),
        ])
        .await;

        let resp = object_put(
            storage.clone(),
            auth_disabled_config(),
            "dest",
            "copied.txt",
            &req,
            "req-124".to_string(),
        )
        .await
        .expect("copy should return a response");

        // Assert
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        let body = String::from_utf8(body.to_vec()).expect("body should be utf8");
        assert!(body.contains("InvalidRange"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_return_object_last_modified_from_stored_object_when_getting_the_object() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let mut object = Object::new(
            "object.txt".to_string(),
            b"payload".to_vec(),
            "text/plain".to_string(),
        );
        let expected_last_modified = Utc.with_ymd_and_hms(2024, 4, 10, 12, 34, 56).unwrap();
        object.last_modified = expected_last_modified;

        storage
            .put_object("bucket", "object.txt".to_string(), object)
            .unwrap();

        // Act
        let req = parsed_request_with_method("GET", &[]).await;

        let resp = object_get(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            "object.txt",
            &req,
            "req-125".to_string(),
        )
        .await
        .expect("get should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::OK);

        let last_modified = resp
            .headers()
            .get("last-modified")
            .expect("last-modified header should be present")
            .to_str()
            .expect("last-modified should be valid header value");
        let parsed = chrono::DateTime::parse_from_rfc2822(last_modified)
            .expect("last-modified should parse as RFC2822")
            .with_timezone(&Utc);
        assert_eq!(parsed, expected_last_modified);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_return_not_modified_when_if_none_match_matches_the_object_etag() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let object = Object::new(
            "object.txt".to_string(),
            b"payload".to_vec(),
            "text/plain".to_string(),
        );
        let etag = object.etag.clone();
        storage
            .put_object("bucket", "object.txt".to_string(), object)
            .unwrap();

        // Act
        let req = parsed_request_with_method("GET", &[("If-None-Match", &etag)]).await;

        let resp = object_get(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            "object.txt",
            &req,
            "req-126".to_string(),
        )
        .await
        .expect("get should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            resp.headers().get("etag").and_then(|v| v.to_str().ok()),
            Some(etag.as_str())
        );
        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        assert!(body.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_return_precondition_failed_when_if_match_does_not_match_the_object_etag() {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        storage
            .put_object(
                "bucket",
                "object.txt".to_string(),
                Object::new(
                    "object.txt".to_string(),
                    b"payload".to_vec(),
                    "text/plain".to_string(),
                ),
            )
            .unwrap();

        // Act
        let req = parsed_request_with_method("GET", &[("If-Match", "not-the-etag")]).await;

        let resp = object_get(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            "object.txt",
            &req,
            "req-127".to_string(),
        )
        .await
        .expect("get should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        let body = String::from_utf8(body.to_vec()).expect("body should be utf8");
        assert!(body.contains("PreconditionFailed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_return_not_modified_when_if_modified_since_is_after_the_object_last_modified_on_head(
    ) {
        // Arrange
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let mut object = Object::new(
            "object.txt".to_string(),
            b"payload".to_vec(),
            "text/plain".to_string(),
        );
        let expected_last_modified = Utc.with_ymd_and_hms(2024, 4, 10, 12, 34, 56).unwrap();
        object.last_modified = expected_last_modified;
        storage
            .put_object("bucket", "object.txt".to_string(), object)
            .unwrap();

        let request_time = (expected_last_modified + chrono::Duration::days(1)).to_rfc2822();

        // Act
        let req = parsed_request_with_method("HEAD", &[("If-Modified-Since", &request_time)]).await;

        let resp = object_head(
            storage.clone(),
            auth_disabled_config(),
            "bucket",
            "object.txt",
            &req,
            "req-128".to_string(),
        )
        .await
        .expect("head should complete");

        // Assert
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        let body = hyper::body::to_bytes(resp.into_body())
            .await
            .expect("body should read");
        assert!(body.is_empty());
    }
}

pub async fn object_delete(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &crate::server::http::Request,
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

    // Verify presigned URL if present
    if let Err(response) = verify_presigned_url(req, bucket, key, &auth_config) {
        return Ok(response);
    }

    if req.has_query_param("uploadId") {
        let upload_id = req.query_param("uploadId").unwrap_or("");
        match tokio::task::block_in_place(|| storage.abort_multipart_upload(bucket, upload_id)) {
            Ok(_) | Err(crate::error::Error::NoSuchUpload) => {
                return Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
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

    if req.has_query_param("versionId") {
        let version_id = req.query_param("versionId").unwrap_or("");
        match tokio::task::block_in_place(|| storage.delete_object_version(bucket, key, version_id))
        {
            Ok(_) | Err(crate::error::Error::KeyNotFound) => {
                return Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .header("x-amz-version-id", version_id)
                    .empty());
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

    if req.has_query_param("tagging") {
        match tokio::task::block_in_place(|| storage.delete_object_tags(bucket, key)) {
            Ok(_) | Err(crate::error::Error::KeyNotFound) => {
                return Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty());
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

    match tokio::task::block_in_place(|| storage.delete_object(bucket, key)) {
        Ok(_) | Err(crate::error::Error::KeyNotFound) => {
            Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty())
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

pub async fn object_head(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    bucket: &str,
    key: &str,
    req: &crate::server::http::Request,
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

    if let Some(version_id) = req.query_param("versionId") {
        match tokio::task::block_in_place(|| storage.get_object_version(bucket, key, version_id)) {
            Ok(obj) => {
                if let Some(response) = check_object_conditionals(req, &obj, &req_id) {
                    return Ok(response);
                }

                let builder = object_response_headers(
                    ResponseBuilder::new(StatusCode::OK)
                        .content_type(&obj.content_type)
                        .header("Content-Length", &obj.size.to_string()),
                    &obj,
                    &req_id,
                );

                return Ok(builder.empty());
            }
            Err(crate::error::Error::KeyNotFound) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "Key not found",
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

    match tokio::task::block_in_place(|| storage.get_object(bucket, key)) {
        Ok(obj) => {
            if let Some(response) = check_object_conditionals(req, &obj, &req_id) {
                return Ok(response);
            }

            let builder = object_response_headers(
                ResponseBuilder::new(StatusCode::OK)
                    .content_type(&obj.content_type)
                    .header("Content-Length", &obj.size.to_string()),
                &obj,
                &req_id,
            );

            Ok(builder.empty())
        }
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
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Complete multipart upload
    if req.has_query_param("uploadId") {
        let upload_id = req.query_param("uploadId").unwrap_or("");
        match tokio::task::block_in_place(|| storage.complete_multipart_upload(bucket, upload_id)) {
            Ok(etag) => {
                let xml = xml_utils::complete_multipart_upload_xml(bucket, key, &etag);
                let stored_version_id =
                    tokio::task::block_in_place(|| storage.get_object(bucket, key))
                        .ok()
                        .and_then(|obj| obj.version_id);

                let mut builder = ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id());

                builder = add_version_header(builder, stored_version_id.as_deref());

                return Ok(builder.body(xml.into_bytes()).build());
            }
            Err(crate::error::Error::NoSuchUpload) => {
                return Ok(xml_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchUpload",
                    "Upload not found",
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
            Err(e) => Ok(xml_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
                &req_id,
            )),
        }
    } else {
        Ok(xml_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Object POST operations not yet implemented",
            &req_id,
        ))
    }
}
