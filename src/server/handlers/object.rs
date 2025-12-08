use super::auth::{check_authorization, verify_presigned_url};
use super::ResponseBuilder;
use crate::auth::AuthConfig;
use crate::storage::Storage;
use crate::utils::{headers as header_utils, validation, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};
use std::collections::HashMap;
use std::sync::Arc;
use urlencoding::decode;

fn not_implemented(req_id: &str, message: &str) -> Response<Body> {
    let xml = xml_utils::error_xml("NotImplemented", message, req_id);
    ResponseBuilder::new(StatusCode::NOT_IMPLEMENTED)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", req_id)
        .body(xml.into_bytes())
        .build()
}

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
        let key = decode(k)
            .map_err(|e| e.to_string())?
            .into_owned();
        let value = decode(v)
            .map_err(|e| e.to_string())?
            .into_owned();
        tags.insert(key, value);
    }
    Ok(tags)
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
        let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
        return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build());
    }

    if req.has_query_param("tagging") {
        match tokio::task::block_in_place(|| storage.get_object_tags(bucket, key)) {
            Ok(tags) => {
                let xml = xml_utils::tagging_xml(&tags);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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

    if req.has_query_param("acl") {
        match tokio::task::block_in_place(|| storage.get_object_acl(bucket, key)) {
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
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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

    if let Some(version_id) = req.query_param("versionId") {
        match tokio::task::block_in_place(|| storage.get_object_version(bucket, key, version_id))
        {
            Ok(obj) => {
                let mut builder = ResponseBuilder::new(StatusCode::OK)
                    .content_type(&obj.content_type)
                    .header("Content-Length", &obj.size.to_string())
                    .header("ETag", &obj.etag.to_string())
                    .header("Last-Modified", &header_utils::format_last_modified())
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .header("x-amz-storage-class", "STANDARD")
                    .header("Accept-Ranges", "bytes")
                    .header("x-amz-version-id", version_id);

                for (k, v) in obj.metadata.iter() {
                    builder = builder.header(&format!("x-amz-meta-{}", k), v);
                }

                return Ok(builder.body(obj.data).build());
            }
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
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
                        let len = data.len() as u64;
                        let end_idx = start + len.saturating_sub(1);
                        let mut builder = ResponseBuilder::new(StatusCode::PARTIAL_CONTENT)
                            .content_type(&obj.content_type)
                            .header("Content-Length", &len.to_string())
                            .header("ETag", &obj.etag.to_string())
                            .header("Last-Modified", &header_utils::format_last_modified())
                            .header(
                                "Content-Range",
                                &format!("bytes {}-{}/{}", start, end_idx, obj.size),
                            )
                            .header("x-amz-request-id", &req_id)
                            .header("x-amz-id-2", &header_utils::generate_request_id())
                            .header("x-amz-storage-class", "STANDARD")
                            .header("Accept-Ranges", "bytes");

                        for (k, v) in obj.metadata.iter() {
                            builder = builder.header(&format!("x-amz-meta-{}", k), v);
                        }

                        Ok(builder.body(data).build())
                    }
                    Err(e) => {
                        let xml = xml_utils::error_xml("InvalidRange", &e.to_string(), &req_id);
                        Ok(ResponseBuilder::new(StatusCode::RANGE_NOT_SATISFIABLE)
                            .content_type("application/xml; charset=utf-8")
                            .header("x-amz-request-id", &req_id)
                            .body(xml.into_bytes())
                            .build())
                    }
                }
            }
            None => {
                let xml = xml_utils::error_xml("InvalidRange", "Invalid Range header", &req_id);
                Ok(ResponseBuilder::new(StatusCode::RANGE_NOT_SATISFIABLE)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build())
            }
        }
    } else {
        // Default: Get full object
        match tokio::task::block_in_place(|| storage.get_object(bucket, key)) {
            Ok(obj) => {
                let mut builder = ResponseBuilder::new(StatusCode::OK)
                    .content_type(&obj.content_type)
                    .header("Content-Length", &obj.size.to_string())
                    .header("ETag", &obj.etag.to_string())
                    .header("Last-Modified", &header_utils::format_last_modified())
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .header("x-amz-storage-class", "STANDARD")
                    .header("Accept-Ranges", "bytes");

                for (k, v) in obj.metadata.iter() {
                    builder = builder.header(&format!("x-amz-meta-{}", k), v);
                }

                Ok(builder.body(obj.data).build())
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
                let xml = xml_utils::error_xml("MalformedXML", &msg, &req_id);
                return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
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
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    }

    if req.header("x-amz-copy-source").is_some() {
        let copy_source = req.header("x-amz-copy-source").unwrap_or("");
        let (source_bucket, source_key) = match copy_source.split_once('/') {
            Some((b, k)) => (b, k),
            None => {
                let xml = xml_utils::error_xml(
                    "InvalidArgument",
                    "Invalid copy source format",
                    &req_id,
                );
                return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
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

        match tokio::task::block_in_place(|| {
            storage.get_object(source_bucket, source_key)
        }) {
            Ok(src_obj) => {
                // Check copy conditionals before proceeding
                if let Some(response) = check_copy_conditionals(req, &src_obj, &req_id) {
                    return Ok(response);
                }

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
                    src_obj.data.clone(),
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

                match tokio::task::block_in_place(|| storage.put_object(bucket, dest_key, dest_obj))
                {
                    Ok(_) => {
                        let xml = format!(
                            r#"<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ETag>{}</ETag>
    <LastModified>{}</LastModified>
</CopyObjectResult>"#,
                            etag,
                            header_utils::format_last_modified()
                        );
                        return Ok(ResponseBuilder::new(StatusCode::OK)
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
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml("NoSuchKey", "Copy source not found", &req_id);
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

    let tagging_header = req.header("x-amz-tagging");
    let tags = if let Some(tag_str) = tagging_header {
        match parse_tagging_header(tag_str) {
            Ok(t) => Some(t),
            Err(e) => {
                let xml = xml_utils::error_xml("InvalidTag", &e, &req_id);
                return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
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
                let xml = xml_utils::error_xml("InternalError", &e.to_string(), &req_id);
                return Ok(ResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        }
    }

    if req.has_query_param("versionId") {
        let version_id = req.query_param("versionId").unwrap_or("");
        match tokio::task::block_in_place(|| {
            storage.delete_object_version(bucket, key, version_id)
        }) {
            Ok(_) | Err(crate::error::Error::KeyNotFound) => {
                return Ok(ResponseBuilder::new(StatusCode::NO_CONTENT)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .header("x-amz-version-id", version_id)
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
        match tokio::task::block_in_place(|| storage.get_object_version(bucket, key, version_id))
        {
            Ok(obj) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type(&obj.content_type)
                    .header("Content-Length", &obj.size.to_string())
                    .header("ETag", &obj.etag.to_string())
                    .header("Last-Modified", &header_utils::format_last_modified())
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .header("x-amz-storage-class", "STANDARD")
                    .header("x-amz-version-id", version_id)
                    .empty());
            }
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml("NoSuchKey", "Key not found", &req_id);
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
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Complete multipart upload
    if req.has_query_param("uploadId") {
        let upload_id = req.query_param("uploadId").unwrap_or("");
        match tokio::task::block_in_place(|| {
            storage.complete_multipart_upload(bucket, upload_id)
        }) {
            Ok(etag) => {
                let xml = xml_utils::complete_multipart_upload_xml(bucket, key, &etag);
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
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
