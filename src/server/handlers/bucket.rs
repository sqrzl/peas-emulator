use super::auth::check_authorization;
use super::ResponseBuilder;
use crate::auth::AuthConfig;
use crate::services::{
    empty_success_response, storage_error_response, xml_error_response, xml_success_response,
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

    let buckets = tokio::task::block_in_place(|| storage.list_buckets())?;
    let xml = xml_utils::list_buckets_xml(&buckets);

    Ok(xml_success_response(StatusCode::OK, xml, &req_id))
}

pub async fn bucket_head(
    storage: Arc<dyn Storage>,
    bucket: &str,
    req_id: String,
) -> Result<Response<Body>, String> {
    match tokio::task::block_in_place(|| storage.get_bucket(bucket)) {
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
    } else {
        "s3:DeleteBucket"
    };

    if let Err(response) = check_authorization(req, &auth_config, &storage, bucket, None, action) {
        return Ok(response);
    }

    if req.has_query_param("lifecycle") {
        match tokio::task::block_in_place(|| storage.delete_bucket_lifecycle(bucket)) {
            Ok(_) => Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id)),
            Err(e) => Ok(storage_error_response(&e, &req_id)),
        }
    } else if req.has_query_param("policy") {
        match tokio::task::block_in_place(|| storage.delete_bucket_policy(bucket)) {
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
        tokio::task::block_in_place(|| storage.delete_bucket(bucket))?;
        Ok(empty_success_response(StatusCode::NO_CONTENT, &req_id))
    }
}

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

    if req.has_query_param("lifecycle") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let cfg = match xml_utils::parse_lifecycle_xml(&body) {
            Ok(c) => c,
            Err(msg) => {
                let xml = xml_utils::error_xml("MalformedXML", &msg, &req_id);
                return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        };

        match tokio::task::block_in_place(|| storage.put_bucket_lifecycle(bucket, cfg)) {
            Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
            Err(crate::error::Error::BucketNotFound) => {
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
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
    } else if req.has_query_param("versioning") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let enabled = match xml_utils::parse_versioning_xml(&body) {
            Ok(e) => e,
            Err(msg) => {
                let xml = xml_utils::error_xml("MalformedXML", &msg, &req_id);
                return Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
        };
        if enabled {
            match tokio::task::block_in_place(|| storage.enable_versioning(bucket)) {
                Ok(_) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .empty())
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
        } else {
            match tokio::task::block_in_place(|| storage.suspend_versioning(bucket)) {
                Ok(_) => {
                    return Ok(ResponseBuilder::new(StatusCode::OK)
                        .header("x-amz-request-id", &req_id)
                        .header("x-amz-id-2", &header_utils::generate_request_id())
                        .empty())
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
    } else if req.has_query_param("acl") {
        let canned_acl_str = req.header("x-amz-acl").unwrap_or("private");
        let canned_acl: crate::models::policy::CannedAcl =
            serde_json::from_value(serde_json::json!(canned_acl_str)).unwrap_or_default();
        let acl = crate::models::policy::Acl {
            canned: canned_acl,
            grants: vec![],
        };
        match tokio::task::block_in_place(|| storage.put_bucket_acl(bucket, acl)) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty())
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
    } else if req.has_query_param("policy") {
        let body = String::from_utf8(req.body.to_vec())
            .map_err(|e| format!("Invalid UTF-8 body: {}", e))?;
        let policy: crate::models::policy::BucketPolicyDocument =
            serde_json::from_str(&body).map_err(|e| format!("Invalid JSON policy: {}", e))?;
        match tokio::task::block_in_place(|| storage.put_bucket_policy(bucket, policy)) {
            Ok(_) => {
                return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty())
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
    } else {
        tokio::task::block_in_place(|| storage.create_bucket(bucket.to_string()))?;
        Ok(ResponseBuilder::new(StatusCode::OK)
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty())
    }
}

pub async fn bucket_get_or_list_objects(
    storage: Arc<dyn Storage>,
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    if req.has_query_param("lifecycle") {
        match tokio::task::block_in_place(|| storage.get_bucket_lifecycle(bucket)) {
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
                let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
                return Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                    .content_type("application/xml; charset=utf-8")
                    .header("x-amz-request-id", &req_id)
                    .body(xml.into_bytes())
                    .build());
            }
            Err(crate::error::Error::KeyNotFound) => {
                let xml = xml_utils::error_xml(
                    "NoSuchLifecycleConfiguration",
                    "No lifecycle configuration present",
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
    } else if req.has_query_param("policy") {
        match tokio::task::block_in_place(|| storage.get_bucket_policy(bucket)) {
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
        match tokio::task::block_in_place(|| storage.get_bucket_acl(bucket)) {
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
    } else if req.has_query_param("versioning") {
        match tokio::task::block_in_place(|| storage.get_bucket(bucket)) {
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
        match tokio::task::block_in_place(|| storage.list_multipart_uploads(bucket)) {
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

        match tokio::task::block_in_place(|| storage.list_object_versions(bucket, prefix)) {
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
    } else if req.has_query_param("uploads") {
        match tokio::task::block_in_place(|| storage.list_multipart_uploads(bucket)) {
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
            storage.list_objects(bucket, Some(prefix), None, None, None)
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
        storage.list_objects(bucket, prefix, delimiter, marker, max_keys)
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
    bucket: &str,
    req: &crate::server::http::Request,
    req_id: String,
) -> Result<Response<Body>, String> {
    // Multi-object delete: POST /bucket?delete
    if req.has_query_param("delete") {
        if !tokio::task::block_in_place(|| storage.bucket_exists(bucket))? {
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

        for (key, version) in &objects {
            let _ = tokio::task::block_in_place(|| {
                if let Some(v) = version {
                    storage.delete_object_version(bucket, key, v)
                } else {
                    storage.delete_object(bucket, key)
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
        let resp =
            bucket_get_or_list_objects(storage.clone(), "bucket", &req, "req-129".to_string())
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
        let resp =
            bucket_get_or_list_objects(storage.clone(), "bucket", &req, "req-132".to_string())
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
}
