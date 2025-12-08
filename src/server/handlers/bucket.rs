use super::auth::check_authorization;
use super::ResponseBuilder;
use crate::auth::AuthConfig;
use crate::storage::Storage;
use crate::utils::{headers as header_utils, validation, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::sync::Arc;

fn not_implemented(req_id: &str, message: &str) -> Response<Body> {
    let xml = xml_utils::error_xml("NotImplemented", message, req_id);
    ResponseBuilder::new(StatusCode::NOT_IMPLEMENTED)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", req_id)
        .body(xml.into_bytes())
        .build()
}

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
            Ok(Event::Start(e)) => {
                match e.name().as_ref() {
                    b"Key" => in_key = true,
                    b"VersionId" => in_version = true,
                    _ => {}
                }
            }
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
    match tokio::task::block_in_place(|| storage.get_bucket(bucket)) {
        Ok(_) => Ok(ResponseBuilder::new(StatusCode::OK)
            .header("x-amz-request-id", &req_id)
            .header("x-amz-id-2", &header_utils::generate_request_id())
            .empty()),
        Err(_) => {
            let xml = xml_utils::error_xml("NoSuchBucket", "Bucket not found", &req_id);
            Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
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
    } else if req.has_query_param("versioning") || req.has_query_param("acl") {
        let xml = xml_utils::error_xml(
            "InvalidRequest",
            "Cannot delete versioning or ACL via DELETE",
            &req_id,
        );
        Ok(ResponseBuilder::new(StatusCode::BAD_REQUEST)
            .content_type("application/xml; charset=utf-8")
            .header("x-amz-request-id", &req_id)
            .body(xml.into_bytes())
            .build())
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
                Ok(_) => return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty()),
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
                Ok(_) => return Ok(ResponseBuilder::new(StatusCode::OK)
                    .header("x-amz-request-id", &req_id)
                    .header("x-amz-id-2", &header_utils::generate_request_id())
                    .empty()),
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
            Ok(_) => return Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
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
            Ok(_) => return Ok(ResponseBuilder::new(StatusCode::OK)
                .header("x-amz-request-id", &req_id)
                .header("x-amz-id-2", &header_utils::generate_request_id())
                .empty()),
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
                    Err(_) => true, // Keep object if check fails
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
