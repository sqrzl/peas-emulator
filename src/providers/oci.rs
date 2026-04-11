use super::ProviderAdapter;
use crate::auth::AuthConfig;
use crate::blob::{BlobBackend, PutBlobRequest};
use crate::server::{RequestExt as Request, ResponseBuilder};
use crate::storage::Storage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use http::{Method, StatusCode};
use hyper::{Body, Response};
use sha2::Sha256;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct OciAdapter;

impl OciAdapter {
    pub fn new() -> Self {
        Self
    }

    fn response(status: StatusCode) -> ResponseBuilder {
        ResponseBuilder::new(status)
            .header("opc-request-id", &uuid::Uuid::new_v4().to_string())
            .header("date", &crate::utils::headers::format_last_modified())
    }

    fn json_response(status: StatusCode, body: &str) -> Response<Body> {
        Self::response(status)
            .content_type("application/json")
            .body(body.as_bytes().to_vec())
            .build()
    }

    fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Body> {
        Self::json_response(
            status,
            &format!("{{\"code\":\"{}\",\"message\":\"{}\"}}", code, message),
        )
    }

    fn parse_path(req: &Request) -> Result<(String, Vec<String>), String> {
        let parts: Vec<&str> = req
            .path()
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if parts.is_empty() || parts[0] != "n" {
            return Err("OCI requests must start with /n".to_string());
        }
        Ok((
            parts.get(1).copied().unwrap_or("peas-emulator").to_string(),
            parts.iter().skip(2).map(|segment| (*segment).to_string()).collect(),
        ))
    }

    fn signing_string(req: &Request) -> String {
        format!(
            "date: {}\n(request-target): {} {}\nhost: {}",
            req.header("date").unwrap_or(""),
            req.method().as_str().to_lowercase(),
            req.path(),
            req.host().unwrap_or("localhost")
        )
    }

    fn authorize(req: &Request, config: &AuthConfig) -> Result<(), Response<Body>> {
        if !config.enforce_auth {
            return Ok(());
        }

        let Some(auth) = req.header("authorization") else {
            return Err(Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "Missing authorization"));
        };
        if !auth.starts_with("Signature ") {
            return Err(Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "Unsupported OCI auth scheme"));
        }
        let signature = auth
            .split(',')
            .find_map(|part| part.trim().strip_prefix("signature=\"").map(|value| value.trim_end_matches('"').to_string()))
            .ok_or_else(|| Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "Missing OCI signature"))?;
        let key_id = auth
            .split(',')
            .find_map(|part| part.trim().strip_prefix("Signature keyId=\"").or_else(|| part.trim().strip_prefix("keyId=\"")).map(|value| value.trim_end_matches('"').to_string()))
            .unwrap_or_default();

        if config.access_key() != Some(key_id.as_str()) {
            return Err(Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "Invalid OCI keyId"));
        }

        type HmacSha256 = Hmac<Sha256>;
        let secret = config.secret_key().unwrap_or_default().as_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&secret)
            .map_err(|_| Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "Invalid OCI key"))?;
        mac.update(Self::signing_string(req).as_bytes());
        let expected = BASE64.encode(mac.finalize().into_bytes());
        if expected == signature {
            Ok(())
        } else {
            Err(Self::error_response(StatusCode::UNAUTHORIZED, "NotAuthenticated", "OCI signature mismatch"))
        }
    }

    async fn handle_request(
        &self,
        storage: Arc<dyn Storage>,
        auth_config: Arc<AuthConfig>,
        req: Request,
    ) -> Result<Response<Body>, String> {
        let (namespace, parts) = match Self::parse_path(&req) {
            Ok(parsed) => parsed,
            Err(msg) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, "InvalidParameter", &msg)),
        };

        if let Err(response) = Self::authorize(&req, &auth_config) {
            return Ok(response);
        }

        if parts.is_empty() {
            if req.method() == Method::GET {
                return Ok(Self::json_response(StatusCode::OK, &format!("{{\"value\":\"{}\"}}", namespace)));
            }
            return Ok(Self::error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "Unsupported OCI namespace operation"));
        }

        if parts.len() >= 2 && parts[0] == "b" && parts.len() == 2 {
            let bucket = parts[1].clone();
            return match req.method() {
                &Method::PUT => {
                    storage.as_ref().create_namespace(bucket).map_err(|err| err.to_string())?;
                    Ok(Self::json_response(StatusCode::OK, "{\"etag\":\"created\"}"))
                }
                &Method::DELETE => {
                    storage.as_ref().delete_namespace(&bucket).map_err(|err| err.to_string())?;
                    Ok(Self::json_response(StatusCode::NO_CONTENT, ""))
                }
                &Method::GET => {
                    storage.as_ref().get_namespace(&bucket).map_err(|err| err.to_string())?;
                    Ok(Self::json_response(StatusCode::OK, &format!("{{\"name\":\"{}\"}}", bucket)))
                }
                _ => Ok(Self::error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "Unsupported OCI bucket operation")),
            };
        }

        if parts.len() >= 3 && parts[0] == "b" && parts[2] == "o" {
            let bucket = parts[1].clone();
            if parts.len() == 3 {
                if req.method() == Method::GET {
                    let objects = storage
                        .as_ref()
                        .list_blobs(&bucket, req.query_param("prefix"), None, None, None)
                        .map_err(|err| err.to_string())?;
                    let items = objects
                        .iter()
                        .map(|blob| format!("{{\"name\":\"{}\",\"size\":{}}}", blob.key, blob.size))
                        .collect::<Vec<_>>()
                        .join(",");
                    return Ok(Self::json_response(StatusCode::OK, &format!("{{\"objects\":[{}]}}", items)));
                }
                return Ok(Self::error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "Unsupported OCI object list operation"));
            }

            let object = parts[3..].join("/");
            return match req.method() {
                &Method::PUT => {
                    let stored = storage
                        .as_ref()
                        .put_blob(PutBlobRequest {
                            namespace: bucket.clone(),
                            key: object.clone(),
                            data: req.body.to_vec(),
                            content_type: req.header("content-type").unwrap_or("application/octet-stream").to_string(),
                            metadata: HashMap::new(),
                            tags: HashMap::new(),
                        })
                        .map_err(|err| err.to_string())?;
                    Ok(Self::json_response(StatusCode::OK, &format!("{{\"etag\":\"{}\"}}", stored.etag)))
                }
                &Method::GET => {
                    let blob = storage.as_ref().get_blob(&bucket, &object).map_err(|err| err.to_string())?;
                    Ok(Self::response(StatusCode::OK)
                        .header("content-length", &blob.size.to_string())
                        .header("content-type", &blob.content_type)
                        .body(blob.data)
                        .build())
                }
                &Method::HEAD => {
                    let blob = storage.as_ref().get_blob(&bucket, &object).map_err(|err| err.to_string())?;
                    Ok(Self::response(StatusCode::OK)
                        .header("content-length", &blob.size.to_string())
                        .header("content-type", &blob.content_type)
                        .empty())
                }
                &Method::DELETE => {
                    storage.as_ref().delete_blob(&bucket, &object).map_err(|err| err.to_string())?;
                    Ok(Self::json_response(StatusCode::NO_CONTENT, ""))
                }
                _ => Ok(Self::error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "Unsupported OCI object operation")),
            };
        }

        Ok(Self::error_response(StatusCode::BAD_REQUEST, "InvalidParameter", "Unsupported OCI path"))
    }
}

impl ProviderAdapter for OciAdapter {
    fn name(&self) -> &'static str {
        "oci-object"
    }

    fn matches(&self, req: &Request) -> bool {
        req.path().starts_with("/n/")
            || req
                .header("authorization")
                .map(|value| value.starts_with("Signature "))
                .unwrap_or(false)
    }

    fn handle<'a>(
        &'a self,
        storage: Arc<dyn Storage>,
        auth_config: Arc<AuthConfig>,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Body>, String>> + Send + 'a>> {
        Box::pin(async move { self.handle_request(storage, auth_config, req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::FilesystemStorage;
    use hyper::Request as HyperRequest;
    use std::fs;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir = std::env::temp_dir().join(format!("peas-oci-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    fn auth_disabled() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: std::time::Duration::from_secs(3600),
        })
    }

    fn oci_auth() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: Some("oci-key".to_string()),
            secret_access_key: Some("oci-secret".to_string()),
            enforce_auth: true,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: std::time::Duration::from_secs(3600),
        })
    }

    async fn parsed_request(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Request {
        let mut builder = HyperRequest::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        Request::from_hyper(builder.body(Body::from(body.to_vec())).expect("request should build"))
            .await
            .expect("request should parse")
    }

    fn authorization(req: &Request) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"oci-secret").expect("key");
        mac.update(OciAdapter::signing_string(req).as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());
        format!("Signature keyId=\"oci-key\",algorithm=\"hmac-sha256\",headers=\"date (request-target) host\",signature=\"{}\"", signature)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_support_oci_namespace_bucket_and_object_flows() {
        let adapter = OciAdapter::new();
        let storage = temp_storage();

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request("GET", "http://localhost/n/tenant", &[], b"").await,
            )
            .await
            .expect("namespace lookup should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request("PUT", "http://localhost/n/tenant/b/archive", &[], b"").await,
            )
            .await
            .expect("bucket create should succeed");

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/n/tenant/b/archive/o/report.txt",
                    &[("content-type", "text/plain")],
                    b"oci data",
                )
                .await,
            )
            .await
            .expect("object put should succeed");

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request("GET", "http://localhost/n/tenant/b/archive/o", &[], b"").await,
            )
            .await
            .expect("object list should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("json").contains("report.txt"));

        let response = adapter
            .handle_request(
                storage,
                auth_disabled(),
                parsed_request("GET", "http://localhost/n/tenant/b/archive/o/report.txt", &[], b"").await,
            )
            .await
            .expect("object get should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert_eq!(body.as_ref(), b"oci data");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_validate_oci_signature_authorization() {
        let adapter = OciAdapter::new();
        let storage = temp_storage();

        let mut request = parsed_request(
            "GET",
            "http://localhost/n/tenant",
            &[("date", "Sat, 01 Jan 2024 00:00:00 +0000"), ("host", "objectstorage.localhost")],
            b"",
        )
        .await;
        let auth = authorization(&request);
        request
            .headers
            .insert("authorization", auth.parse().expect("header should parse"));

        let response = adapter
            .handle_request(storage, oci_auth(), request)
            .await
            .expect("oci auth request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
