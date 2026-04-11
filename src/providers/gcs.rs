use super::ProviderAdapter;
use crate::auth::AuthConfig;
use crate::blob::{BlobBackend, PutBlobRequest};
use crate::server::{RequestExt as Request, ResponseBuilder};
use crate::storage::Storage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use http::{Method, StatusCode};
use hyper::{Body, Response};
use sha1::Sha1;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct ResumableSession {
    bucket: String,
    key: String,
    content_type: String,
}

pub struct GcsAdapter {
    resumable_sessions: Mutex<HashMap<String, ResumableSession>>,
}

impl GcsAdapter {
    pub fn new() -> Self {
        Self {
            resumable_sessions: Mutex::new(HashMap::new()),
        }
    }

    fn response(status: StatusCode) -> ResponseBuilder {
        ResponseBuilder::new(status)
            .header("x-guploader-uploadid", &uuid::Uuid::new_v4().to_string())
            .header("date", &crate::utils::headers::format_last_modified())
    }

    fn xml_response(status: StatusCode, body: String) -> Response<Body> {
        Self::response(status)
            .content_type("application/xml")
            .body(body.into_bytes())
            .build()
    }

    fn empty_response(status: StatusCode) -> Response<Body> {
        Self::response(status).empty()
    }

    fn json_response(status: StatusCode, body: &str) -> Response<Body> {
        Self::response(status)
            .content_type("application/json")
            .body(body.as_bytes().to_vec())
            .build()
    }

    fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Body> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message></Error>",
            code, message
        );
        Self::xml_response(status, body)
    }

    fn is_gcs_host(req: &Request) -> bool {
        req.host()
            .map(|host| {
                let host = host.split(':').next().unwrap_or(host);
                host.eq_ignore_ascii_case("storage.googleapis.com")
                    || host.eq_ignore_ascii_case("storage.localhost")
            })
            .unwrap_or(false)
    }

    fn parse_path(req: &Request) -> (Option<String>, Option<String>) {
        let parts: Vec<&str> = req
            .path()
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let bucket = parts.first().map(|segment| (*segment).to_string());
        let object = if parts.len() > 1 {
            Some(parts[1..].join("/"))
        } else {
            None
        };
        (bucket, object)
    }

    fn sign(config: &AuthConfig, payload: &str) -> Result<String, String> {
        type HmacSha1 = Hmac<Sha1>;
        let secret = config
            .secret_key()
            .ok_or_else(|| "Missing GCS secret key".to_string())?;
        let key = BASE64.decode(secret).ok().unwrap_or_else(|| secret.as_bytes().to_vec());
        let mut mac =
            HmacSha1::new_from_slice(&key).map_err(|err| format!("Invalid GCS key: {}", err))?;
        mac.update(payload.as_bytes());
        Ok(BASE64.encode(mac.finalize().into_bytes()))
    }

    fn string_to_sign(req: &Request, bucket: &str, object: Option<&str>, expires: &str) -> String {
        let resource = if let Some(object) = object {
            format!("/{}/{}", bucket, object)
        } else {
            format!("/{}", bucket)
        };

        format!(
            "{}\n{}\n{}\n{}\n{}",
            req.method(),
            req.header("content-md5").unwrap_or(""),
            req.header("content-type").unwrap_or(""),
            expires,
            resource
        )
    }

    fn authorize(
        req: &Request,
        config: &AuthConfig,
        bucket: &str,
        object: Option<&str>,
    ) -> Result<(), Response<Body>> {
        if !config.enforce_auth {
            return Ok(());
        }

        if let (Some(access_id), Some(expires), Some(signature)) = (
            req.query_param("GoogleAccessId"),
            req.query_param("Expires"),
            req.query_param("Signature"),
        ) {
            if config.access_key() != Some(access_id) {
                return Err(Self::error_response(StatusCode::FORBIDDEN, "AccessDenied", "Invalid access id"));
            }
            let expected = Self::sign(config, &Self::string_to_sign(req, bucket, object, expires))
                .map_err(|msg| Self::error_response(StatusCode::FORBIDDEN, "SignatureDoesNotMatch", &msg))?;
            if expected == signature {
                return Ok(());
            }
            return Err(Self::error_response(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "GCS signed URL signature mismatch",
            ));
        }

        let Some(authorization) = req.header("authorization") else {
            return Err(Self::error_response(StatusCode::FORBIDDEN, "AccessDenied", "Missing authorization"));
        };
        let prefix = format!("GOOG1 {}:", config.access_key().unwrap_or_default());
        let Some(signature) = authorization.strip_prefix(&prefix) else {
            return Err(Self::error_response(StatusCode::FORBIDDEN, "AccessDenied", "Unsupported authorization"));
        };
        let date = req.header("date").unwrap_or("");
        let expected = Self::sign(config, &Self::string_to_sign(req, bucket, object, date))
            .map_err(|msg| Self::error_response(StatusCode::FORBIDDEN, "SignatureDoesNotMatch", &msg))?;
        if expected == signature {
            Ok(())
        } else {
            Err(Self::error_response(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "GCS HMAC signature mismatch",
            ))
        }
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
        let dir = std::env::temp_dir().join(format!("peas-gcs-test-{}", uuid::Uuid::new_v4()));
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

    fn gcs_auth() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: Some("test-access".to_string()),
            secret_access_key: Some(BASE64.encode("gcs-secret")),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn should_handle_gcs_bucket_and_object_crud() {
        let adapter = GcsAdapter::new();
        let storage = temp_storage();

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/photos",
                    &[("host", "storage.googleapis.com")],
                    b"",
                )
                .await,
            )
            .await
            .expect("bucket create should succeed");

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/photos/kitten.txt",
                    &[("host", "storage.googleapis.com"), ("content-type", "text/plain")],
                    b"hello gcs",
                )
                .await,
            )
            .await
            .expect("object put should succeed");

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "GET",
                    "http://localhost/photos",
                    &[("host", "storage.googleapis.com")],
                    b"",
                )
                .await,
            )
            .await
            .expect("list should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert!(String::from_utf8(body.to_vec()).expect("xml").contains("kitten.txt"));

        let response = adapter
            .handle_request(
                storage,
                auth_disabled(),
                parsed_request(
                    "GET",
                    "http://localhost/photos/kitten.txt",
                    &[("host", "storage.googleapis.com")],
                    b"",
                )
                .await,
            )
            .await
            .expect("get should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert_eq!(body.as_ref(), b"hello gcs");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_support_gcs_resumable_uploads_and_signed_access() {
        let adapter = GcsAdapter::new();
        let storage = temp_storage();
        storage.create_bucket("videos".to_string()).unwrap();

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "POST",
                    "http://localhost/upload/storage/v1/b/videos/o?uploadType=resumable&name=movie.txt",
                    &[
                        ("host", "storage.googleapis.com"),
                        ("x-upload-content-type", "text/plain"),
                    ],
                    b"",
                )
                .await,
            )
            .await
            .expect("resumable init should succeed");
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .expect("location should exist")
            .to_string();

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request("PUT", &location, &[("host", "storage.googleapis.com")], b"chunked")
                    .await,
            )
            .await
            .expect("resumable commit should succeed");

        let expires = "4102444800";
        let request = parsed_request(
            "GET",
            &format!(
                "http://localhost/videos/movie.txt?GoogleAccessId=test-access&Expires={}",
                expires
            ),
            &[("host", "storage.googleapis.com")],
            b"",
        )
        .await;
        let signature = GcsAdapter::sign(&gcs_auth(), &GcsAdapter::string_to_sign(&request, "videos", Some("movie.txt"), expires))
            .expect("signature should build");
        let signed_request = parsed_request(
            "GET",
            &format!(
                "http://localhost/videos/movie.txt?GoogleAccessId=test-access&Expires={}&Signature={}",
                expires,
                urlencoding::encode(&signature)
            ),
            &[("host", "storage.googleapis.com")],
            b"",
        )
        .await;

        let response = adapter
            .handle_request(storage, gcs_auth(), signed_request)
            .await
            .expect("signed get should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert_eq!(body.as_ref(), b"chunked");
    }
}

impl ProviderAdapter for GcsAdapter {
    fn name(&self) -> &'static str {
        "gcs"
    }

    fn matches(&self, req: &Request) -> bool {
        Self::is_gcs_host(req)
            || req
                .header("authorization")
                .map(|value| value.starts_with("GOOG1 "))
                .unwrap_or(false)
            || req.query_param("GoogleAccessId").is_some()
            || req.path().starts_with("/upload/storage/v1/")
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

impl GcsAdapter {
    async fn handle_request(
        &self,
        storage: Arc<dyn Storage>,
        auth_config: Arc<AuthConfig>,
        req: Request,
    ) -> Result<Response<Body>, String> {
        if req.path().starts_with("/upload/storage/v1/b/")
            || req.path().starts_with("/upload/resumable/")
        {
            return self.handle_resumable(storage, auth_config, req).await;
        }

        let (bucket, object) = Self::parse_path(&req);
        let Some(bucket) = bucket else {
            if req.method() == Method::GET {
                let buckets = storage.as_ref().list_namespaces().map_err(|err| err.to_string())?;
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets>{}</Buckets></ListAllMyBucketsResult>",
                    buckets
                        .iter()
                        .map(|bucket| format!("<Bucket><Name>{}</Name></Bucket>", bucket.name))
                        .collect::<Vec<_>>()
                        .join("")
                );
                return Ok(Self::xml_response(StatusCode::OK, body));
            }

            return Ok(Self::error_response(StatusCode::BAD_REQUEST, "InvalidURI", "Missing bucket"));
        };

        if let Err(response) = Self::authorize(&req, &auth_config, &bucket, object.as_deref()) {
            return Ok(response);
        }

        match (req.method(), object) {
            (&Method::PUT, None) => {
                storage.as_ref().create_namespace(bucket).map_err(|err| err.to_string())?;
                Ok(Self::empty_response(StatusCode::OK))
            }
            (&Method::DELETE, None) => {
                storage.as_ref().delete_namespace(&bucket).map_err(|err| err.to_string())?;
                Ok(Self::empty_response(StatusCode::NO_CONTENT))
            }
            (&Method::GET, None) => {
                let blobs = storage
                    .as_ref()
                    .list_blobs(
                        &bucket,
                        req.query_param("prefix"),
                        req.query_param("delimiter"),
                        None,
                        None,
                    )
                    .map_err(|err| err.to_string())?;
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{}</Name>{}</ListBucketResult>",
                    bucket,
                    blobs
                        .iter()
                        .map(|blob| format!(
                            "<Contents><Key>{}</Key><Size>{}</Size><ETag>{}</ETag></Contents>",
                            blob.key, blob.size, blob.etag
                        ))
                        .collect::<Vec<_>>()
                        .join("")
                );
                Ok(Self::xml_response(StatusCode::OK, body))
            }
            (&Method::PUT, Some(object)) => {
                let stored = storage
                    .as_ref()
                    .put_blob(PutBlobRequest {
                        namespace: bucket,
                        key: object,
                        data: req.body.to_vec(),
                        content_type: req.header("content-type").unwrap_or("application/octet-stream").to_string(),
                        metadata: HashMap::new(),
                        tags: HashMap::new(),
                    })
                    .map_err(|err| err.to_string())?;
                Ok(Self::response(StatusCode::OK)
                    .header("etag", &format!("\"{}\"", stored.etag))
                    .empty())
            }
            (&Method::GET, Some(object)) => {
                let blob = storage.as_ref().get_blob(&bucket, &object).map_err(|err| err.to_string())?;
                Ok(Self::response(StatusCode::OK)
                    .header("content-length", &blob.size.to_string())
                    .header("content-type", &blob.content_type)
                    .header("etag", &format!("\"{}\"", blob.etag))
                    .body(blob.data)
                    .build())
            }
            (&Method::HEAD, Some(object)) => {
                let blob = storage.as_ref().get_blob(&bucket, &object).map_err(|err| err.to_string())?;
                Ok(Self::response(StatusCode::OK)
                    .header("content-length", &blob.size.to_string())
                    .header("content-type", &blob.content_type)
                    .header("etag", &format!("\"{}\"", blob.etag))
                    .empty())
            }
            (&Method::DELETE, Some(object)) => {
                storage.as_ref().delete_blob(&bucket, &object).map_err(|err| err.to_string())?;
                Ok(Self::empty_response(StatusCode::NO_CONTENT))
            }
            _ => Ok(Self::error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UnsupportedHttpVerb",
                "Unsupported GCS operation",
            )),
        }
    }

    async fn handle_resumable(
        &self,
        storage: Arc<dyn Storage>,
        auth_config: Arc<AuthConfig>,
        req: Request,
    ) -> Result<Response<Body>, String> {
        let parts: Vec<&str> = req
            .path()
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();

        if parts.starts_with(&["upload", "storage", "v1", "b"]) && parts.len() >= 6 {
            let bucket = parts[4].to_string();
            if let Err(response) = Self::authorize(&req, &auth_config, &bucket, None) {
                return Ok(response);
            }
            let key = req
                .query_param("name")
                .ok_or_else(|| "Missing resumable upload object name".to_string())?
                .to_string();
            let session_id = uuid::Uuid::new_v4().to_string();
            self.resumable_sessions
                .lock()
                .map_err(|_| "Failed to lock resumable sessions".to_string())?
                .insert(
                    session_id.clone(),
                    ResumableSession {
                        bucket,
                        key,
                        content_type: req.header("x-upload-content-type").unwrap_or("application/octet-stream").to_string(),
                    },
                );
            return Ok(Self::response(StatusCode::OK)
                .header(
                    "location",
                    &format!("http://storage.localhost/upload/resumable/{}", session_id),
                )
                .empty());
        }

        let parts: Vec<&str> = req
            .path()
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if parts.starts_with(&["upload", "resumable"]) && parts.len() == 3 {
            let session_id = parts[2];
            let mut sessions = self
                .resumable_sessions
                .lock()
                .map_err(|_| "Failed to lock resumable sessions".to_string())?;
            let session = sessions
                .remove(session_id)
                .ok_or_else(|| "Unknown resumable upload session".to_string())?;
            let stored = storage
                .as_ref()
                .put_blob(PutBlobRequest {
                    namespace: session.bucket,
                    key: session.key,
                    data: req.body.to_vec(),
                    content_type: session.content_type,
                    metadata: HashMap::new(),
                    tags: HashMap::new(),
                })
                .map_err(|err| err.to_string())?;
            return Ok(Self::json_response(
                StatusCode::OK,
                &format!(
                    "{{\"kind\":\"storage#object\",\"name\":\"{}\",\"etag\":\"{}\"}}",
                    stored.key, stored.etag
                ),
            ));
        }

        Ok(Self::error_response(
            StatusCode::BAD_REQUEST,
            "InvalidURI",
            "Unsupported resumable upload path",
        ))
    }
}
