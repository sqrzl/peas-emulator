use super::ProviderAdapter;
use crate::auth::{AuthConfig, HttpRequestLike};
use crate::blob::{BlobBackend, PutBlobRequest};
use crate::server::{RequestExt as Request, ResponseBuilder};
use crate::storage::Storage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::{Method, StatusCode};
use hyper::{Body, Response};
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::Sha256;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

const AZURE_VERSION: &str = "2023-11-03";

#[derive(Default)]
struct AzureBlockSession {
    blocks: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct AzureResource {
    account: String,
    container: Option<String>,
    blob: Option<String>,
}

pub struct AzureBlobAdapter {
    block_sessions: Mutex<HashMap<String, AzureBlockSession>>,
}

impl AzureBlobAdapter {
    pub fn new() -> Self {
        Self {
            block_sessions: Mutex::new(HashMap::new()),
        }
    }

    fn parse_resource(req: &Request) -> Result<AzureResource, String> {
        let parts: Vec<&str> = req
            .path()
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();

        if parts.is_empty() {
            return Err("Azure requests must include an account segment".to_string());
        }

        Ok(AzureResource {
            account: parts[0].to_string(),
            container: parts.get(1).map(|segment| (*segment).to_string()),
            blob: if parts.len() > 2 {
                Some(parts[2..].join("/"))
            } else {
                None
            },
        })
    }

    fn request_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn response(status: StatusCode) -> ResponseBuilder {
        ResponseBuilder::new(status)
            .header("x-ms-version", AZURE_VERSION)
            .header("x-ms-request-id", &Self::request_id())
            .header("date", &crate::utils::headers::format_last_modified())
    }

    fn empty_response(status: StatusCode) -> Response<Body> {
        Self::response(status).empty()
    }

    fn xml_response(status: StatusCode, body: String) -> Response<Body> {
        Self::response(status)
            .content_type("application/xml")
            .body(body.into_bytes())
            .build()
    }

    fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Body> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>{}</Code><Message>{}</Message></Error>",
            escape_xml(code),
            escape_xml(message),
        );

        Self::response(status)
            .content_type("application/xml")
            .header("x-ms-error-code", code)
            .body(body.into_bytes())
            .build()
    }

    fn metadata_from_headers(req: &Request) -> HashMap<String, String> {
        req.headers()
            .into_iter()
            .filter_map(|(name, value)| {
                name.strip_prefix("x-ms-meta-")
                    .map(|key| (key.to_string(), value))
            })
            .collect()
    }

    fn content_type(req: &Request) -> String {
        req.header("x-ms-blob-content-type")
            .or_else(|| req.header("content-type"))
            .unwrap_or("application/octet-stream")
            .to_string()
    }

    fn list_containers_xml(account: &str, namespaces: &[crate::blob::Namespace]) -> String {
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults ServiceEndpoint=\"http://127.0.0.1:9000/{}\"><Containers>",
            escape_xml(account)
        );

        for namespace in namespaces {
            xml.push_str(&format!(
                "<Container><Name>{}</Name><Properties><Last-Modified>{}</Last-Modified><Etag>\"{}\"</Etag></Properties></Container>",
                escape_xml(&namespace.name),
                namespace.created_at.to_rfc2822(),
                crate::utils::headers::compute_etag(namespace.name.as_bytes()),
            ));
        }

        xml.push_str("</Containers><NextMarker /></EnumerationResults>");
        xml
    }

    fn list_blobs_xml(container: &str, blobs: &[crate::blob::BlobRecord]) -> String {
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults ContainerName=\"{}\"><Blobs>",
            escape_xml(container)
        );

        for blob in blobs {
            xml.push_str(&format!(
                "<Blob><Name>{}</Name><Properties><Content-Length>{}</Content-Length><Content-Type>{}</Content-Type><Etag>\"{}\"</Etag><BlobType>BlockBlob</BlobType><Last-Modified>{}</Last-Modified></Properties></Blob>",
                escape_xml(&blob.key),
                blob.size,
                escape_xml(&blob.content_type),
                escape_xml(&blob.etag),
                blob.last_modified.to_rfc2822(),
            ));
        }

        xml.push_str("</Blobs><NextMarker /></EnumerationResults>");
        xml
    }

    fn canonicalized_headers(req: &Request) -> String {
        let mut headers: Vec<(String, String)> = req
            .headers()
            .into_iter()
            .filter(|(name, _)| name.starts_with("x-ms-"))
            .map(|(name, value)| {
                (
                    name.to_lowercase(),
                    value.split_whitespace().collect::<Vec<_>>().join(" "),
                )
            })
            .collect();
        headers.sort_by(|left, right| left.0.cmp(&right.0));

        headers
            .into_iter()
            .map(|(name, value)| format!("{}:{}\n", name, value))
            .collect::<String>()
    }

    fn canonicalized_resource(req: &Request, account: &str) -> String {
        let mut resource = format!("/{}{}", account, req.path());
        let mut query_map: HashMap<String, Vec<String>> = HashMap::new();
        for (key, value) in &req.query_params {
            query_map
                .entry(key.to_lowercase())
                .or_default()
                .push(value.to_string());
        }

        let mut keys: Vec<_> = query_map.keys().cloned().collect();
        keys.sort();
        for key in keys {
            let mut values = query_map.remove(&key).unwrap_or_default();
            values.sort();
            resource.push_str(&format!("\n{}:{}", key, values.join(",")));
        }

        resource
    }

    fn shared_key_secret(config: &AuthConfig) -> Option<Vec<u8>> {
        let secret = config.secret_key()?;
        BASE64.decode(secret).ok().or_else(|| Some(secret.as_bytes().to_vec()))
    }

    fn shared_key_string_to_sign(req: &Request, account: &str) -> String {
        let content_length = match req.method() {
            &Method::GET | &Method::HEAD => String::new(),
            _ => req
                .header("content-length")
                .filter(|value| *value != "0")
                .unwrap_or("")
                .to_string(),
        };

        [
            req.method().as_str().to_string(),
            req.header("content-encoding").unwrap_or("").to_string(),
            req.header("content-language").unwrap_or("").to_string(),
            content_length,
            req.header("content-md5").unwrap_or("").to_string(),
            req.header("content-type").unwrap_or("").to_string(),
            String::new(),
            req.header("if-modified-since").unwrap_or("").to_string(),
            req.header("if-match").unwrap_or("").to_string(),
            req.header("if-none-match").unwrap_or("").to_string(),
            req.header("if-unmodified-since").unwrap_or("").to_string(),
            req.header("range").unwrap_or("").to_string(),
            Self::canonicalized_headers(req),
            Self::canonicalized_resource(req, account),
        ]
        .join("\n")
    }

    fn validate_shared_key(
        req: &Request,
        config: &AuthConfig,
        account: &str,
    ) -> Result<(), String> {
        let authorization = req
            .header("authorization")
            .ok_or_else(|| "Missing Authorization header".to_string())?;
        let prefix = format!("SharedKey {}:", account);
        let provided = authorization
            .strip_prefix(&prefix)
            .ok_or_else(|| "Unsupported Azure authorization scheme".to_string())?;
        let key =
            Self::shared_key_secret(config).ok_or_else(|| "Missing Azure shared key".to_string())?;
        let expected = sign_hmac_base64(&key, &Self::shared_key_string_to_sign(req, account))?;

        if provided == expected {
            Ok(())
        } else {
            Err("Azure shared key signature mismatch".to_string())
        }
    }

    fn sas_string_to_sign(
        resource: &str,
        permissions: &str,
        starts_on: &str,
        expires_on: &str,
        version: &str,
        resource_type: &str,
    ) -> String {
        [
            permissions,
            starts_on,
            expires_on,
            resource,
            "",
            "",
            "",
            version,
            resource_type,
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        .join("\n")
    }

    fn validate_sas(
        req: &Request,
        config: &AuthConfig,
        resource: &AzureResource,
    ) -> Result<(), String> {
        let signature = req
            .query_param("sig")
            .ok_or_else(|| "Missing SAS signature".to_string())?;
        let expires_on = req
            .query_param("se")
            .ok_or_else(|| "Missing SAS expiry".to_string())?;
        let permissions = req.query_param("sp").unwrap_or("");
        let starts_on = req.query_param("st").unwrap_or("");
        let version = req.query_param("sv").unwrap_or("");
        let resource_type = req.query_param("sr").unwrap_or("");

        let expiry = DateTime::parse_from_rfc3339(expires_on)
            .or_else(|_| DateTime::parse_from_str(expires_on, "%Y-%m-%dT%H:%M:%SZ"))
            .map_err(|_| "Invalid SAS expiry".to_string())?
            .with_timezone(&Utc);

        if Utc::now() > expiry {
            return Err("SAS token has expired".to_string());
        }

        let canonical_resource = if let Some(container) = &resource.container {
            if let Some(blob) = &resource.blob {
                format!("/blob/{}/{}/{}", resource.account, container, blob)
            } else {
                format!("/blob/{}/{}", resource.account, container)
            }
        } else {
            format!("/blob/{}", resource.account)
        };

        let key =
            Self::shared_key_secret(config).ok_or_else(|| "Missing Azure shared key".to_string())?;
        let expected = sign_hmac_base64(
            &key,
            &Self::sas_string_to_sign(
                &canonical_resource,
                permissions,
                starts_on,
                expires_on,
                version,
                resource_type,
            ),
        )?;

        if expected == signature {
            Ok(())
        } else {
            Err("Azure SAS signature mismatch".to_string())
        }
    }

    fn authorize(
        req: &Request,
        config: &AuthConfig,
        resource: &AzureResource,
    ) -> Result<(), Response<Body>> {
        if !config.enforce_auth {
            return Ok(());
        }

        if req.query_param("sig").is_some() {
            return Self::validate_sas(req, config, resource).map_err(|msg| {
                Self::error_response(StatusCode::FORBIDDEN, "AuthenticationFailed", &msg)
            });
        }

        Self::validate_shared_key(req, config, &resource.account).map_err(|msg| {
            Self::error_response(StatusCode::FORBIDDEN, "AuthenticationFailed", &msg)
        })
    }

    fn parse_block_list(xml: &str) -> Result<Vec<String>, String> {
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);
        let mut buf = Vec::new();
        let mut in_name = false;
        let mut block_ids = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(event)) => {
                    if matches!(event.name().as_ref(), b"Latest" | b"Committed" | b"Uncommitted")
                    {
                        in_name = true;
                    }
                }
                Ok(Event::End(event)) => {
                    if matches!(event.name().as_ref(), b"Latest" | b"Committed" | b"Uncommitted")
                    {
                        in_name = false;
                    }
                }
                Ok(Event::Text(text)) if in_name => {
                    block_ids.push(
                        text.unescape()
                            .map_err(|err| err.to_string())?
                            .to_string(),
                    );
                }
                Ok(Event::Eof) => break,
                Err(err) => return Err(err.to_string()),
                _ => {}
            }
            buf.clear();
        }

        if block_ids.is_empty() {
            return Err("Block list cannot be empty".to_string());
        }

        Ok(block_ids)
    }
}

impl ProviderAdapter for AzureBlobAdapter {
    fn name(&self) -> &'static str {
        "azure-blob"
    }

    fn matches(&self, req: &Request) -> bool {
        req.header("x-ms-version").is_some()
            || req
                .header("authorization")
                .map(|value| value.starts_with("SharedKey "))
                .unwrap_or(false)
            || req.header("x-ms-blob-type").is_some()
            || req.query_param("restype").is_some()
            || req.query_param("comp").is_some()
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

impl AzureBlobAdapter {
    async fn handle_request(
        &self,
        storage: Arc<dyn Storage>,
        auth_config: Arc<AuthConfig>,
        req: Request,
    ) -> Result<Response<Body>, String> {
        let resource = match Self::parse_resource(&req) {
            Ok(resource) => resource,
            Err(msg) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, "InvalidUri", &msg)),
        };

        if let Err(response) = Self::authorize(&req, &auth_config, &resource) {
            return Ok(response);
        }

        if resource.container.is_none() {
            if req.method() == Method::GET && req.query_param("comp") == Some("list") {
                let namespaces = storage.as_ref().list_namespaces().map_err(|err| err.to_string())?;
                return Ok(Self::xml_response(
                    StatusCode::OK,
                    Self::list_containers_xml(&resource.account, &namespaces),
                ));
            }

            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "InvalidUri",
                "Azure account requests must use comp=list",
            ));
        }

        let container = resource.container.clone().unwrap_or_default();
        if req.query_param("restype") == Some("container") {
            return match req.method() {
                &Method::PUT => {
                    storage.as_ref().create_namespace(container).map_err(|err| err.to_string())?;
                    Ok(Self::empty_response(StatusCode::CREATED))
                }
                &Method::DELETE => {
                    storage.as_ref().delete_namespace(&container).map_err(|err| err.to_string())?;
                    Ok(Self::empty_response(StatusCode::ACCEPTED))
                }
                &Method::GET => {
                    if req.query_param("comp") == Some("list") {
                        let blobs = storage
                            .as_ref()
                            .list_blobs(
                                &container,
                                req.query_param("prefix"),
                                req.query_param("delimiter"),
                                None,
                                None,
                            )
                            .map_err(|err| err.to_string())?;
                        Ok(Self::xml_response(
                            StatusCode::OK,
                            Self::list_blobs_xml(&container, &blobs),
                        ))
                    } else {
                        storage.as_ref().get_namespace(&container).map_err(|err| err.to_string())?;
                        Ok(Self::empty_response(StatusCode::OK))
                    }
                }
                _ => Ok(Self::error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "UnsupportedHttpVerb",
                    "Unsupported Azure container operation",
                )),
            };
        }

        let Some(blob_key) = resource.blob.clone() else {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "InvalidUri",
                "Blob requests must include a blob name",
            ));
        };

        if req.method() == Method::PUT && req.query_param("comp") == Some("block") {
            let block_id = req
                .query_param("blockid")
                .ok_or_else(|| "Missing blockid query parameter".to_string())?;
            let session_key = format!("{}/{}/{}", resource.account, container, blob_key);
            let mut sessions = self
                .block_sessions
                .lock()
                .map_err(|_| "Failed to lock Azure block session state".to_string())?;
            sessions
                .entry(session_key)
                .or_default()
                .blocks
                .insert(block_id.to_string(), req.body.to_vec());

            return Ok(Self::response(StatusCode::CREATED).empty());
        }

        if req.method() == Method::PUT && req.query_param("comp") == Some("blocklist") {
            let block_ids = Self::parse_block_list(
                &String::from_utf8(req.body.to_vec()).map_err(|err| err.to_string())?,
            )?;
            let session_key = format!("{}/{}/{}", resource.account, container, blob_key);
            let mut sessions = self
                .block_sessions
                .lock()
                .map_err(|_| "Failed to lock Azure block session state".to_string())?;
            let session = sessions
                .remove(&session_key)
                .ok_or_else(|| "No staged Azure blocks were found".to_string())?;
            let upload = storage
                .as_ref()
                .create_upload_session(&container, blob_key.clone())
                .map_err(|err| err.to_string())?;

            for (index, block_id) in block_ids.iter().enumerate() {
                let block = session
                    .blocks
                    .get(block_id)
                    .ok_or_else(|| format!("Unknown block id {}", block_id))?;
                storage
                    .as_ref()
                    .upload_session_part(&container, &upload.upload_id, index as u32 + 1, block.clone())
                    .map_err(|err| err.to_string())?;
            }

            storage
                .as_ref()
                .complete_upload_session(&container, &upload.upload_id)
                .map_err(|err| err.to_string())?;

            return Ok(Self::empty_response(StatusCode::CREATED));
        }

        match req.method() {
            &Method::PUT => {
                let stored = storage
                    .as_ref()
                    .put_blob(PutBlobRequest {
                        namespace: container.clone(),
                        key: blob_key.clone(),
                        data: req.body.to_vec(),
                        content_type: Self::content_type(&req),
                        metadata: Self::metadata_from_headers(&req),
                        tags: HashMap::new(),
                    })
                    .map_err(|err| err.to_string())?;
                Ok(Self::response(StatusCode::CREATED)
                    .header("etag", &format!("\"{}\"", stored.etag))
                    .header("last-modified", &stored.last_modified.to_rfc2822())
                    .header("x-ms-blob-type", req.header("x-ms-blob-type").unwrap_or("BlockBlob"))
                    .empty())
            }
            &Method::GET => {
                let blob = storage.as_ref().get_blob(&container, &blob_key).map_err(|err| err.to_string())?;
                let mut builder = Self::response(StatusCode::OK)
                    .header("content-length", &blob.size.to_string())
                    .header("content-type", &blob.content_type)
                    .header("etag", &format!("\"{}\"", blob.etag))
                    .header("last-modified", &blob.last_modified.to_rfc2822())
                    .header("x-ms-blob-type", "BlockBlob");
                for (key, value) in blob.metadata {
                    builder = builder.header(&format!("x-ms-meta-{}", key), &value);
                }
                Ok(builder.body(blob.data).build())
            }
            &Method::HEAD => {
                let blob = storage.as_ref().get_blob(&container, &blob_key).map_err(|err| err.to_string())?;
                let mut builder = Self::response(StatusCode::OK)
                    .header("content-length", &blob.size.to_string())
                    .header("content-type", &blob.content_type)
                    .header("etag", &format!("\"{}\"", blob.etag))
                    .header("last-modified", &blob.last_modified.to_rfc2822())
                    .header("x-ms-blob-type", "BlockBlob");
                for (key, value) in blob.metadata {
                    builder = builder.header(&format!("x-ms-meta-{}", key), &value);
                }
                Ok(builder.empty())
            }
            &Method::DELETE => {
                storage.as_ref().delete_blob(&container, &blob_key).map_err(|err| err.to_string())?;
                Ok(Self::empty_response(StatusCode::ACCEPTED))
            }
            _ => Ok(Self::error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "UnsupportedHttpVerb",
                "Unsupported Azure blob operation",
            )),
        }
    }
}

fn sign_hmac_base64(key: &[u8], payload: &str) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|err| format!("Invalid Azure signing key: {}", err))?;
    mac.update(payload.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::FilesystemStorage;
    use hyper::Request as HyperRequest;
    use std::fs;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir = std::env::temp_dir().join(format!("peas-azure-test-{}", uuid::Uuid::new_v4()));
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

    fn azure_auth() -> Arc<AuthConfig> {
        Arc::new(Config {
            access_key_id: Some("devstoreaccount1".to_string()),
            secret_access_key: Some(BASE64.encode("topsecretkey")),
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

    fn signed_headers(req: &Request, config: &AuthConfig, account: &str) -> String {
        let string_to_sign = AzureBlobAdapter::shared_key_string_to_sign(req, account);
        let key = AzureBlobAdapter::shared_key_secret(config).expect("key should exist");
        format!(
            "SharedKey {}:{}",
            account,
            sign_hmac_base64(&key, &string_to_sign).expect("signature should build")
        )
    }

    fn sas_signature(resource: &str, config: &AuthConfig, permissions: &str, expires: &str) -> String {
        let key = AzureBlobAdapter::shared_key_secret(config).expect("key should exist");
        let payload = AzureBlobAdapter::sas_string_to_sign(
            resource,
            permissions,
            "",
            expires,
            "2023-11-03",
            "b",
        );
        sign_hmac_base64(&key, &payload).expect("signature should build")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_create_list_and_fetch_azure_blobs() {
        let adapter = AzureBlobAdapter::new();
        let storage = temp_storage();

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/devstoreaccount1/photos?restype=container",
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("container create should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/devstoreaccount1/photos/kitten.txt",
                    &[
                        ("x-ms-version", AZURE_VERSION),
                        ("x-ms-blob-type", "BlockBlob"),
                        ("x-ms-meta-owner", "alice"),
                        ("content-type", "text/plain"),
                    ],
                    b"hello azure",
                )
                .await,
            )
            .await
            .expect("put blob should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "GET",
                    "http://localhost/devstoreaccount1/photos?restype=container&comp=list",
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("list blobs should succeed");
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
                    "http://localhost/devstoreaccount1/photos/kitten.txt",
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("get blob should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert_eq!(body.as_ref(), b"hello azure");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_commit_block_blob_from_put_block_list() {
        let adapter = AzureBlobAdapter::new();
        let storage = temp_storage();

        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/devstoreaccount1/archive?restype=container",
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("container create should succeed");

        let block_one = BASE64.encode("block-001");
        let block_two = BASE64.encode("block-002");
        for (block_id, payload) in [(&block_one, b"abc".as_slice()), (&block_two, b"def".as_slice())] {
            let response = adapter
                .handle_request(
                    storage.clone(),
                    auth_disabled(),
                    parsed_request(
                        "PUT",
                        &format!(
                            "http://localhost/devstoreaccount1/archive/report.txt?comp=block&blockid={}",
                            urlencoding::encode(block_id)
                        ),
                        &[("x-ms-version", AZURE_VERSION)],
                        payload,
                    )
                    .await,
                )
                .await
                .expect("put block should succeed");
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        let block_list = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{}</Latest><Latest>{}</Latest></BlockList>",
            block_one, block_two
        );
        adapter
            .handle_request(
                storage.clone(),
                auth_disabled(),
                parsed_request(
                    "PUT",
                    "http://localhost/devstoreaccount1/archive/report.txt?comp=blocklist",
                    &[("x-ms-version", AZURE_VERSION), ("content-type", "application/xml")],
                    block_list.as_bytes(),
                )
                .await,
            )
            .await
            .expect("put block list should succeed");

        let response = adapter
            .handle_request(
                storage,
                auth_disabled(),
                parsed_request(
                    "GET",
                    "http://localhost/devstoreaccount1/archive/report.txt",
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("get blob should succeed");
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("body should read");
        assert_eq!(body.as_ref(), b"abcdef");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn should_validate_azure_shared_key_and_sas_authorization() {
        let adapter = AzureBlobAdapter::new();
        let storage = temp_storage();
        storage.create_bucket("secure".to_string()).unwrap();
        storage
            .put_object(
                "secure",
                "blob.txt".to_string(),
                crate::models::Object::new(
                    "blob.txt".to_string(),
                    b"secret".to_vec(),
                    "text/plain".to_string(),
                ),
            )
            .unwrap();

        let mut shared_key_request = parsed_request(
            "GET",
            "http://localhost/devstoreaccount1?comp=list",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-date", "Sat, 01 Jan 2024 00:00:00 +0000"),
                ("host", "localhost:9000"),
            ],
            b"",
        )
        .await;
        let auth = signed_headers(&shared_key_request, &azure_auth(), "devstoreaccount1");
        shared_key_request
            .headers
            .insert("authorization", auth.parse().expect("header should parse"));

        let response = adapter
            .handle_request(storage.clone(), azure_auth(), shared_key_request)
            .await
            .expect("shared key request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let expiry = "2035-01-01T00:00:00Z";
        let canonical_resource = "/blob/devstoreaccount1/secure/blob.txt";
        let sig = sas_signature(canonical_resource, &azure_auth(), "r", expiry);
        let response = adapter
            .handle_request(
                storage,
                azure_auth(),
                parsed_request(
                    "GET",
                    &format!(
                        "http://localhost/devstoreaccount1/secure/blob.txt?sp=r&se={}&sv=2023-11-03&sr=b&sig={}",
                        urlencoding::encode(expiry),
                        urlencoding::encode(&sig)
                    ),
                    &[("x-ms-version", AZURE_VERSION)],
                    b"",
                )
                .await,
            )
            .await
            .expect("sas request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
