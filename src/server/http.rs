use bytes::Bytes;
use http::{Method, StatusCode, Uri, Response as HttpResponse};
use hyper::{Body, Request as HyperRequest};
use std::collections::HashMap;
use std::str::FromStr;
use crate::auth::HttpRequestLike;

/// Parsed HTTP request with extracted components
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    pub path_params: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

impl HttpRequestLike for Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|h| h.to_str().ok())
    }

    fn query(&self) -> Option<&str> {
        self.uri.query()
    }
}

impl Request {
    pub async fn from_hyper(req: HyperRequest<Body>) -> Result<Self, String> {
        let (parts, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await.map_err(|e| e.to_string())?;

        let mut query_params = HashMap::new();
        if let Some(query) = parts.uri.query() {
            for param in query.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    let decoded_key = urlencoding::decode(key).unwrap_or_default().to_string();
                    let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
                    query_params.insert(decoded_key, decoded_value);
                }
            }
        }

        Ok(Request {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: body_bytes,
            path_params: HashMap::new(),
            query_params,
        })
    }

    pub fn path(&self) -> &str {
        self.uri.path()
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|h| h.to_str().ok())
    }

    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query_params.get(name).map(|s| s.as_str())
    }

    pub fn has_query_param(&self, name: &str) -> bool {
        self.query_params.contains_key(name)
    }
}

/// Builder for HTTP responses
pub struct ResponseBuilder {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl ResponseBuilder {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let Ok(header_name) = http::HeaderName::from_str(name) {
            if let Ok(header_value) = http::HeaderValue::from_str(value) {
                self.headers.insert(header_name, header_value);
            }
        }
        self
    }

    pub fn content_type(self, ct: &str) -> Self {
        self.header("content-type", ct)
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn body_str(self, body: &str) -> Self {
        self.body(body.as_bytes().to_vec())
    }

    pub fn build(self) -> HttpResponse<Body> {
        let content_length = self.body.len();
        
        let mut response = HttpResponse::builder()
            .status(self.status);

        for (name, value) in self.headers.iter() {
            response = response.header(name.clone(), value.clone());
        }

        if content_length > 0 && !self.headers.contains_key("content-length") {
            response = response.header("content-length", content_length.to_string());
        }

        response
            .body(Body::from(self.body))
            .unwrap_or_else(|_| {
                // Last resort fallback - should never fail
                HttpResponse::new(Body::from("Internal Server Error"))
            })
    }

    pub fn empty(self) -> HttpResponse<Body> {
        let mut response = HttpResponse::builder()
            .status(self.status);

        for (name, value) in self.headers.iter() {
            response = response.header(name.clone(), value.clone());
        }

        response
            .body(Body::empty())
            .unwrap_or_else(|_| {
                // Last resort fallback - should never fail
                HttpResponse::new(Body::empty())
            })
    }
}

/// Router for S3 API endpoints
pub struct Router;

impl Router {
    pub fn route(method: &Method, path: &str) -> RouteMatch {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        match parts.as_slice() {
            // List buckets: GET /
            [] if method == Method::GET => RouteMatch::ListBuckets,

            // Bucket operations
            [bucket] => match *method {
                Method::GET => RouteMatch::BucketGet(bucket.to_string()),
                Method::PUT => RouteMatch::BucketPut(bucket.to_string()),
                Method::DELETE => RouteMatch::BucketDelete(bucket.to_string()),
                Method::HEAD => RouteMatch::BucketHead(bucket.to_string()),
                Method::POST => RouteMatch::BucketPost(bucket.to_string()),
                _ => RouteMatch::NotFound,
            },

            // Object operations
            [bucket, key @ ..] if !key.is_empty() => {
                let key = key.join("/");
                match *method {
                    Method::GET => RouteMatch::ObjectGet(bucket.to_string(), key),
                    Method::PUT => RouteMatch::ObjectPut(bucket.to_string(), key),
                    Method::DELETE => RouteMatch::ObjectDelete(bucket.to_string(), key),
                    Method::HEAD => RouteMatch::ObjectHead(bucket.to_string(), key),
                    Method::POST => RouteMatch::ObjectPost(bucket.to_string(), key),
                    _ => RouteMatch::NotFound,
                }
            }

            _ => RouteMatch::NotFound,
        }
    }
}

#[derive(Debug)]
pub enum RouteMatch {
    ListBuckets,
    BucketGet(String),
    BucketPut(String),
    BucketDelete(String),
    BucketHead(String),
    BucketPost(String),
    ObjectGet(String, String),
    ObjectPut(String, String),
    ObjectDelete(String, String),
    ObjectHead(String, String),
    ObjectPost(String, String),
    NotFound,
}
