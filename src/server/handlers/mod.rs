use super::http::{Request, ResponseBuilder, RouteMatch, Router};
use crate::auth::AuthConfig;
use crate::storage::Storage;
use crate::utils::{headers as header_utils, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};
use std::sync::Arc;

mod auth;
mod bucket;
mod object;

#[allow(unused_imports)]
pub(crate) use auth::{
    build_canonical_request, check_authorization, extract_credential_scope, extract_signed_headers,
    extract_sigv4_signature, verify_sigv4_signature,
};
pub use bucket::{
    bucket_delete, bucket_get_or_list_objects, bucket_head, bucket_post, bucket_put, list_buckets,
};
pub use object::{object_delete, object_get, object_head, object_post, object_put};

pub async fn handle_request(
    storage: Arc<dyn Storage>,
    auth_config: Arc<AuthConfig>,
    req: Request,
) -> Result<Response<Body>, String> {
    let route = Router::route(req.method(), req.path());
    let req_id = header_utils::generate_request_id();

    match route {
        RouteMatch::ListBuckets => list_buckets(storage, auth_config, req, req_id).await,

        RouteMatch::BucketGet(bucket) => {
            bucket_get_or_list_objects(storage, &bucket, &req, req_id).await
        }

        RouteMatch::BucketPut(bucket) => {
            bucket_put(storage, auth_config, &bucket, &req, req_id).await
        }

        RouteMatch::BucketDelete(bucket) => {
            bucket_delete(storage, auth_config, &bucket, &req, req_id).await
        }

        RouteMatch::BucketHead(bucket) => bucket_head(storage, &bucket, req_id).await,

        RouteMatch::BucketPost(bucket) => bucket_post(storage, &bucket, &req, req_id).await,

        RouteMatch::ObjectGet(bucket, key) => {
            object_get(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectPut(bucket, key) => {
            object_put(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectDelete(bucket, key) => {
            object_delete(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectHead(bucket, key) => {
            object_head(storage, auth_config, &bucket, &key, &req, req_id).await
        }

        RouteMatch::ObjectPost(bucket, key) => {
            object_post(storage, &bucket, &key, &req, req_id).await
        }

        RouteMatch::NotFound => {
            let xml = xml_utils::error_xml("NotFound", "Not Found", &req_id);
            Ok(ResponseBuilder::new(StatusCode::NOT_FOUND)
                .content_type("application/xml; charset=utf-8")
                .header("x-amz-request-id", &req_id)
                .body(xml.into_bytes())
                .build())
        }
    }
}
