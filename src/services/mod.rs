use crate::error::Error;
use crate::server::ResponseBuilder;
use crate::utils::{headers as header_utils, xml as xml_utils};
use http::StatusCode;
use hyper::{Body, Response};

pub fn xml_error_response(
    status: StatusCode,
    error_code: &str,
    message: &str,
    req_id: &str,
) -> Response<Body> {
    let xml = xml_utils::error_xml(error_code, message, req_id);

    ResponseBuilder::new(status)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", req_id)
        .body(xml.into_bytes())
        .build()
}

pub fn xml_success_response(status: StatusCode, xml: String, req_id: &str) -> Response<Body> {
    ResponseBuilder::new(status)
        .content_type("application/xml; charset=utf-8")
        .header("x-amz-request-id", req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .body(xml.into_bytes())
        .build()
}

pub fn empty_success_response(status: StatusCode, req_id: &str) -> Response<Body> {
    ResponseBuilder::new(status)
        .header("x-amz-request-id", req_id)
        .header("x-amz-id-2", &header_utils::generate_request_id())
        .empty()
}

pub fn storage_error_response(error: &Error, req_id: &str) -> Response<Body> {
    xml_error_response(
        error.status_code(),
        error.error_code(),
        &error.to_string(),
        req_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_render_storage_errors_as_xml_responses() {
        let response = storage_error_response(&Error::BucketNotFound, "req-1");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get("x-amz-request-id").unwrap(), "req-1");

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<Code>NoSuchBucket</Code>"));
        assert!(body.contains("<Message>Bucket not found</Message>"));
    }

    #[tokio::test]
    async fn should_render_standard_xml_success_headers() {
        let response = xml_success_response(StatusCode::OK, "<ok/>".to_string(), "req-2");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/xml; charset=utf-8"
        );
        assert_eq!(response.headers().get("x-amz-request-id").unwrap(), "req-2");
        assert!(response.headers().get("x-amz-id-2").is_some());

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(body.as_ref(), b"<ok/>");
    }
}
