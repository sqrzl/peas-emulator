use thiserror::Error;
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bucket already exists")]
    BucketAlreadyExists,
    
    #[error("Bucket not found")]
    BucketNotFound,
    
    #[error("Bucket not empty")]
    BucketNotEmpty,
    
    #[error("Key not found")]
    KeyNotFound,
    
    #[error("Invalid request")]
    InvalidRequest(String),
    
    #[error("Access denied")]
    AccessDenied,
    
    #[error("Invalid multipart upload ID")]
    InvalidUploadId,
    
    #[error("No such upload")]
    NoSuchUpload,
    
    #[error("Invalid part number")]
    InvalidPartNumber,
    
    #[error("Invalid part order")]
    InvalidPartOrder,
    
    #[error("Incomplete multipart upload")]
    IncompleteMultipartUpload,
    
    #[error("No such version")]
    NoSuchVersion,
    
    #[error("No such lifecycle configuration")]
    NoSuchLifecycleConfiguration,
    
    #[error("Invalid policy")]
    InvalidPolicy(String),
    
    #[error("Internal server error")]
    InternalError(String),
    
    #[error("Signature does not match")]
    SignatureDoesNotMatch,
}

pub type Result<T> = std::result::Result<T, Error>;

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::BucketAlreadyExists => StatusCode::CONFLICT,
            Error::BucketNotFound => StatusCode::NOT_FOUND,
            Error::BucketNotEmpty => StatusCode::CONFLICT,
            Error::KeyNotFound => StatusCode::NOT_FOUND,
            Error::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Error::AccessDenied => StatusCode::FORBIDDEN,
            Error::InvalidUploadId => StatusCode::NOT_FOUND,
            Error::NoSuchUpload => StatusCode::NOT_FOUND,
            Error::InvalidPartNumber => StatusCode::BAD_REQUEST,
            Error::InvalidPartOrder => StatusCode::BAD_REQUEST,
            Error::IncompleteMultipartUpload => StatusCode::BAD_REQUEST,
            Error::NoSuchVersion => StatusCode::NOT_FOUND,
            Error::NoSuchLifecycleConfiguration => StatusCode::NOT_FOUND,
            Error::InvalidPolicy(_) => StatusCode::BAD_REQUEST,
            Error::SignatureDoesNotMatch => StatusCode::FORBIDDEN,
            Error::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let code = self.status_code();
        let body = json!({
            "Code": error_code(self),
            "Message": self.to_string(),
        });
        
        HttpResponse::build(code).json(body)
    }
}

fn error_code(error: &Error) -> &'static str {
    match error {
        Error::BucketAlreadyExists => "BucketAlreadyExists",
        Error::BucketNotFound => "NoSuchBucket",
        Error::BucketNotEmpty => "BucketNotEmpty",
        Error::KeyNotFound => "NoSuchKey",
        Error::InvalidRequest(_) => "InvalidRequest",
        Error::AccessDenied => "AccessDenied",
        Error::InvalidUploadId => "NoSuchUpload",
        Error::NoSuchUpload => "NoSuchUpload",
        Error::InvalidPartNumber => "InvalidPartNumber",
        Error::InvalidPartOrder => "InvalidPartOrder",
        Error::IncompleteMultipartUpload => "IncompleteMultipartUpload",
        Error::NoSuchVersion => "NoSuchVersion",
        Error::NoSuchLifecycleConfiguration => "NoSuchLifecycleConfiguration",
        Error::InvalidPolicy(_) => "MalformedPolicy",
        Error::SignatureDoesNotMatch => "SignatureDoesNotMatch",
        Error::InternalError(_) => "InternalError",
    }
}
