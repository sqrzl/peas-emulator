use thiserror::Error;

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

impl Error {
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            Error::BucketAlreadyExists => http::StatusCode::CONFLICT,
            Error::BucketNotFound => http::StatusCode::NOT_FOUND,
            Error::BucketNotEmpty => http::StatusCode::CONFLICT,
            Error::KeyNotFound => http::StatusCode::NOT_FOUND,
            Error::InvalidRequest(_) => http::StatusCode::BAD_REQUEST,
            Error::AccessDenied => http::StatusCode::FORBIDDEN,
            Error::InvalidUploadId => http::StatusCode::NOT_FOUND,
            Error::NoSuchUpload => http::StatusCode::NOT_FOUND,
            Error::InvalidPartNumber => http::StatusCode::BAD_REQUEST,
            Error::InvalidPartOrder => http::StatusCode::BAD_REQUEST,
            Error::IncompleteMultipartUpload => http::StatusCode::BAD_REQUEST,
            Error::NoSuchVersion => http::StatusCode::NOT_FOUND,
            Error::NoSuchLifecycleConfiguration => http::StatusCode::NOT_FOUND,
            Error::InvalidPolicy(_) => http::StatusCode::BAD_REQUEST,
            Error::SignatureDoesNotMatch => http::StatusCode::FORBIDDEN,
            Error::InternalError(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
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
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}
