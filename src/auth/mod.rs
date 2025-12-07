// Authentication and SigV4 verification
pub mod authenticator;
pub mod presigned;
pub mod sigv4;

pub use authenticator::{AuthConfig, AuthInfo, HttpRequestLike};
pub use presigned::PresignedUrl;
pub use sigv4::{SigV4Config, SignatureVerifier};
