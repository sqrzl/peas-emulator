// Authentication and SigV4 verification
pub mod authenticator;
pub mod sigv4;
pub mod presigned;

pub use authenticator::{AuthConfig, AuthInfo, HttpRequestLike};
pub use sigv4::{SignatureVerifier, SigV4Config};
pub use presigned::PresignedUrl;
