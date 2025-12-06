// Authentication and SigV4 verification
pub mod sigv4;
pub mod presigned;

pub use sigv4::SignatureVerifier;
pub use presigned::PresignedUrl;
