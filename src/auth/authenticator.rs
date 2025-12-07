//! Authentication and authorization for the S3 emulator.
//!
//! This module handles:
//! - Extracting and validating credentials from requests
//! - Supporting multiple signature formats (SigV4, v2, presigned URLs)
//!
//! ## Configuration
//!
//! Authentication configuration is loaded from the global `Config` in `config.rs`.
//! Credentials are read from `PEAS_ACCESS_KEY_ID` and `PEAS_SECRET_ACCESS_KEY`
//! environment variables during application startup.
//!
//! If both variables are not set, authentication is disabled and all requests
//! are treated as anonymous.

use crate::config::Config;

/// Type alias for backward compatibility.
/// Use `Config` directly instead.
pub type AuthConfig = Config;

/// Trait for HTTP request abstraction
pub trait HttpRequestLike {
    fn header(&self, name: &str) -> Option<&str>;
    fn query(&self) -> Option<&str>;
}


/// Authentication information extracted from a request.
///
/// Represents either an authenticated principal or an anonymous request.
#[derive(Debug, Clone)]
pub struct AuthInfo {
    /// Principal identifier (ARN or "*" for anonymous)
    pub principal: String,
    /// Whether the request is authenticated
    pub is_authenticated: bool,
}

impl AuthInfo {
    /// Create an anonymous/unauthenticated request context.
    pub fn anonymous() -> Self {
        Self {
            principal: "*".to_string(),
            is_authenticated: false,
        }
    }

    /// Create an authenticated request context with the given principal.
    pub fn authenticated(principal: String) -> Self {
        Self {
            principal,
            is_authenticated: true,
        }
    }

    /// Extract authentication information from an HTTP request.
    ///
    /// Attempts to extract and validate credentials from:
    /// 1. Authorization header (SigV4 or v2)
    /// 2. Query parameters (presigned URLs)
    ///
    /// Returns an anonymous context if no valid credentials are found
    /// or if authentication is disabled.
    pub fn from_request(req: &dyn HttpRequestLike, config: &Config) -> Self {
        if !config.enforce_auth {
            // Auth is disabled, treat as authenticated with default principal
            return Self::authenticated("peas-emulator".to_string());
        }

        // Try to extract credentials from Authorization header
        if let Some(auth_str) = req.header("authorization") {
            // Check for AWS4-HMAC-SHA256 (SigV4)
            if auth_str.starts_with("AWS4-HMAC-SHA256") {
                if let Some(principal) = Self::extract_sigv4_principal(auth_str, config) {
                    return Self::authenticated(principal);
                }
            }
            // Check for AWS Signature Version 2
            else if auth_str.starts_with("AWS ") {
                if let Some(principal) = Self::extract_v2_principal(auth_str, config) {
                    return Self::authenticated(principal);
                }
            }
        }

        // Check query parameters for presigned URLs
        if let Some(query) = req.query() {
            if query.contains("X-Amz-Credential") || query.contains("AWSAccessKeyId") {
                if let Some(principal) = Self::extract_presigned_principal(query, config) {
                    return Self::authenticated(principal);
                }
            }
        }

        // No valid authentication found
        Self::anonymous()
    }

    /// Extract principal from AWS Signature Version 4 Authorization header.
    ///
    /// Format: `AWS4-HMAC-SHA256 Credential=AKID/date/region/s3/aws4_request, ...`
    pub(crate) fn extract_sigv4_principal(auth_str: &str, config: &Config) -> Option<String> {
        for part in auth_str.split(',') {
            let part = part.trim();
            // Look for Credential= anywhere in the part, not just at the start
            if let Some(cred_start) = part.find("Credential=") {
                let credential = &part[cred_start + 11..]; // Skip "Credential="
                let access_key = credential.split('/').next()?;

                // Validate the access key matches configured credentials
                if let Some(configured_key) = config.access_key() {
                    if access_key == configured_key {
                        return Some(format!("arn:aws:iam::000000000000:user/{}", access_key));
                    }
                }
            }
        }
        None
    }

    /// Extract principal from AWS Signature Version 2 Authorization header.
    ///
    /// Format: `AWS AKIAIOSFODNN7EXAMPLE:signature`
    pub(crate) fn extract_v2_principal(auth_str: &str, config: &Config) -> Option<String> {
        let rest = auth_str.strip_prefix("AWS ")?;
        let access_key = rest.split(':').next()?;

        // Validate the access key matches configured credentials
        if let Some(configured_key) = config.access_key() {
            if access_key == configured_key {
                return Some(format!("arn:aws:iam::000000000000:user/{}", access_key));
            }
        }
        None
    }

    /// Extract principal from presigned URL query parameters.
    ///
    /// Supports both:
    /// - `X-Amz-Credential=AKID/date/region/s3/aws4_request`
    /// - `AWSAccessKeyId=AKID`
    pub(crate) fn extract_presigned_principal(query: &str, config: &Config) -> Option<String> {
        for param in query.split('&') {
            let (key, value) = param.split_once('=')?;

            if key == "X-Amz-Credential" {
                // Extract access key from credential (before first /)
                let access_key = value.split('/').next()?;
                if let Some(configured_key) = config.access_key() {
                    if access_key == configured_key {
                        return Some(format!("arn:aws:iam::000000000000:user/{}", access_key));
                    }
                }
            } else if key == "AWSAccessKeyId" {
                if let Some(configured_key) = config.access_key() {
                    if value == configured_key {
                        return Some(format!("arn:aws:iam::000000000000:user/{}", value));
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config(
        access_key: Option<&str>,
        secret_key: Option<&str>,
        enforce_auth: bool,
    ) -> Config {
        Config {
            access_key_id: access_key.map(|k| k.to_string()),
            secret_access_key: secret_key.map(|k| k.to_string()),
            enforce_auth,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        }
    }

    #[test]
    fn should_create_anonymous_auth_info() {
        let auth = AuthInfo::anonymous();
        assert_eq!(auth.principal, "*");
        assert!(!auth.is_authenticated);
    }

    #[test]
    fn should_create_authenticated_auth_info() {
        let auth = AuthInfo::authenticated("user123".to_string());
        assert_eq!(auth.principal, "user123");
        assert!(auth.is_authenticated);
    }

    #[test]
    fn should_disable_auth_when_env_vars_missing() {
        let config = test_config(None, None, false);
        assert!(!config.enforce_auth);
    }

    #[test]
    fn should_validate_correct_credentials() {
        let config = test_config(Some("test-key"), Some("test-secret"), true);
        assert!(config.validate_credentials("test-key", "test-secret"));
    }

    #[test]
    fn should_reject_wrong_access_key() {
        let config = test_config(Some("test-key"), Some("test-secret"), true);
        assert!(!config.validate_credentials("wrong-key", "test-secret"));
    }

    #[test]
    fn should_reject_wrong_secret_key() {
        let config = test_config(Some("test-key"), Some("test-secret"), true);
        assert!(!config.validate_credentials("test-key", "wrong-secret"));
    }

    #[test]
    fn should_allow_all_credentials_when_auth_disabled() {
        let config = test_config(None, None, false);
        assert!(config.validate_credentials("any-key", "any-secret"));
        assert!(config.validate_credentials("", ""));
    }

    #[test]
    fn should_extract_sigv4_principal_from_auth_header() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let auth_header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=xyz";
        let principal = AuthInfo::extract_sigv4_principal(auth_header, &config);

        assert!(principal.is_some());
        assert!(principal.unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn should_reject_sigv4_with_wrong_access_key() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let auth_header =
            "AWS4-HMAC-SHA256 Credential=WRONGKEY/20130524/us-east-1/s3/aws4_request";
        let principal = AuthInfo::extract_sigv4_principal(auth_header, &config);

        assert!(principal.is_none());
    }

    #[test]
    fn should_extract_v2_principal_from_auth_header() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let auth_header = "AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo5+fyQLFro=";
        let principal = AuthInfo::extract_v2_principal(auth_header, &config);

        assert!(principal.is_some());
        assert!(principal.unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn should_reject_v2_with_wrong_access_key() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let auth_header = "AWS WRONGKEY:signature";
        let principal = AuthInfo::extract_v2_principal(auth_header, &config);

        assert!(principal.is_none());
    }

    #[test]
    fn should_extract_presigned_principal_from_x_amz_credential() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request&X-Amz-Date=20130524T000000Z";
        let principal = AuthInfo::extract_presigned_principal(query, &config);

        assert!(principal.is_some());
        assert!(principal.unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn should_extract_presigned_principal_from_aws_access_key_id() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let query = "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=xyz&Expires=86400";
        let principal = AuthInfo::extract_presigned_principal(query, &config);

        assert!(principal.is_some());
        assert!(principal.unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn should_reject_presigned_with_wrong_access_key() {
        let config = test_config(
            Some("AKIAIOSFODNN7EXAMPLE"),
            Some("secret"),
            true,
        );

        let query = "X-Amz-Credential=WRONGKEY/20130524/us-east-1/s3/aws4_request";
        let principal = AuthInfo::extract_presigned_principal(query, &config);

        assert!(principal.is_none());
    }
}
