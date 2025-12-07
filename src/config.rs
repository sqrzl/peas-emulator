//! Centralized configuration management for the Peas Emulator.
//!
//! This module is the single source of truth for all environment variables
//! and configuration options. All other modules should use the types and
//! functions exported from this module rather than accessing env vars directly.

use std::env;
use std::time::Duration;

// Environment variable names
const ENV_ACCESS_KEY_ID: &str = "ACCESS_KEY_ID";
const ENV_SECRET_ACCESS_KEY: &str = "SECRET_ACCESS_KEY";
const ENV_BLOBS_PATH: &str = "BLOBS_PATH";
const ENV_LIFECYCLE_HOURS: &str = "LIFECYCLE_HOURS";

// Default values
const DEFAULT_BLOBS_PATH: &str = "./blobs";
const DEFAULT_LIFECYCLE_HOURS: u64 = 1;

/// Global application configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// AWS access key ID for authentication
    pub access_key_id: Option<String>,
    /// AWS secret access key for authentication
    pub secret_access_key: Option<String>,
    /// Whether authentication is enforced
    pub enforce_auth: bool,
    /// Path to filesystem storage directory
    pub blobs_path: String,
    /// Interval for running lifecycle rules
    pub lifecycle_interval: Duration,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `ACCESS_KEY_ID`: AWS access key ID (optional)
    /// - `SECRET_ACCESS_KEY`: AWS secret access key (optional)
    /// - `BLOBS_PATH`: Path to storage directory (default: "./blobs")
    /// - `LIFECYCLE_HOURS`: Hours between lifecycle rule executions (default: 1)
    pub fn from_env() -> Self {
        let access_key_id = env::var(ENV_ACCESS_KEY_ID).ok();
        let secret_access_key = env::var(ENV_SECRET_ACCESS_KEY).ok();
        let blobs_path = env::var(ENV_BLOBS_PATH).unwrap_or_else(|_| DEFAULT_BLOBS_PATH.to_string());

        let lifecycle_interval_hours = env::var(ENV_LIFECYCLE_HOURS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_LIFECYCLE_HOURS);

        let enforce_auth = access_key_id.is_some() && secret_access_key.is_some();

        Self {
            access_key_id,
            secret_access_key,
            enforce_auth,
            blobs_path,
            lifecycle_interval: Duration::from_secs(lifecycle_interval_hours * 3600),
        }
    }

    /// Get the access key ID if authentication is enabled.
    pub fn access_key(&self) -> Option<&str> {
        self.access_key_id.as_deref()
    }

    /// Get the secret access key if authentication is enabled.
    pub fn secret_key(&self) -> Option<&str> {
        self.secret_access_key.as_deref()
    }

    /// Validate that provided credentials match configured credentials.
    ///
    /// If authentication is not enforced, this always returns `true`.
    pub fn validate_credentials(&self, provided_key: &str, provided_secret: &str) -> bool {
        if !self.enforce_auth {
            return true;
        }

        if let (Some(key), Some(secret)) = (self.access_key(), self.secret_key()) {
            provided_key == key && provided_secret == secret
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_use_default_blobs_path_when_not_set() {
        let config = Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert_eq!(config.blobs_path, "./blobs");
    }

    #[test]
    fn should_validate_correct_credentials() {
        let config = Config {
            access_key_id: Some("test-key".to_string()),
            secret_access_key: Some("test-secret".to_string()),
            enforce_auth: true,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert!(config.validate_credentials("test-key", "test-secret"));
    }

    #[test]
    fn should_reject_wrong_credentials() {
        let config = Config {
            access_key_id: Some("test-key".to_string()),
            secret_access_key: Some("test-secret".to_string()),
            enforce_auth: true,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert!(!config.validate_credentials("wrong-key", "test-secret"));
        assert!(!config.validate_credentials("test-key", "wrong-secret"));
    }

    #[test]
    fn should_allow_all_when_auth_disabled() {
        let config = Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert!(config.validate_credentials("any-key", "any-secret"));
    }

    #[test]
    fn should_access_key_returns_none_when_not_set() {
        let config = Config {
            access_key_id: None,
            secret_access_key: None,
            enforce_auth: false,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert!(config.access_key().is_none());
    }

    #[test]
    fn should_access_key_returns_some_when_set() {
        let config = Config {
            access_key_id: Some("test-key".to_string()),
            secret_access_key: Some("test-secret".to_string()),
            enforce_auth: true,
            blobs_path: "./blobs".to_string(),
            lifecycle_interval: Duration::from_secs(3600),
        };

        assert_eq!(config.access_key(), Some("test-key"));
        assert_eq!(config.secret_key(), Some("test-secret"));
    }
}
