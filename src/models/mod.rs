use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub mod bucket;
pub mod object;
pub mod multipart;
pub mod policy;
pub mod lifecycle;

pub use bucket::Bucket;
pub use object::Object;
pub use multipart::{MultipartUpload, Part};
pub use policy::{BucketPolicy, Acl, CannedAcl, Owner};
pub use lifecycle::{LifecycleConfiguration, Rule, Status, Filter, Expiration, Transition, StorageClass};

/// S3 Object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: DateTime<Utc>,
    pub version_id: Option<String>,
    pub storage_class: String,
    pub metadata: HashMap<String, String>,
}

/// Versioning status for a bucket
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum VersioningStatus {
    Enabled,
    Suspended,
    NotSet,
}

impl std::fmt::Display for VersioningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersioningStatus::Enabled => write!(f, "Enabled"),
            VersioningStatus::Suspended => write!(f, "Suspended"),
            VersioningStatus::NotSet => write!(f, ""),
        }
    }
}
