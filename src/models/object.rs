use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub key: String,
    pub data: Vec<u8>,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: DateTime<Utc>,
    pub version_id: Option<String>,
    pub storage_class: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default)]
    pub acl: Option<crate::models::policy::Acl>,
}

impl Object {
    pub fn new(key: String, data: Vec<u8>, content_type: String) -> Self {
        Self::new_with_metadata(key, data, content_type, HashMap::new())
    }

    pub fn new_with_metadata(
        key: String,
        data: Vec<u8>,
        content_type: String,
        metadata: HashMap<String, String>,
    ) -> Self {
        let size = data.len() as u64;
        let etag = compute_etag(&data);
        
        Self {
            key,
            data,
            size,
            etag,
            content_type,
            last_modified: Utc::now(),
            version_id: None,
            storage_class: "STANDARD".to_string(),
            metadata,
            tags: HashMap::new(),
            acl: None,
        }
    }
}

/// Compute S3-compatible ETag (MD5 for single-part objects)
pub fn compute_etag(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Simple hash for now - in real implementation use MD5
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:x}", hash)
}
