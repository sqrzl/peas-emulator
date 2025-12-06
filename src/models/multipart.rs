use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub key: String,
    pub initiated: DateTime<Utc>,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Part {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
}

impl MultipartUpload {
    pub fn new(key: String) -> Self {
        Self {
            upload_id: Uuid::new_v4().to_string(),
            key,
            initiated: Utc::now(),
            parts: Vec::new(),
        }
    }
}
