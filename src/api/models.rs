use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BucketInfo {
    pub name: String,
    pub created_at: String,
    pub versioning_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BucketDetails {
    pub name: String,
    pub created_at: String,
    pub versioning_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListBucketsResponse {
    pub items: Vec<BucketInfo>,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersioningStatus {
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub content_type: Option<String>,
    pub storage_class: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub content_type: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
    pub version_id: Option<String>,
    pub storage_class: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    pub items: Vec<ObjectInfo>,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectVersionInfo {
    pub key: String,
    pub version_id: String,
    pub size: u64,
    pub last_modified: String,
    pub etag: String,
    pub is_latest: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListVersionsResponse {
    pub items: Vec<ObjectVersionInfo>,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TagsResponse {
    pub tags: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TagsRequest {
    pub tags: std::collections::HashMap<String, String>,
}
