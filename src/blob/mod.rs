use crate::error::Result;
use crate::models::{MultipartUpload, Object};
use crate::storage::Storage;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantContext {
    pub account_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Namespace {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobChecksums {
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobRecord {
    pub namespace: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: DateTime<Utc>,
    pub version_id: Option<String>,
    pub storage_class: String,
    pub metadata: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    pub provider_metadata: HashMap<String, String>,
}

impl BlobRecord {
    pub fn from_object(namespace: &str, object: &Object) -> Self {
        Self {
            namespace: namespace.to_string(),
            key: object.key.clone(),
            size: object.size,
            etag: object.etag.clone(),
            content_type: object.content_type.clone(),
            last_modified: object.last_modified,
            version_id: object.version_id.clone(),
            storage_class: object.storage_class.clone(),
            metadata: object.metadata.clone(),
            tags: object.tags.clone(),
            provider_metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutBlobRequest {
    pub namespace: String,
    pub key: String,
    pub data: Vec<u8>,
    pub content_type: String,
    pub metadata: HashMap<String, String>,
    pub tags: HashMap<String, String>,
}

pub trait BlobBackend: Send + Sync {
    fn create_namespace(&self, name: String) -> Result<Namespace>;
    fn get_namespace(&self, name: &str) -> Result<Namespace>;
    fn list_namespaces(&self) -> Result<Vec<Namespace>>;
    fn delete_namespace(&self, name: &str) -> Result<()>;

    fn put_blob(&self, request: PutBlobRequest) -> Result<BlobRecord>;
    fn get_blob(&self, namespace: &str, key: &str) -> Result<Object>;
    fn delete_blob(&self, namespace: &str, key: &str) -> Result<()>;
    fn list_blobs(
        &self,
        namespace: &str,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        marker: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<Vec<BlobRecord>>;

    fn create_upload_session(&self, namespace: &str, key: String) -> Result<MultipartUpload>;
    fn upload_session_part(
        &self,
        namespace: &str,
        upload_id: &str,
        part_number: u32,
        data: Vec<u8>,
    ) -> Result<String>;
    fn complete_upload_session(&self, namespace: &str, upload_id: &str) -> Result<String>;
}

impl<T: Storage + ?Sized> BlobBackend for T {
    fn create_namespace(&self, name: String) -> Result<Namespace> {
        self.create_bucket(name.clone())?;
        self.get_namespace(&name)
    }

    fn get_namespace(&self, name: &str) -> Result<Namespace> {
        let bucket = self.get_bucket(name)?;
        Ok(Namespace {
            name: bucket.name,
            created_at: bucket.created_at,
            metadata: bucket.metadata,
        })
    }

    fn list_namespaces(&self) -> Result<Vec<Namespace>> {
        Ok(self
            .list_buckets()?
            .into_iter()
            .map(|bucket| Namespace {
                name: bucket.name,
                created_at: bucket.created_at,
                metadata: bucket.metadata,
            })
            .collect())
    }

    fn delete_namespace(&self, name: &str) -> Result<()> {
        self.delete_bucket(name)
    }

    fn put_blob(&self, request: PutBlobRequest) -> Result<BlobRecord> {
        let mut object = Object::new_with_metadata(
            request.key.clone(),
            request.data,
            request.content_type,
            request.metadata,
        );
        object.tags = request.tags;
        self.put_object(&request.namespace, request.key.clone(), object)?;
        let stored = self.get_object(&request.namespace, &request.key)?;
        Ok(BlobRecord::from_object(&request.namespace, &stored))
    }

    fn get_blob(&self, namespace: &str, key: &str) -> Result<Object> {
        self.get_object(namespace, key)
    }

    fn delete_blob(&self, namespace: &str, key: &str) -> Result<()> {
        self.delete_object(namespace, key)
    }

    fn list_blobs(
        &self,
        namespace: &str,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        marker: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<Vec<BlobRecord>> {
        Ok(self
            .list_objects(namespace, prefix, delimiter, marker, max_keys)?
            .objects
            .iter()
            .map(|object| BlobRecord::from_object(namespace, object))
            .collect())
    }

    fn create_upload_session(&self, namespace: &str, key: String) -> Result<MultipartUpload> {
        self.create_multipart_upload(namespace, key)
    }

    fn upload_session_part(
        &self,
        namespace: &str,
        upload_id: &str,
        part_number: u32,
        data: Vec<u8>,
    ) -> Result<String> {
        self.upload_part(namespace, upload_id, part_number, data)
    }

    fn complete_upload_session(&self, namespace: &str, upload_id: &str) -> Result<String> {
        self.complete_multipart_upload(namespace, upload_id)
    }
}
