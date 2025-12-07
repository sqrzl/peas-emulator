use crate::error::Result;
use crate::models::{Acl, Bucket, MultipartUpload, Object};
use crate::storage::Storage;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory index for fast lookups
#[derive(Clone)]
struct ObjectIndex {
    /// bucket_name -> Set of object keys
    buckets: HashMap<String, Vec<String>>,
}

/// Wraps any Storage implementation with in-memory indices for O(1) list/exists operations
pub struct IndexedStorage {
    inner: Arc<dyn Storage>,
    index: Arc<RwLock<ObjectIndex>>,
}

impl IndexedStorage {
    pub fn new(inner: Arc<dyn Storage>) -> Self {
        Self {
            inner,
            index: Arc::new(RwLock::new(ObjectIndex {
                buckets: HashMap::new(),
            })),
        }
    }

    fn update_index_put(&self, bucket: &str, key: String) {
        if let Ok(mut index) = self.index.write() {
            index
                .buckets
                .entry(bucket.to_string())
                .or_default()
                .push(key);
        }
    }

    fn update_index_delete(&self, bucket: &str, key: &str) {
        if let Ok(mut index) = self.index.write() {
            if let Some(keys) = index.buckets.get_mut(bucket) {
                keys.retain(|k| k != key);
            }
        }
    }

    fn update_index_create_bucket(&self, bucket: String) {
        if let Ok(mut index) = self.index.write() {
            index.buckets.entry(bucket).or_default();
        }
    }

    fn update_index_delete_bucket(&self, bucket: &str) {
        if let Ok(mut index) = self.index.write() {
            index.buckets.remove(bucket);
        }
    }

    fn get_indexed_objects(&self, bucket: &str, prefix: Option<&str>) -> Vec<String> {
        let Ok(index) = self.index.read() else {
            return Vec::new();
        };
        if let Some(keys) = index.buckets.get(bucket) {
            keys.iter()
                .filter(|k| prefix.is_none_or(|p| k.starts_with(p)))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl Storage for IndexedStorage {
    fn create_bucket(&self, name: String) -> Result<()> {
        self.inner.create_bucket(name.clone())?;
        self.update_index_create_bucket(name);
        Ok(())
    }

    fn delete_bucket(&self, name: &str) -> Result<()> {
        self.inner.delete_bucket(name)?;
        self.update_index_delete_bucket(name);
        Ok(())
    }

    fn get_bucket(&self, name: &str) -> Result<Bucket> {
        self.inner.get_bucket(name)
    }

    fn list_buckets(&self) -> Result<Vec<Bucket>> {
        self.inner.list_buckets()
    }

    fn bucket_exists(&self, name: &str) -> Result<bool> {
        self.inner.bucket_exists(name)
    }

    fn put_object(&self, bucket: &str, key: String, object: Object) -> Result<()> {
        self.inner.put_object(bucket, key.clone(), object)?;
        self.update_index_put(bucket, key);
        Ok(())
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<Object> {
        self.inner.get_object(bucket, key)
    }

    fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(Object, Vec<u8>)> {
        self.inner.get_object_range(bucket, key, start, end)
    }

    fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.inner.delete_object(bucket, key)?;
        self.update_index_delete(bucket, key);
        Ok(())
    }

    fn object_exists(&self, bucket: &str, key: &str) -> Result<bool> {
        // Fast path: check index first
        if let Ok(index) = self.index.read() {
            if let Some(keys) = index.buckets.get(bucket) {
                if keys.contains(&key.to_string()) {
                    return Ok(true);
                }
            }
            drop(index);
        }
        // Fallback to storage
        self.inner.object_exists(bucket, key)
    }

    fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        _delimiter: Option<&str>,
        marker: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<crate::models::ListObjectsResult> {
        // Get keys from index without disk access
        let mut keys = self.get_indexed_objects(bucket, prefix);

        // Sort keys
        keys.sort();

        // Apply marker filter
        if let Some(m) = marker {
            keys.retain(|key| key.as_str() > m);
        }

        // Apply pagination
        let max_keys = max_keys.unwrap_or(1000);
        let is_truncated = keys.len() > max_keys;

        let next_marker = if is_truncated && keys.len() > max_keys {
            let next_key = keys[max_keys].clone();
            keys.truncate(max_keys);
            Some(next_key)
        } else {
            None
        };

        // Fetch full objects from storage
        let mut objects = Vec::new();
        for key in keys {
            if let Ok(obj) = self.inner.get_object(bucket, &key) {
                objects.push(obj);
            }
        }

        Ok(crate::models::ListObjectsResult {
            objects,
            is_truncated,
            next_marker,
        })
    }

    fn create_multipart_upload(&self, bucket: &str, key: String) -> Result<MultipartUpload> {
        self.inner.create_multipart_upload(bucket, key)
    }

    fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        data: Vec<u8>,
    ) -> Result<String> {
        self.inner.upload_part(bucket, upload_id, part_number, data)
    }

    fn list_parts(&self, bucket: &str, upload_id: &str) -> Result<Vec<crate::models::Part>> {
        self.inner.list_parts(bucket, upload_id)
    }

    fn get_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<MultipartUpload> {
        self.inner.get_multipart_upload(bucket, upload_id)
    }

    fn complete_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<String> {
        self.inner.complete_multipart_upload(bucket, upload_id)
    }

    fn abort_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<()> {
        self.inner.abort_multipart_upload(bucket, upload_id)
    }

    fn enable_versioning(&self, bucket: &str) -> Result<()> {
        self.inner.enable_versioning(bucket)
    }

    fn suspend_versioning(&self, bucket: &str) -> Result<()> {
        self.inner.suspend_versioning(bucket)
    }

    fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<crate::models::Object> {
        self.inner.get_object_version(bucket, key, version_id)
    }

    fn list_object_versions(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<crate::models::Object>> {
        self.inner.list_object_versions(bucket, prefix)
    }

    fn delete_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<()> {
        self.inner.delete_object_version(bucket, key, version_id)
    }

    fn get_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        self.inner.get_object_tags(bucket, key)
    }

    fn put_object_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        self.inner.put_object_tags(bucket, key, tags)
    }

    fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<()> {
        self.inner.delete_object_tags(bucket, key)
    }

    fn get_bucket_acl(&self, name: &str) -> Result<Acl> {
        self.inner.get_bucket_acl(name)
    }

    fn put_bucket_acl(&self, name: &str, acl: Acl) -> Result<()> {
        self.inner.put_bucket_acl(name, acl)
    }

    fn get_object_acl(&self, bucket: &str, key: &str) -> Result<Acl> {
        self.inner.get_object_acl(bucket, key)
    }

    fn put_object_acl(&self, bucket: &str, key: &str, acl: Acl) -> Result<()> {
        self.inner.put_object_acl(bucket, key, acl)
    }

    fn get_bucket_lifecycle(
        &self,
        bucket: &str,
    ) -> Result<crate::models::lifecycle::LifecycleConfiguration> {
        self.inner.get_bucket_lifecycle(bucket)
    }

    fn put_bucket_lifecycle(
        &self,
        bucket: &str,
        config: crate::models::lifecycle::LifecycleConfiguration,
    ) -> Result<()> {
        self.inner.put_bucket_lifecycle(bucket, config)
    }

    fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<()> {
        self.inner.delete_bucket_lifecycle(bucket)
    }

    fn get_bucket_policy(
        &self,
        bucket: &str,
    ) -> Result<crate::models::policy::BucketPolicyDocument> {
        self.inner.get_bucket_policy(bucket)
    }

    fn put_bucket_policy(
        &self,
        bucket: &str,
        policy: crate::models::policy::BucketPolicyDocument,
    ) -> Result<()> {
        self.inner.put_bucket_policy(bucket, policy)
    }

    fn delete_bucket_policy(&self, bucket: &str) -> Result<()> {
        self.inner.delete_bucket_policy(bucket)
    }
}
