use crate::models::{Acl, Bucket, Object, MultipartUpload};
use crate::error::{Error, Result};
use crate::storage::Storage;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct MemoryStorage {
    buckets: Arc<RwLock<HashMap<String, Bucket>>>,
    objects: Arc<RwLock<HashMap<String, HashMap<String, Object>>>>,
    uploads: Arc<RwLock<HashMap<String, MultipartUpload>>>,
    lifecycles: Arc<RwLock<HashMap<String, crate::models::lifecycle::LifecycleConfiguration>>>,
    policies: Arc<RwLock<HashMap<String, crate::models::policy::BucketPolicyDocument>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            objects: Arc::new(RwLock::new(HashMap::new())),
            uploads: Arc::new(RwLock::new(HashMap::new())),
            lifecycles: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn create_bucket(&self, name: String) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();
        if buckets.contains_key(&name) {
            return Err(Error::BucketAlreadyExists);
        }
        buckets.insert(name.clone(), Bucket::new(name.clone()));
        self.objects.write().unwrap().insert(name, HashMap::new());
        Ok(())
    }

    fn delete_bucket(&self, name: &str) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();
        let mut objects = self.objects.write().unwrap();
        
        if !buckets.contains_key(name) {
            return Err(Error::BucketNotFound);
        }

        if let Some(bucket_objects) = objects.get(name) {
            if !bucket_objects.is_empty() {
                return Err(Error::BucketNotEmpty);
            }
        }

        buckets.remove(name);
        objects.remove(name);
        Ok(())
    }

    fn get_bucket(&self, name: &str) -> Result<Bucket> {
        self.buckets.read().unwrap()
            .get(name).cloned().ok_or(Error::BucketNotFound)
    }

    fn list_buckets(&self) -> Result<Vec<Bucket>> {
        let buckets = self.buckets.read().unwrap();
        Ok(buckets.values().cloned().collect())
    }

    fn bucket_exists(&self, name: &str) -> Result<bool> {
        Ok(self.buckets.read().unwrap().contains_key(name))
    }

    fn put_object(&self, bucket: &str, key: String, object: Object) -> Result<()> {
        if !self.buckets.read().unwrap().contains_key(bucket) {
            return Err(Error::BucketNotFound);
        }

        let mut objects = self.objects.write().unwrap();
        objects.entry(bucket.to_string()).or_default().insert(key, object);
        Ok(())
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<Object> {
        self.objects.read().unwrap()
            .get(bucket)
            .and_then(|b| b.get(key))
            .cloned()
            .ok_or(Error::KeyNotFound)
    }

    fn get_object_range(&self, bucket: &str, key: &str, start: u64, end: Option<u64>) -> Result<(Object, Vec<u8>)> {
        let object = self.get_object(bucket, key)?;
        
        // Validate range
        if start >= object.size {
            return Err(Error::InternalError("Range start beyond file size".to_string()));
        }

        let actual_end = end.map(|e| e.min(object.size - 1)).unwrap_or(object.size - 1);
        if actual_end < start {
            return Err(Error::InternalError("Invalid range: end < start".to_string()));
        }

        let start_idx = start as usize;
        let end_idx = (actual_end + 1) as usize;
        let data_slice = object.data[start_idx..end_idx].to_vec();

        Ok((object, data_slice))
    }

    fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let mut objects = self.objects.write().unwrap();
        objects
            .get_mut(bucket)
            .and_then(|b| b.remove(key))
            .ok_or(Error::KeyNotFound)?;
        Ok(())
    }

    fn object_exists(&self, bucket: &str, key: &str) -> Result<bool> {
        Ok(self.objects.read().unwrap()
            .get(bucket).map(|b| b.contains_key(key)).unwrap_or(false))
    }

    fn get_object_tags(&self, bucket: &str, key: &str) -> Result<HashMap<String, String>> {
        let objects = self.objects.read().unwrap();
        let bucket_objects = objects.get(bucket).ok_or(Error::KeyNotFound)?;
        let obj = bucket_objects.get(key).ok_or(Error::KeyNotFound)?;
        Ok(obj.tags.clone())
    }

    fn put_object_tags(&self, bucket: &str, key: &str, tags: HashMap<String, String>) -> Result<()> {
        let mut objects = self.objects.write().unwrap();
        let bucket_objects = objects.get_mut(bucket).ok_or(Error::KeyNotFound)?;
        let obj = bucket_objects.get_mut(key).ok_or(Error::KeyNotFound)?;
        obj.tags = tags;
        Ok(())
    }

    fn get_bucket_acl(&self, name: &str) -> Result<Acl> {
        let buckets = self.buckets.read().unwrap();
        let bucket = buckets.get(name).ok_or(Error::BucketNotFound)?;
        Ok(bucket.acl.clone().unwrap_or_default())
    }

    fn put_bucket_acl(&self, name: &str, acl: Acl) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.get_mut(name).ok_or(Error::BucketNotFound)?;
        bucket.acl = Some(acl);
        Ok(())
    }

    fn get_object_acl(&self, bucket: &str, key: &str) -> Result<Acl> {
        let objects = self.objects.read().unwrap();
        let bucket_objects = objects.get(bucket).ok_or(Error::KeyNotFound)?;
        let obj = bucket_objects.get(key).ok_or(Error::KeyNotFound)?;
        Ok(obj.acl.clone().unwrap_or_default())
    }

    fn put_object_acl(&self, bucket: &str, key: &str, acl: Acl) -> Result<()> {
        let mut objects = self.objects.write().unwrap();
        let bucket_objects = objects.get_mut(bucket).ok_or(Error::KeyNotFound)?;
        let obj = bucket_objects.get_mut(key).ok_or(Error::KeyNotFound)?;
        obj.acl = Some(acl);
        Ok(())
    }

    fn list_objects(&self, bucket: &str, prefix: Option<&str>, _delimiter: Option<&str>, _marker: Option<&str>) -> Result<Vec<Object>> {
        let objects = self.objects.read().unwrap();
        let bucket_objects = objects.get(bucket).ok_or(Error::BucketNotFound)?;
        
        let mut result: Vec<_> = bucket_objects.values().cloned().collect();
        
        if let Some(p) = prefix {
            result.retain(|o| o.key.starts_with(p));
        }
        
        result.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(result)
    }

    fn create_multipart_upload(&self, bucket: &str, key: String) -> Result<MultipartUpload> {
        if !self.buckets.read().unwrap().contains_key(bucket) {
            return Err(Error::BucketNotFound);
        }

        let upload = MultipartUpload::new(key);
        let mut uploads = self.uploads.write().unwrap();
        uploads.insert(upload.upload_id.clone(), upload.clone());
        Ok(upload)
    }

    fn upload_part(&self, _bucket: &str, _upload_id: &str, _part_number: u32, data: Vec<u8>) -> Result<String> {
        let etag = md5_hash(&data);
        Ok(etag)
    }

    fn list_parts(&self, _bucket: &str, _upload_id: &str) -> Result<Vec<crate::models::Part>> {
        Err(Error::NoSuchUpload)
    }

    fn get_multipart_upload(&self, _bucket: &str, _upload_id: &str) -> Result<MultipartUpload> {
        Err(Error::NoSuchUpload)
    }

    fn complete_multipart_upload(&self, _bucket: &str, _upload_id: &str) -> Result<String> {
        let etag = format!("{}-0", md5_hash(b""));
        Ok(etag)
    }

    fn abort_multipart_upload(&self, _bucket: &str, _upload_id: &str) -> Result<()> {
        Ok(())
    }

    fn enable_versioning(&self, bucket: &str) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();
        if let Some(b) = buckets.get_mut(bucket) {
            b.versioning_enabled = true;
            Ok(())
        } else {
            Err(Error::BucketNotFound)
        }
    }

    fn suspend_versioning(&self, bucket: &str) -> Result<()> {
        let mut buckets = self.buckets.write().unwrap();
        if let Some(b) = buckets.get_mut(bucket) {
            b.versioning_enabled = false;
            Ok(())
        } else {
            Err(Error::BucketNotFound)
        }
    }

    fn get_object_version(&self, _bucket: &str, _key: &str, _version_id: &str) -> Result<Object> {
        Err(Error::NoSuchVersion)
    }

    fn list_object_versions(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<Object>> {
        self.list_objects(bucket, prefix, None, None)
    }

    fn delete_object_version(&self, bucket: &str, key: &str, _version_id: &str) -> Result<()> {
        self.delete_object(bucket, key)
    }

    fn get_bucket_lifecycle(&self, bucket: &str) -> Result<crate::models::lifecycle::LifecycleConfiguration> {
        let lifecycles = self.lifecycles.read().unwrap();
        lifecycles.get(bucket)
            .cloned()
            .ok_or(Error::KeyNotFound)
    }

    fn put_bucket_lifecycle(&self, bucket: &str, config: crate::models::lifecycle::LifecycleConfiguration) -> Result<()> {
        if !self.buckets.read().unwrap().contains_key(bucket) {
            return Err(Error::BucketNotFound);
        }
        
        let mut lifecycles = self.lifecycles.write().unwrap();
        lifecycles.insert(bucket.to_string(), config);
        Ok(())
    }

    fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<()> {
        let mut lifecycles = self.lifecycles.write().unwrap();
        lifecycles.remove(bucket);
        Ok(())
    }

    fn get_bucket_policy(&self, bucket: &str) -> Result<crate::models::policy::BucketPolicyDocument> {
        let policies = self.policies.read().unwrap();
        policies.get(bucket).cloned().ok_or(Error::KeyNotFound)
    }

    fn put_bucket_policy(&self, bucket: &str, policy: crate::models::policy::BucketPolicyDocument) -> Result<()> {
        let mut policies = self.policies.write().unwrap();
        policies.insert(bucket.to_string(), policy);
        Ok(())
    }

    fn delete_bucket_policy(&self, bucket: &str) -> Result<()> {
        let mut policies = self.policies.write().unwrap();
        policies.remove(bucket);
        Ok(())
    }
}

fn md5_hash(data: &[u8]) -> String {
    use md5;
    format!("{:x}", md5::compute(data))
}
