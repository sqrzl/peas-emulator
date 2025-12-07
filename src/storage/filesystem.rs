use crate::models::{Bucket, Object, MultipartUpload, policy::Acl};
use crate::error::{Error, Result};
use crate::storage::{Storage, LockFreeIndex};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Read, Write};
use std::sync::Arc;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

pub struct FilesystemStorage {
    base_path: PathBuf,
    index: Arc<LockFreeIndex>,
}

impl FilesystemStorage {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        let base_path = base_path.as_ref().to_path_buf();
        // Ensure base directory exists
        let _ = fs::create_dir_all(&base_path);
        
        let index = Arc::new(LockFreeIndex::new());
        
        // Rebuild index from filesystem
        if let Ok(entries) = fs::read_dir(&base_path) {
            for entry in entries.flatten() {
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                
                if metadata.is_dir() {
                    if let Some(bucket_name) = entry.file_name().to_str().map(|s| s.to_string()) {
                        index.get_or_create_bucket(bucket_name.clone());
                        
                        // Scan bucket for object_id directories
                        if let Ok(objects) = fs::read_dir(entry.path()) {
                            for obj_entry in objects.flatten() {
                                let path = obj_entry.path();
                                if path.is_dir() {
                                    // Each directory is an object_id, read metadata to get key
                                    let metadata_path = path.join("object.meta.json");
                                    if let Ok(metadata_json) = fs::read_to_string(&metadata_path) {
                                        if let Ok(obj) = serde_json::from_str::<Object>(&metadata_json) {
                                            index.insert(bucket_name.clone(), obj.key);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Self { base_path, index }
    }

    fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.base_path.join(bucket)
    }

    fn bucket_acl_path(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join("bucket.acl.json")
    }

    fn compute_object_id(bucket: &str, key: &str) -> String {
        let mut hasher = DefaultHasher::new();
        (bucket, key).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn object_id_dir(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.bucket_dir(bucket).join(object_id)
    }

    fn object_data_path(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id).join("object.blob")
    }

    fn object_metadata_path(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id).join("object.meta.json")
    }

    fn versions_dir(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id).join("versions")
    }

    fn version_dir(&self, bucket: &str, object_id: &str, version_id: &str) -> PathBuf {
        self.versions_dir(bucket, object_id).join(version_id)
    }

    fn version_data_path(&self, bucket: &str, object_id: &str, version_id: &str) -> PathBuf {
        self.version_dir(bucket, object_id, version_id).join("object.blob")
    }

    fn version_metadata_path(&self, bucket: &str, object_id: &str, version_id: &str) -> PathBuf {
        self.version_dir(bucket, object_id, version_id).join("object.meta.json")
    }

    fn multipart_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.bucket_dir(bucket).join(".multipart").join(upload_id)
    }

    fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.multipart_dir(bucket, upload_id).join(format!("part-{:05}", part_number))
    }

    fn uploads_index_path(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join(".multipart").join("uploads.json")
    }

    fn load_uploads(&self, bucket: &str) -> Result<std::collections::HashMap<String, MultipartUpload>> {
        let uploads_path = self.uploads_index_path(bucket);
        
        if !uploads_path.exists() {
            return Ok(std::collections::HashMap::new());
        }
        
        let json_str = std::fs::read_to_string(&uploads_path)
            .map_err(|e| Error::InternalError(format!("Failed to read uploads index: {}", e)))?;
        
        serde_json::from_str(&json_str)
            .map_err(|e| Error::InternalError(format!("Failed to parse uploads index: {}", e)))
    }

    fn save_uploads(&self, bucket: &str, uploads: &std::collections::HashMap<String, MultipartUpload>) -> Result<()> {
        let uploads_path = self.uploads_index_path(bucket);
        let uploads_dir = uploads_path.parent().unwrap();
        
        fs::create_dir_all(uploads_dir)
            .map_err(|e| Error::InternalError(format!("Failed to create multipart dir: {}", e)))?;
        
        let json_str = serde_json::to_string_pretty(uploads)
            .map_err(|e| Error::InternalError(format!("Failed to serialize uploads: {}", e)))?;
        
        fs::write(&uploads_path, json_str)
            .map_err(|e| Error::InternalError(format!("Failed to write uploads index: {}", e)))
    }
}

impl Storage for FilesystemStorage {
    fn create_bucket(&self, name: String) -> Result<()> {
        let bucket_dir = self.bucket_dir(&name);
        
        if bucket_dir.exists() {
            return Err(Error::BucketAlreadyExists);
        }
        
        fs::create_dir(&bucket_dir)
            .map_err(|e| Error::InternalError(format!("Failed to create bucket: {}", e)))?;
        
        // Update index
        self.index.get_or_create_bucket(name);
        
        Ok(())
    }

    fn delete_bucket(&self, name: &str) -> Result<()> {
        let bucket_dir = self.bucket_dir(name);
        
        if !bucket_dir.exists() {
            return Err(Error::BucketNotFound);
        }

        // Check if bucket is empty
        let entries = fs::read_dir(&bucket_dir)
            .map_err(|e| Error::InternalError(format!("Failed to read bucket: {}", e)))?;
        
        if entries.count() > 0 {
            return Err(Error::BucketNotEmpty);
        }

        fs::remove_dir(&bucket_dir)
            .map_err(|e| Error::InternalError(format!("Failed to delete bucket: {}", e)))?;
        
        // Update index
        self.index.clear_bucket(name);
        
        Ok(())
    }

    fn get_bucket(&self, name: &str) -> Result<Bucket> {
        let bucket_dir = self.bucket_dir(name);
        
        if !bucket_dir.exists() {
            return Err(Error::BucketNotFound);
        }

        Ok(Bucket::new(name.to_string()))
    }

    fn list_buckets(&self) -> Result<Vec<Bucket>> {
        let mut buckets = Vec::new();
        let entries = fs::read_dir(&self.base_path)
            .map_err(|e| Error::InternalError(format!("Failed to read base path: {}", e)))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| Error::InternalError(format!("Failed to read entry: {}", e)))?;
            
            let metadata = entry.metadata()
                .map_err(|e| Error::InternalError(format!("Failed to get metadata: {}", e)))?;
            
            if metadata.is_dir() {
                let name = entry.file_name();
                if let Some(bucket_name) = name.to_str() {
                    buckets.push(Bucket::new(bucket_name.to_string()));
                }
            }
        }

        Ok(buckets)
    }

    fn bucket_exists(&self, name: &str) -> Result<bool> {
        Ok(self.bucket_dir(name).exists())
    }

    fn put_object(&self, bucket: &str, key: String, object: Object) -> Result<()> {
        let bucket_dir = self.bucket_dir(bucket);
        
        if !bucket_dir.exists() {
            return Err(Error::BucketNotFound);
        }

        let object_id = Self::compute_object_id(bucket, &key);
        let object_id_dir = self.object_id_dir(bucket, &object_id);
        
        // Create object directory if needed
        fs::create_dir_all(&object_id_dir)
            .map_err(|e| Error::InternalError(format!("Failed to create object directory: {}", e)))?;

        // Write object data to object.blob
        let object_data_path = self.object_data_path(bucket, &object_id);
        let mut file = fs::File::create(&object_data_path)
            .map_err(|e| Error::InternalError(format!("Failed to create object file: {}", e)))?;
        
        file.write_all(&object.data)
            .map_err(|e| Error::InternalError(format!("Failed to write object data: {}", e)))?;

        // Write metadata to object.meta.json
        let metadata_path = self.object_metadata_path(bucket, &object_id);
        let metadata_json = serde_json::to_string(&object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;
        
        let mut meta_file = fs::File::create(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to create metadata file: {}", e)))?;
        
        meta_file.write_all(metadata_json.as_bytes())
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))?;

        // Update index
        self.index.insert(bucket.to_string(), key);

        Ok(())
    }

    fn get_object(&self, bucket: &str, key: &str) -> Result<Object> {
        let object_id = Self::compute_object_id(bucket, key);
        let object_data_path = self.object_data_path(bucket, &object_id);
        
        if !object_data_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_path = self.object_metadata_path(bucket, &object_id);
        
        // Read metadata
        let mut meta_file = fs::File::open(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to open metadata file: {}", e)))?;
        
        let mut metadata_json = String::new();
        meta_file.read_to_string(&mut metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;
        
        let object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        Ok(object)
    }

    fn get_object_range(&self, bucket: &str, key: &str, start: u64, end: Option<u64>) -> Result<(Object, Vec<u8>)> {
        let object_id = Self::compute_object_id(bucket, key);
        let object_data_path = self.object_data_path(bucket, &object_id);
        
        if !object_data_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_path = self.object_metadata_path(bucket, &object_id);
        
        // Read metadata
        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;
        
        let object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        // Validate range
        if start >= object.size {
            return Err(Error::InternalError("Range start beyond file size".to_string()));
        }

        let actual_end = end.map(|e| e.min(object.size - 1)).unwrap_or(object.size - 1);
        if actual_end < start {
            return Err(Error::InternalError("Invalid range: end < start".to_string()));
        }

        let length = (actual_end - start + 1) as usize;

        // Read range from file
        use std::io::{Seek, SeekFrom, Read};
        let mut file = fs::File::open(&object_data_path)
            .map_err(|e| Error::InternalError(format!("Failed to open object file: {}", e)))?;
        
        file.seek(SeekFrom::Start(start))
            .map_err(|e| Error::InternalError(format!("Failed to seek: {}", e)))?;
        
        let mut buffer = vec![0u8; length];
        file.read_exact(&mut buffer)
            .map_err(|e| Error::InternalError(format!("Failed to read range: {}", e)))?;

        Ok((object, buffer))
    }

    fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let object_id = Self::compute_object_id(bucket, key);
        let object_id_dir = self.object_id_dir(bucket, &object_id);
        
        if !object_id_dir.exists() {
            return Err(Error::KeyNotFound);
        }

        // Remove entire object_id directory
        fs::remove_dir_all(&object_id_dir)
            .map_err(|e| Error::InternalError(format!("Failed to delete object: {}", e)))?;

        // Update index
        self.index.remove(bucket, key);

        Ok(())
    }

    fn object_exists(&self, bucket: &str, key: &str) -> Result<bool> {
        // Fast path: check lock-free index first
        Ok(self.index.contains(bucket, key))
    }

    fn get_bucket_acl(&self, bucket: &str) -> Result<Acl> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let path = self.bucket_acl_path(bucket);
        if !path.exists() {
            return Ok(Acl::default());
        }

        let json = fs::read_to_string(&path)
            .map_err(|e| Error::InternalError(format!("Failed to read bucket ACL: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| Error::InternalError(format!("Failed to parse bucket ACL: {}", e)))
    }

    fn put_bucket_acl(&self, bucket: &str, acl: Acl) -> Result<()> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let path = self.bucket_acl_path(bucket);
        let json = serde_json::to_string(&acl)
            .map_err(|e| Error::InternalError(format!("Failed to serialize bucket ACL: {}", e)))?;
        fs::write(&path, json)
            .map_err(|e| Error::InternalError(format!("Failed to write bucket ACL: {}", e)))
    }

    fn get_object_acl(&self, bucket: &str, key: &str) -> Result<Acl> {
        let object_id = Self::compute_object_id(bucket, key);
        let metadata_path = self.object_metadata_path(bucket, &object_id);

        if !metadata_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;
        let object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        Ok(object.acl.unwrap_or_default())
    }

    fn put_object_acl(&self, bucket: &str, key: &str, acl: Acl) -> Result<()> {
        let object_id = Self::compute_object_id(bucket, key);
        let metadata_path = self.object_metadata_path(bucket, &object_id);

        if !metadata_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;
        let mut object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        object.acl = Some(acl);

        let updated = serde_json::to_string(&object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;
        fs::write(&metadata_path, updated)
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))
    }

    fn get_bucket_lifecycle(&self, bucket: &str) -> Result<crate::models::lifecycle::LifecycleConfiguration> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let lifecycle_path = bucket_path.join(".lifecycle.json");
        if !lifecycle_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let json = fs::read_to_string(&lifecycle_path)
            .map_err(|e| Error::InternalError(format!("Failed to read lifecycle config: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| Error::InternalError(format!("Failed to parse lifecycle config: {}", e)))
    }

    fn put_bucket_lifecycle(&self, bucket: &str, config: crate::models::lifecycle::LifecycleConfiguration) -> Result<()> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let lifecycle_path = bucket_path.join(".lifecycle.json");
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| Error::InternalError(format!("Failed to serialize lifecycle config: {}", e)))?;
        fs::write(&lifecycle_path, json)
            .map_err(|e| Error::InternalError(format!("Failed to write lifecycle config: {}", e)))
    }

    fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<()> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let lifecycle_path = bucket_path.join(".lifecycle.json");
        if lifecycle_path.exists() {
            fs::remove_file(&lifecycle_path)
                .map_err(|e| Error::InternalError(format!("Failed to delete lifecycle config: {}", e)))?;
        }
        Ok(())
    }

    fn get_bucket_policy(&self, bucket: &str) -> Result<crate::models::policy::BucketPolicyDocument> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let policy_path = bucket_path.join(".policy.json");
        if !policy_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let policy_json = fs::read_to_string(&policy_path)
            .map_err(|e| Error::InternalError(format!("Failed to read policy: {}", e)))?;

        serde_json::from_str(&policy_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse policy: {}", e)))
    }

    fn put_bucket_policy(&self, bucket: &str, policy: crate::models::policy::BucketPolicyDocument) -> Result<()> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let policy_path = bucket_path.join(".policy.json");
        let policy_json = serde_json::to_string_pretty(&policy)
            .map_err(|e| Error::InternalError(format!("Failed to serialize policy: {}", e)))?;

        fs::write(&policy_path, policy_json)
            .map_err(|e| Error::InternalError(format!("Failed to write policy: {}", e)))
    }

    fn delete_bucket_policy(&self, bucket: &str) -> Result<()> {
        let bucket_path = self.base_path.join(bucket);
        if !bucket_path.exists() {
            return Err(Error::BucketNotFound);
        }

        let policy_path = bucket_path.join(".policy.json");
        if policy_path.exists() {
            fs::remove_file(&policy_path)
                .map_err(|e| Error::InternalError(format!("Failed to delete policy: {}", e)))?;
        }
        Ok(())
    }

    fn get_object_tags(&self, bucket: &str, key: &str) -> Result<HashMap<String, String>> {
        let object_id = Self::compute_object_id(bucket, key);
        let metadata_path = self.object_metadata_path(bucket, &object_id);

        if !metadata_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;

        let object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        Ok(object.tags)
    }

    fn put_object_tags(&self, bucket: &str, key: &str, tags: HashMap<String, String>) -> Result<()> {
        let object_id = Self::compute_object_id(bucket, key);
        let metadata_path = self.object_metadata_path(bucket, &object_id);

        if !metadata_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;

        let mut object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        object.tags = tags;

        let updated_json = serde_json::to_string(&object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;

        fs::write(&metadata_path, updated_json)
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))?
            ;

        Ok(())
    }

    fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<()> {
        let object_id = Self::compute_object_id(bucket, key);
        let metadata_path = self.object_metadata_path(bucket, &object_id);

        if !metadata_path.exists() {
            return Err(Error::KeyNotFound);
        }

        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;

        let mut object: Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))?;

        // Clear all tags
        object.tags.clear();

        let updated_json = serde_json::to_string(&object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;

        fs::write(&metadata_path, updated_json)
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))?;

        Ok(())
    }

    fn list_objects(&self, bucket: &str, prefix: Option<&str>, _delimiter: Option<&str>, marker: Option<&str>, max_keys: Option<usize>) -> Result<crate::models::ListObjectsResult> {
        let bucket_dir = self.bucket_dir(bucket);
        if !bucket_dir.exists() {
            return Err(Error::BucketNotFound);
        }

        let mut all_objects = Vec::new();
        
        // Use index to get all keys in bucket
        let keys = self.index.list(bucket, prefix);
        
        // Load objects for each key
        for obj_key in keys {
            if let Ok(obj) = self.get_object(bucket, &obj_key) {
                all_objects.push(obj);
            }
        }

        // Sort by key (S3 lexicographic order)
        all_objects.sort_by(|a, b| a.key.cmp(&b.key));
        
        // Apply marker filter - skip objects until we find the marker
        if let Some(m) = marker {
            all_objects.retain(|obj| obj.key.as_str() > m);
        }
        
        // Apply pagination
        let max_keys = max_keys.unwrap_or(1000); // S3 default is 1000
        let is_truncated = all_objects.len() > max_keys;
        
        let mut objects = all_objects;
        let next_marker = if is_truncated {
            // Take max_keys + 1 to get the next marker
            if objects.len() > max_keys {
                let next_key = objects[max_keys].key.clone();
                objects.truncate(max_keys);
                Some(next_key)
            } else {
                None
            }
        } else {
            None
        };

        Ok(crate::models::ListObjectsResult {
            objects,
            is_truncated,
            next_marker,
        })
    }

    fn create_multipart_upload(&self, bucket: &str, key: String) -> Result<MultipartUpload> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let upload = MultipartUpload::new(key);
        let mut uploads = self.load_uploads(bucket)?;
        uploads.insert(upload.upload_id.clone(), upload.clone());
        self.save_uploads(bucket, &uploads)?;
        
        Ok(upload)
    }

    fn upload_part(&self, bucket: &str, upload_id: &str, part_number: u32, data: Vec<u8>) -> Result<String> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }
        
        // Validate part number
        if !(1..=10000).contains(&part_number) {
            return Err(Error::InvalidPartNumber);
        }
        
        // Check upload exists
        let mut uploads = self.load_uploads(bucket)?;
        let upload = uploads.get_mut(upload_id)
            .ok_or(Error::NoSuchUpload)?;
        
        // Compute ETag
        let etag = md5_hash(&data);
        let size = data.len() as u64;
        
        // Create multipart directory
        let multipart_dir = self.multipart_dir(bucket, upload_id);
        fs::create_dir_all(&multipart_dir)
            .map_err(|e| Error::InternalError(format!("Failed to create multipart dir: {}", e)))?;
        
        // Write part data
        let part_path = self.part_path(bucket, upload_id, part_number);
        fs::write(&part_path, &data)
            .map_err(|e| Error::InternalError(format!("Failed to write part: {}", e)))?;
        
        // Remove existing part with same number and add new one
        upload.parts.retain(|p| p.part_number != part_number);
        upload.parts.push(crate::models::Part {
            part_number,
            etag: etag.clone(),
            size,
            last_modified: chrono::Utc::now(),
        });
        
        // Save uploads index
        self.save_uploads(bucket, &uploads)?;
        
        Ok(etag)
    }

    fn list_parts(&self, bucket: &str, upload_id: &str) -> Result<Vec<crate::models::Part>> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }
        
        let uploads = self.load_uploads(bucket)?;
        let upload = uploads.get(upload_id)
            .ok_or(Error::NoSuchUpload)?;
        
        let mut parts = upload.parts.clone();
        parts.sort_by_key(|p| p.part_number);
        Ok(parts)
    }

    fn get_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<MultipartUpload> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }
        
        let uploads = self.load_uploads(bucket)?;
        uploads.get(upload_id)
            .cloned()
            .ok_or(Error::NoSuchUpload)
    }

    fn complete_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<String> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }
        
        let mut uploads = self.load_uploads(bucket)?;
        let upload = uploads.remove(upload_id)
            .ok_or(Error::NoSuchUpload)?;
        
        if upload.parts.is_empty() {
            return Err(Error::InvalidPartOrder);
        }
        
        // Validate parts are sequential starting from 1
        let mut part_numbers: Vec<_> = upload.parts.iter().map(|p| p.part_number).collect();
        part_numbers.sort();
        for (i, &num) in part_numbers.iter().enumerate() {
            if num != (i as u32 + 1) {
                return Err(Error::InvalidPartOrder);
            }
        }
        
        // Read all parts and concatenate
        let mut object_data = Vec::new();
        for part in &upload.parts {
            let part_path = self.part_path(bucket, upload_id, part.part_number);
            let part_data = fs::read(&part_path)
                .map_err(|e| Error::InternalError(format!("Failed to read part: {}", e)))?;
            object_data.extend_from_slice(&part_data);
        }
        
        // Compute final ETag: MD5(concat(part_etags)) + "-" + part_count
        let part_etags = upload.parts.iter().map(|p| p.etag.clone()).collect::<Vec<_>>();
        let concatenated = part_etags.join("");
        let final_etag = format!("{}-{}", md5_hash(concatenated.as_bytes()), upload.parts.len());
        
        // Save completed object
        let mut obj = Object::new(upload.key.clone(), object_data, "application/octet-stream".to_string());
        obj.etag = final_etag.clone();
        self.put_object(bucket, upload.key, obj)?;
        
        // Clean up multipart directory
        let multipart_dir = self.multipart_dir(bucket, upload_id);
        let _ = fs::remove_dir_all(multipart_dir);
        
        // Save updated uploads index
        self.save_uploads(bucket, &uploads)?;
        
        Ok(final_etag)
    }

    fn abort_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<()> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }
        
        let mut uploads = self.load_uploads(bucket)?;
        uploads.remove(upload_id)
            .ok_or(Error::NoSuchUpload)?;
        
        // Clean up multipart directory
        let multipart_dir = self.multipart_dir(bucket, upload_id);
        if multipart_dir.exists() {
            let _ = fs::remove_dir_all(multipart_dir);
        }
        
        // Save updated uploads index
        self.save_uploads(bucket, &uploads)?;
        
        Ok(())
    }

    fn enable_versioning(&self, bucket: &str) -> Result<()> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        // Mark bucket as versioning-enabled by creating a marker file
        let versioning_marker = self.bucket_dir(bucket).join(".versioning-enabled");
        fs::write(&versioning_marker, "")
            .map_err(|e| Error::InternalError(format!("Failed to enable versioning: {}", e)))?;
        Ok(())
    }

    fn suspend_versioning(&self, bucket: &str) -> Result<()> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        // Remove the versioning marker
        let versioning_marker = self.bucket_dir(bucket).join(".versioning-enabled");
        let _ = fs::remove_file(versioning_marker);
        Ok(())
    }

    fn get_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<crate::models::Object> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let object_id = Self::compute_object_id(bucket, key);
        let version_data_path = self.version_data_path(bucket, &object_id, version_id);
        if !version_data_path.exists() {
            return Err(Error::NoSuchVersion);
        }

        let data = fs::read(&version_data_path)
            .map_err(|e| Error::InternalError(format!("Failed to read version: {}", e)))?;
        
        let metadata_path = self.version_metadata_path(bucket, &object_id, version_id);
        let metadata_json = fs::read_to_string(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read version metadata: {}", e)))?;
        
        let mut object: crate::models::Object = serde_json::from_str(&metadata_json)
            .map_err(|e| Error::InternalError(format!("Failed to parse version metadata: {}", e)))?;
        
        object.data = data;
        object.version_id = Some(version_id.to_string());

        Ok(object)
    }

    fn list_object_versions(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<crate::models::Object>> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let mut versions = Vec::new();
        let prefix = prefix.unwrap_or("");
        let bucket_dir = self.bucket_dir(bucket);

        // Scan all object directories in bucket
        if let Ok(entries) = fs::read_dir(&bucket_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Skip special directories
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with(".") {
                            continue;
                        }
                    }
                    
                    // Check for versions subdirectory
                    let versions_dir = path.join("versions");
                    if versions_dir.exists() {
                        // Scan version directories
                        if let Ok(version_entries) = fs::read_dir(&versions_dir) {
                            for version_entry in version_entries.flatten() {
                                let version_path = version_entry.path();
                                if version_path.is_dir() {
                                    if let Some(version_id) = version_path.file_name().and_then(|n| n.to_str()) {
                                        // Read version metadata to get the key and check prefix
                                        let metadata_path = version_path.join("object.meta.json");
                                        if let Ok(metadata_json) = fs::read_to_string(&metadata_path) {
                                            if let Ok(mut obj) = serde_json::from_str::<crate::models::Object>(&metadata_json) {
                                                if obj.key.starts_with(prefix) {
                                                    // Read version data
                                                    let data_path = version_path.join("object.blob");
                                                    if let Ok(data) = fs::read(&data_path) {
                                                        obj.data = data;
                                                        obj.version_id = Some(version_id.to_string());
                                                        versions.push(obj);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        versions.sort_by(|a, b| {
            if a.key == b.key {
                a.version_id.cmp(&b.version_id)
            } else {
                a.key.cmp(&b.key)
            }
        });

        Ok(versions)
    }

    fn delete_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<()> {
        if !self.bucket_exists(bucket)? {
            return Err(Error::BucketNotFound);
        }

        let object_id = Self::compute_object_id(bucket, key);
        let version_data_path = self.version_data_path(bucket, &object_id, version_id);
        if !version_data_path.exists() {
            return Err(Error::NoSuchVersion);
        }

        let version_dir = self.version_dir(bucket, &object_id, version_id);
        fs::remove_dir_all(&version_dir)
            .map_err(|e| Error::InternalError(format!("Failed to delete version: {}", e)))?;

        Ok(())
    }
}

fn md5_hash(data: &[u8]) -> String {
    use md5;
    format!("{:x}", md5::compute(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("peas_fs_test_{}", Uuid::new_v4()))
    }

    #[test]
    fn should_roundtrip_metadata_on_put_and_get() {
        let base = temp_path();
        let storage = FilesystemStorage::new(&base);

        let bucket = "meta-bucket";
        storage.create_bucket(bucket.to_string()).unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("owner".to_string(), "alice".to_string());
        metadata.insert("purpose".to_string(), "test".to_string());

        let data = b"hello metadata".to_vec();
        let key = "note.txt".to_string();
        let obj = Object::new_with_metadata(key.clone(), data.clone(), "text/plain".to_string(), metadata.clone());

        storage.put_object(bucket, key.clone(), obj).unwrap();

        let fetched = storage.get_object(bucket, &key).unwrap();
        assert_eq!(fetched.data, data, "Object data should round-trip");
        assert_eq!(fetched.metadata.len(), metadata.len(), "Metadata count should match");
        assert_eq!(fetched.metadata.get("owner"), Some(&"alice".to_string()));
        assert_eq!(fetched.metadata.get("purpose"), Some(&"test".to_string()));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn should_rebuild_index_with_metadata_present() {
        let base = temp_path();
        let bucket = "meta-rebuild";
        let key = "file.bin";

        {
            let storage = FilesystemStorage::new(&base);
            storage.create_bucket(bucket.to_string()).unwrap();

            let mut metadata = HashMap::new();
            metadata.insert("role".to_string(), "cache".to_string());

            let data = b"persisted".to_vec();
            let obj = Object::new_with_metadata(key.to_string(), data, "application/octet-stream".to_string(), metadata);

            storage.put_object(bucket, key.to_string(), obj).unwrap();
        }

        // Recreate storage to force index rebuild from disk
        let storage = FilesystemStorage::new(&base);
        assert!(storage.object_exists(bucket, key).unwrap(), "Index should include existing object");

        let fetched = storage.get_object(bucket, key).unwrap();
        assert_eq!(fetched.metadata.get("role"), Some(&"cache".to_string()));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn should_store_and_return_tags() {
        let base = temp_path();
        let storage = FilesystemStorage::new(&base);

        let bucket = "tag-bucket";
        let key = "tag.txt";
        storage.create_bucket(bucket.to_string()).unwrap();

        let data = b"tag-data".to_vec();
        let mut obj = Object::new_with_metadata(key.to_string(), data.clone(), "text/plain".to_string(), HashMap::new());
        obj.tags.insert("env".to_string(), "test".to_string());
        storage.put_object(bucket, key.to_string(), obj).unwrap();

        let tags = storage.get_object_tags(bucket, key).unwrap();
        assert_eq!(tags.get("env"), Some(&"test".to_string()));

        let mut new_tags = HashMap::new();
        new_tags.insert("owner".to_string(), "alice".to_string());
        storage.put_object_tags(bucket, key, new_tags.clone()).unwrap();

        let updated = storage.get_object_tags(bucket, key).unwrap();
        assert_eq!(updated, new_tags);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn should_store_and_retrieve_lifecycle_configuration() {
        use crate::models::lifecycle::*;

        let base = temp_path();
        let storage = FilesystemStorage::new(&base);
        let bucket = "lifecycle-bucket";
        storage.create_bucket(bucket.to_string()).unwrap();

        let mut config = LifecycleConfiguration::default();
        config.rules.push(Rule {
            id: Some("delete-old-logs".to_string()),
            status: Status::Enabled,
            filter: Some(Filter {
                prefix: Some("logs/".to_string()),
                tags: vec![],
            }),
            expiration: Some(Expiration {
                days: Some(30),
                date: None,
                expired_object_delete_marker: None,
            }),
            transitions: vec![],
        });

        storage.put_bucket_lifecycle(bucket, config.clone()).unwrap();
        let retrieved = storage.get_bucket_lifecycle(bucket).unwrap();
        assert_eq!(retrieved.rules.len(), 1);
        assert_eq!(retrieved.rules[0].id, Some("delete-old-logs".to_string()));

        storage.delete_bucket_lifecycle(bucket).unwrap();
        assert!(storage.get_bucket_lifecycle(bucket).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }
}
