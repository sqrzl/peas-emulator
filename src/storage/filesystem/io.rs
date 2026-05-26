use super::FilesystemStorage;
use crate::error::{Error, Result};
use crate::models::{MultipartUpload, Object};
use crate::storage::LockFreeIndex;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
                                        if let Ok(obj) =
                                            serde_json::from_str::<Object>(&metadata_json)
                                        {
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

    pub(super) fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.base_path.join(bucket)
    }

    pub(super) fn bucket_acl_path(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join("bucket.acl.json")
    }

    pub(super) fn is_bucket_control_entry(&self, _bucket: &str, entry: &fs::DirEntry) -> bool {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        match name.as_ref() {
            ".bucket.meta.json"
            | ".versioning-enabled"
            | ".lifecycle.json"
            | ".policy.json"
            | "bucket.acl.json" => true,
            ".multipart" => entry
                .path()
                .read_dir()
                .map(|entries| entries.flatten().next().is_none())
                .unwrap_or(false),
            _ => false,
        }
    }

    pub(super) fn bucket_metadata_path(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join(".bucket.meta.json")
    }

    pub(super) fn versioning_marker(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join(".versioning-enabled")
    }

    pub(super) fn versioning_enabled(&self, bucket: &str) -> bool {
        self.versioning_marker(bucket).exists()
    }

    pub(super) fn compute_object_id(bucket: &str, key: &str) -> String {
        let mut hasher = DefaultHasher::new();
        (bucket, key).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub(super) fn object_id_dir(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.bucket_dir(bucket).join(object_id)
    }

    pub(super) fn object_data_path(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id).join("object.blob")
    }

    pub(super) fn object_metadata_path(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id)
            .join("object.meta.json")
    }

    pub(super) fn versions_dir(&self, bucket: &str, object_id: &str) -> PathBuf {
        self.object_id_dir(bucket, object_id).join("versions")
    }

    pub(super) fn version_dir(&self, bucket: &str, object_id: &str, version_id: &str) -> PathBuf {
        self.versions_dir(bucket, object_id).join(version_id)
    }

    pub(super) fn version_data_path(
        &self,
        bucket: &str,
        object_id: &str,
        version_id: &str,
    ) -> PathBuf {
        self.version_dir(bucket, object_id, version_id)
            .join("object.blob")
    }

    pub(super) fn version_metadata_path(
        &self,
        bucket: &str,
        object_id: &str,
        version_id: &str,
    ) -> PathBuf {
        self.version_dir(bucket, object_id, version_id)
            .join("object.meta.json")
    }

    pub(super) fn multipart_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.bucket_dir(bucket).join(".multipart").join(upload_id)
    }

    pub(super) fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.multipart_dir(bucket, upload_id)
            .join(format!("part-{:05}", part_number))
    }

    pub(super) fn uploads_index_path(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket)
            .join(".multipart")
            .join("uploads.json")
    }

    pub(super) fn load_uploads(
        &self,
        bucket: &str,
    ) -> Result<std::collections::HashMap<String, MultipartUpload>> {
        let uploads_path = self.uploads_index_path(bucket);

        if !uploads_path.exists() {
            return Ok(std::collections::HashMap::new());
        }

        let json_str = std::fs::read_to_string(&uploads_path)
            .map_err(|e| Error::InternalError(format!("Failed to read uploads index: {}", e)))?;

        serde_json::from_str(&json_str)
            .map_err(|e| Error::InternalError(format!("Failed to parse uploads index: {}", e)))
    }

    pub(super) fn save_uploads(
        &self,
        bucket: &str,
        uploads: &std::collections::HashMap<String, MultipartUpload>,
    ) -> Result<()> {
        let uploads_path = self.uploads_index_path(bucket);
        let uploads_dir = uploads_path
            .parent()
            .ok_or_else(|| Error::InternalError("Invalid uploads path".to_string()))?;

        fs::create_dir_all(uploads_dir)
            .map_err(|e| Error::InternalError(format!("Failed to create multipart dir: {}", e)))?;

        let json_str = serde_json::to_string_pretty(uploads)
            .map_err(|e| Error::InternalError(format!("Failed to serialize uploads: {}", e)))?;

        fs::write(&uploads_path, json_str)
            .map_err(|e| Error::InternalError(format!("Failed to write uploads index: {}", e)))
    }

    pub(super) fn write_object_files(
        &self,
        bucket: &str,
        object_id: &str,
        object: &Object,
    ) -> Result<()> {
        let object_id_dir = self.object_id_dir(bucket, object_id);
        fs::create_dir_all(&object_id_dir).map_err(|e| {
            Error::InternalError(format!("Failed to create object directory: {}", e))
        })?;

        let object_data_path = self.object_data_path(bucket, object_id);
        let mut file = fs::File::create(&object_data_path)
            .map_err(|e| Error::InternalError(format!("Failed to create object file: {}", e)))?;

        file.write_all(&object.data)
            .map_err(|e| Error::InternalError(format!("Failed to write object data: {}", e)))?;

        let metadata_path = self.object_metadata_path(bucket, object_id);
        let metadata_json = serde_json::to_string(object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;

        let mut meta_file = fs::File::create(&metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to create metadata file: {}", e)))?;

        meta_file
            .write_all(metadata_json.as_bytes())
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))?;

        Ok(())
    }

    pub(super) fn write_version_snapshot(
        &self,
        bucket: &str,
        object_id: &str,
        version_id: &str,
        object: &Object,
    ) -> Result<()> {
        let version_dir = self.version_dir(bucket, object_id, version_id);
        fs::create_dir_all(&version_dir).map_err(|e| {
            Error::InternalError(format!("Failed to create version directory: {}", e))
        })?;

        let mut version_object = object.clone();
        version_object.version_id = Some(version_id.to_string());

        let version_data_path = self.version_data_path(bucket, object_id, version_id);
        fs::write(&version_data_path, &version_object.data)
            .map_err(|e| Error::InternalError(format!("Failed to write version data: {}", e)))?;

        let version_metadata_path = self.version_metadata_path(bucket, object_id, version_id);
        let metadata_json = serde_json::to_string(&version_object).map_err(|e| {
            Error::InternalError(format!("Failed to serialize version metadata: {}", e))
        })?;

        fs::write(&version_metadata_path, metadata_json).map_err(|e| {
            Error::InternalError(format!("Failed to write version metadata: {}", e))
        })?;

        Ok(())
    }

    pub(super) fn read_bucket_metadata(&self, bucket: &str) -> Result<HashMap<String, String>> {
        let path = self.bucket_metadata_path(bucket);
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let json = fs::read_to_string(&path)
            .map_err(|e| Error::InternalError(format!("Failed to read bucket metadata: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| Error::InternalError(format!("Failed to parse bucket metadata: {}", e)))
    }

    pub(super) fn write_bucket_metadata(
        &self,
        bucket: &str,
        metadata: &HashMap<String, String>,
    ) -> Result<()> {
        let path = self.bucket_metadata_path(bucket);
        let json = serde_json::to_string_pretty(metadata).map_err(|e| {
            Error::InternalError(format!("Failed to serialize bucket metadata: {}", e))
        })?;
        fs::write(&path, json)
            .map_err(|e| Error::InternalError(format!("Failed to write bucket metadata: {}", e)))
    }

    pub(super) fn read_object_metadata(&self, metadata_path: &Path) -> Result<Object> {
        let json = fs::read_to_string(metadata_path)
            .map_err(|e| Error::InternalError(format!("Failed to read metadata: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| Error::InternalError(format!("Failed to parse metadata: {}", e)))
    }

    pub(super) fn write_object_metadata(
        &self,
        metadata_path: &Path,
        object: &Object,
    ) -> Result<()> {
        let json = serde_json::to_string(object)
            .map_err(|e| Error::InternalError(format!("Failed to serialize metadata: {}", e)))?;
        fs::write(metadata_path, json)
            .map_err(|e| Error::InternalError(format!("Failed to write metadata: {}", e)))
    }

    pub(super) fn version_entries_exist(&self, bucket: &str, object_id: &str) -> Result<bool> {
        let versions_dir = self.versions_dir(bucket, object_id);
        if !versions_dir.exists() {
            return Ok(false);
        }

        let entries = fs::read_dir(&versions_dir)
            .map_err(|e| Error::InternalError(format!("Failed to read versions dir: {}", e)))?;

        Ok(entries.flatten().next().is_some())
    }
}
