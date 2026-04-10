use crate::error::Result;
use crate::models::{ListObjectsResult, Object};
use crate::storage::Storage;
use std::collections::HashMap;

pub fn list_objects(
    storage: &dyn Storage,
    bucket: &str,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    marker: Option<&str>,
    max_keys: Option<usize>,
) -> Result<ListObjectsResult> {
    storage.list_objects(bucket, prefix, delimiter, marker, max_keys)
}

pub fn get_object(storage: &dyn Storage, bucket: &str, key: &str) -> Result<Object> {
    storage.get_object(bucket, key)
}

pub fn put_object(storage: &dyn Storage, bucket: &str, key: String, object: Object) -> Result<()> {
    storage.put_object(bucket, key, object)
}

pub fn delete_object(storage: &dyn Storage, bucket: &str, key: &str) -> Result<()> {
    storage.delete_object(bucket, key)
}

pub fn list_object_versions(
    storage: &dyn Storage,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<Vec<Object>> {
    storage.list_object_versions(bucket, prefix)
}

pub fn get_object_tags(
    storage: &dyn Storage,
    bucket: &str,
    key: &str,
) -> Result<HashMap<String, String>> {
    storage.get_object_tags(bucket, key)
}

pub fn put_object_tags(
    storage: &dyn Storage,
    bucket: &str,
    key: &str,
    tags: HashMap<String, String>,
) -> Result<()> {
    storage.put_object_tags(bucket, key, tags)
}

pub fn delete_object_tags(storage: &dyn Storage, bucket: &str, key: &str) -> Result<()> {
    storage.delete_object_tags(bucket, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FilesystemStorage;
    use std::fs;
    use std::sync::Arc;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir =
            std::env::temp_dir().join(format!("peas-service-object-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    #[test]
    fn should_roundtrip_object_through_service() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();

        let mut object = Object::new(
            "key.txt".to_string(),
            b"hello".to_vec(),
            "text/plain".to_string(),
        );
        object.tags.insert("env".to_string(), "dev".to_string());
        put_object(storage.as_ref(), "bucket", "key.txt".to_string(), object).unwrap();

        let stored = get_object(storage.as_ref(), "bucket", "key.txt").unwrap();
        assert_eq!(stored.data, b"hello".to_vec());
        assert_eq!(stored.tags.get("env"), Some(&"dev".to_string()));

        let tags = get_object_tags(storage.as_ref(), "bucket", "key.txt").unwrap();
        assert_eq!(tags.get("env"), Some(&"dev".to_string()));

        delete_object_tags(storage.as_ref(), "bucket", "key.txt").unwrap();
        assert!(get_object_tags(storage.as_ref(), "bucket", "key.txt")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn should_list_object_versions_through_service() {
        let storage = temp_storage();
        storage.create_bucket("bucket".to_string()).unwrap();
        storage.enable_versioning("bucket").unwrap();

        put_object(
            storage.as_ref(),
            "bucket",
            "key.txt".to_string(),
            Object::new(
                "key.txt".to_string(),
                b"v1".to_vec(),
                "text/plain".to_string(),
            ),
        )
        .unwrap();
        put_object(
            storage.as_ref(),
            "bucket",
            "key.txt".to_string(),
            Object::new(
                "key.txt".to_string(),
                b"v2".to_vec(),
                "text/plain".to_string(),
            ),
        )
        .unwrap();

        let versions = list_object_versions(storage.as_ref(), "bucket", Some("key.txt")).unwrap();
        assert!(versions.len() >= 2);
        assert!(versions.iter().all(|version| version.key == "key.txt"));
    }
}
