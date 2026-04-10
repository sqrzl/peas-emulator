use crate::error::Result;
use crate::models::Bucket;
use crate::storage::Storage;

pub fn list_buckets(storage: &dyn Storage) -> Result<Vec<Bucket>> {
    storage.list_buckets()
}

pub fn create_bucket(storage: &dyn Storage, name: String) -> Result<()> {
    storage.create_bucket(name)
}

pub fn get_bucket(storage: &dyn Storage, name: &str) -> Result<Bucket> {
    storage.get_bucket(name)
}

pub fn delete_bucket(storage: &dyn Storage, name: &str) -> Result<()> {
    storage.delete_bucket(name)
}

pub fn set_versioning(storage: &dyn Storage, bucket: &str, enabled: bool) -> Result<()> {
    if enabled {
        storage.enable_versioning(bucket)
    } else {
        storage.suspend_versioning(bucket)
    }
}

pub fn versioning_enabled(bucket: &Bucket) -> bool {
    bucket.versioning_enabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FilesystemStorage;
    use std::fs;
    use std::sync::Arc;

    fn temp_storage() -> Arc<dyn Storage> {
        let dir =
            std::env::temp_dir().join(format!("peas-service-bucket-test-{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        Arc::new(FilesystemStorage::new(dir))
    }

    #[test]
    fn should_create_list_get_and_delete_bucket() {
        let storage = temp_storage();

        create_bucket(storage.as_ref(), "demo".to_string()).unwrap();

        let buckets = list_buckets(storage.as_ref()).unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name, "demo");

        let bucket = get_bucket(storage.as_ref(), "demo").unwrap();
        assert_eq!(bucket.name, "demo");
        assert!(!versioning_enabled(&bucket));

        delete_bucket(storage.as_ref(), "demo").unwrap();
        assert!(list_buckets(storage.as_ref()).unwrap().is_empty());
    }

    #[test]
    fn should_toggle_versioning_for_bucket() {
        let storage = temp_storage();
        create_bucket(storage.as_ref(), "demo".to_string()).unwrap();

        set_versioning(storage.as_ref(), "demo", true).unwrap();
        assert!(
            get_bucket(storage.as_ref(), "demo")
                .unwrap()
                .versioning_enabled
        );

        set_versioning(storage.as_ref(), "demo", false).unwrap();
        assert!(
            !get_bucket(storage.as_ref(), "demo")
                .unwrap()
                .versioning_enabled
        );
    }
}
