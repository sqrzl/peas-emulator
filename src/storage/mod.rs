use crate::error::Result;
use crate::models::{Bucket, ListObjectsResult, MultipartUpload, Object};

pub mod filesystem;
pub mod indexed;
pub mod lockfree_index;

pub use filesystem::FilesystemStorage;
pub use indexed::IndexedStorage;
pub use lockfree_index::LockFreeIndex;

/// Storage backend trait - synchronous operations
/// HTTP layer handles async/await by calling these on thread pool
pub trait Storage: Send + Sync {
    // Bucket operations
    fn create_bucket(&self, name: String) -> Result<()>;
    fn delete_bucket(&self, name: &str) -> Result<()>;
    fn get_bucket(&self, name: &str) -> Result<Bucket>;
    fn list_buckets(&self) -> Result<Vec<Bucket>>;
    fn bucket_exists(&self, name: &str) -> Result<bool>;

    // Object operations
    fn put_object(&self, bucket: &str, key: String, object: Object) -> Result<()>;
    fn get_object(&self, bucket: &str, key: &str) -> Result<Object>;
    fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(Object, Vec<u8>)>;
    fn delete_object(&self, bucket: &str, key: &str) -> Result<()>;
    fn update_object_storage_class(
        &self,
        bucket: &str,
        key: &str,
        storage_class: &str,
    ) -> Result<()>;
    fn object_exists(&self, bucket: &str, key: &str) -> Result<bool>;
    fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        marker: Option<&str>,
        max_keys: Option<usize>,
    ) -> Result<ListObjectsResult>;

    // Multipart operations
    fn create_multipart_upload(&self, bucket: &str, key: String) -> Result<MultipartUpload>;
    fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        data: Vec<u8>,
    ) -> Result<String>;
    fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<MultipartUpload>>;
    fn list_parts(&self, bucket: &str, upload_id: &str) -> Result<Vec<crate::models::Part>>;
    fn get_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<MultipartUpload>;
    fn complete_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<String>;
    fn abort_multipart_upload(&self, bucket: &str, upload_id: &str) -> Result<()>;

    // Versioning operations
    fn enable_versioning(&self, bucket: &str) -> Result<()>;
    fn suspend_versioning(&self, bucket: &str) -> Result<()>;
    fn get_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<Object>;
    fn list_object_versions(&self, bucket: &str, prefix: Option<&str>) -> Result<Vec<Object>>;
    fn delete_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<()>;

    // Tagging operations
    fn get_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<std::collections::HashMap<String, String>>;
    fn put_object_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<()>;
    fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<()>;

    // ACL operations
    fn get_bucket_acl(&self, bucket: &str) -> Result<crate::models::policy::Acl>;
    fn put_bucket_acl(&self, bucket: &str, acl: crate::models::policy::Acl) -> Result<()>;
    fn get_object_acl(&self, bucket: &str, key: &str) -> Result<crate::models::policy::Acl>;
    fn put_object_acl(
        &self,
        bucket: &str,
        key: &str,
        acl: crate::models::policy::Acl,
    ) -> Result<()>;

    // Lifecycle operations
    fn get_bucket_lifecycle(
        &self,
        bucket: &str,
    ) -> Result<crate::models::lifecycle::LifecycleConfiguration>;
    fn put_bucket_lifecycle(
        &self,
        bucket: &str,
        config: crate::models::lifecycle::LifecycleConfiguration,
    ) -> Result<()>;
    fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<()>;

    // Policy operations
    fn get_bucket_policy(
        &self,
        bucket: &str,
    ) -> Result<crate::models::policy::BucketPolicyDocument>;
    fn put_bucket_policy(
        &self,
        bucket: &str,
        policy: crate::models::policy::BucketPolicyDocument,
    ) -> Result<()>;
    fn delete_bucket_policy(&self, bucket: &str) -> Result<()>;
}
