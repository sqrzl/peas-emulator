use crossbeam_skiplist::SkipMap;

/// Lock-free concurrent index for object keys by bucket
/// Uses crossbeam's SkipMap for atomic, wait-free reads
pub struct LockFreeIndex {
    // Map from bucket_name to SkipMap of keys
    buckets: SkipMap<String, SkipMap<String, ()>>,
}

impl LockFreeIndex {
    pub fn new() -> Self {
        Self {
            buckets: SkipMap::new(),
        }
    }

    /// Insert an object key into a bucket's index
    pub fn insert(&self, bucket: String, key: String) {
        // Get or create bucket map
        if let Some(entry) = self.buckets.get(&bucket) {
            entry.value().insert(key, ());
        } else {
            let bucket_map = SkipMap::new();
            bucket_map.insert(key, ());
            self.buckets.insert(bucket, bucket_map);
        }
    }

    /// Remove an object key from a bucket's index
    pub fn remove(&self, bucket: &str, key: &str) -> bool {
        if let Some(entry) = self.buckets.get(bucket) {
            entry.value().remove(key).is_some()
        } else {
            false
        }
    }

    /// Check if an object exists in a bucket
    pub fn contains(&self, bucket: &str, key: &str) -> bool {
        if let Some(entry) = self.buckets.get(bucket) {
            entry.value().get(key).is_some()
        } else {
            false
        }
    }

    /// Get all keys in a bucket matching optional prefix
    pub fn list(&self, bucket: &str, prefix: Option<&str>) -> Vec<String> {
        if let Some(entry) = self.buckets.get(bucket) {
            entry
                .value()
                .iter()
                .filter_map(|node| {
                    let key = node.key();
                    if prefix.is_none_or(|p| key.starts_with(p)) {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clear all keys from a bucket
    pub fn clear_bucket(&self, bucket: &str) {
        self.buckets.remove(bucket);
    }

    /// Get or create a bucket entry
    pub fn get_or_create_bucket(&self, bucket: String) {
        if self.buckets.get(&bucket).is_none() {
            self.buckets.insert(bucket, SkipMap::new());
        }
    }

    /// Populate index from iterator of (bucket, keys) pairs
    pub fn rebuild<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (String, Vec<String>)>,
    {
        for (bucket, keys) in entries {
            let bucket_map = SkipMap::new();
            for key in keys {
                bucket_map.insert(key, ());
            }
            self.buckets.insert(bucket, bucket_map);
        }
    }

    /// Check if bucket exists
    pub fn bucket_exists(&self, bucket: &str) -> bool {
        self.buckets.contains_key(bucket)
    }
}

impl Default for LockFreeIndex {
    fn default() -> Self {
        Self::new()
    }
}
