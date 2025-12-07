use crate::error::Error;
use crate::models::{LifecycleConfiguration, Status};
use crate::storage::Storage;
use chrono::{DateTime, Utc, NaiveDate};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, error, debug};

/// Background job that executes lifecycle rules periodically
pub struct LifecycleExecutor {
    storage: Arc<dyn Storage>,
    interval: Duration,
}

impl LifecycleExecutor {
    /// Create a new lifecycle executor with the specified interval.
    pub fn new(storage: Arc<dyn Storage>, interval: Duration) -> Self {
        Self { storage, interval }
    }

    /// Start the lifecycle executor as a background task
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!("Lifecycle executor started with interval: {:?}", self.interval);
            
            loop {
                tokio::time::sleep(self.interval).await;
                
                if let Err(e) = self.execute_lifecycle_rules().await {
                    error!("Failed to execute lifecycle rules: {}", e);
                }
            }
        })
    }

    async fn execute_lifecycle_rules(&self) -> Result<(), Error> {
        debug!("Executing lifecycle rules...");
        let now = Utc::now();
        
        // Get all buckets
        let buckets = tokio::task::block_in_place(|| self.storage.list_buckets())?;
        
        for bucket in buckets {
            // Get lifecycle configuration for this bucket
            let config = match tokio::task::block_in_place(|| self.storage.get_bucket_lifecycle(&bucket.name)) {
                Ok(cfg) => cfg,
                Err(Error::KeyNotFound) => continue, // No lifecycle config
                Err(e) => {
                    error!("Failed to get lifecycle config for bucket {}: {}", bucket.name, e);
                    continue;
                }
            };
            
            self.apply_lifecycle_rules(&bucket.name, &config, now).await?;
        }
        
        debug!("Lifecycle rules execution completed");
        Ok(())
    }

    async fn apply_lifecycle_rules(
        &self,
        bucket_name: &str,
        config: &LifecycleConfiguration,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        for rule in &config.rules {
            // Skip disabled rules
            if rule.status != Status::Enabled {
                continue;
            }

            debug!(
                bucket = bucket_name,
                rule_id = rule.id.as_deref().unwrap_or("unnamed"),
                "Applying lifecycle rule"
            );

            // List all objects in the bucket (using pagination)
            let result = tokio::task::block_in_place(|| {
                self.storage.list_objects(bucket_name, None, None, None, None)
            })?;
            let objects = result.objects;

            for object in objects {
                // Get object tags
                let tags = tokio::task::block_in_place(|| {
                    self.storage.get_object_tags(bucket_name, &object.key)
                }).unwrap_or_default();

                // Check if filter matches
                if let Some(filter) = &rule.filter {
                    if !filter.matches(&object.key, &tags) {
                        continue;
                    }
                }

                // Apply expiration action
                if let Some(expiration) = &rule.expiration {
                    if self.should_expire(object.last_modified, expiration, now) {
                        info!(
                            bucket = bucket_name,
                            key = object.key,
                            rule_id = rule.id.as_deref().unwrap_or("unnamed"),
                            "Expiring object"
                        );
                        
                        let _ = tokio::task::block_in_place(|| {
                            self.storage.delete_object(bucket_name, &object.key)
                        });
                    }
                }

                // Transitions would be applied here (not implemented in emulator)
                // As an emulator, we don't actually move objects between storage classes
            }
        }

        Ok(())
    }

    fn should_expire(
        &self,
        last_modified: DateTime<Utc>,
        expiration: &crate::models::lifecycle::Expiration,
        now: DateTime<Utc>,
    ) -> bool {
        let object_date = last_modified;

        // Check days-based expiration
        if let Some(days) = expiration.days {
            let age_days = (now - object_date).num_days();
            if age_days >= days as i64 {
                return true;
            }
        }

        // Check date-based expiration (ISO 8601 format: YYYY-MM-DD)
        if let Some(date_str) = &expiration.date {
            if let Ok(expire_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                let expire_datetime = expire_date.and_hms_opt(0, 0, 0)
                    .map(|dt| dt.and_utc());
                
                if let Some(expire_dt) = expire_datetime {
                    if now >= expire_dt {
                        return true;
                    }
                }
            }
        }

        false
    }
}
