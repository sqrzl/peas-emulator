/**
 * API Response and Model types
 * These represent the data structures returned from the backend API
 */

// ============================================================================
// Bucket Models
// ============================================================================

export interface BucketInfo {
  name: string;
  created_at: string;
  versioning_enabled: boolean;
}

export interface BucketDetails {
  name: string;
  created_at: string;
  versioning_enabled: boolean;
}

export interface CreateBucketRequest {
  name: string;
}

export interface ListBucketsResponse {
  buckets: BucketInfo[];
}

export interface VersioningStatus {
  enabled: boolean;
}

// ============================================================================
// Object Models
// ============================================================================

export interface ObjectInfo {
  key: string;
  size: number;
  last_modified: string;
  etag: string;
  content_type?: string;
  storage_class: string;
}

export interface ObjectMetadata {
  key: string;
  size: number;
  last_modified: string;
  etag: string;
  content_type?: string;
  metadata: Record<string, string>;
  version_id?: string;
}

export interface ObjectVersionInfo {
  key: string;
  version_id: string;
  size: number;
  last_modified: string;
  etag: string;
  is_latest: boolean;
}

export interface ListObjectsResponse {
  objects: ObjectInfo[];
  prefix: string;
  delimiter?: string;
  is_truncated: boolean;
  next_marker?: string;
}

export interface ListVersionsResponse {
  versions: ObjectVersionInfo[];
}

// ============================================================================
// Tags
// ============================================================================

export interface TagsResponse {
  tags: Record<string, string>;
}

export interface TagsRequest {
  tags: Record<string, string>;
}

// ============================================================================
// Upload
// ============================================================================

export interface UploadOptions {
  key: string;
  contentType?: string;
  metadata?: Record<string, string>;
}

// ============================================================================
// Generic Responses
// ============================================================================

export interface SuccessResponse {
  success: boolean;
  [key: string]: unknown;
}

export interface ApiError {
  error: string;
}
