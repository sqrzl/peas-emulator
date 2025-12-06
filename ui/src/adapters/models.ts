/**
 * API Response and Model types
 * These represent the data structures returned from the backend API
 */

export interface BucketInfo {
  name: string;
  created_at: string;
}

export interface ObjectInfo {
  key: string;
  size: number;
  last_modified: string;
  etag: string;
}

export interface ListBucketsResponse {
  buckets: BucketInfo[];
}

export interface ListObjectsResponse {
  objects: ObjectInfo[];
  prefix: string;
  delimiter?: string;
}

export interface ApiError {
  error: string;
}
