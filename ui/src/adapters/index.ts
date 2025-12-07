/**
 * Public API adapter exports
 * This is the single entry point for API interactions
 */

export { apiClient } from "./api";
export type {
  // Bucket types
  BucketInfo,
  BucketDetails,
  CreateBucketRequest,
  ListBucketsResponse,
  VersioningStatus,
  // Object types
  ObjectInfo,
  ObjectMetadata,
  ObjectVersionInfo,
  ListObjectsResponse,
  ListVersionsResponse,
  // Tags
  TagsResponse,
  TagsRequest,
  // Upload
  UploadOptions,
  // Generic
  SuccessResponse,
  ApiError,
} from "./models";
