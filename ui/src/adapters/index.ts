/**
 * Public API adapter exports
 * This is the single entry point for API interactions
 */

export { apiClient } from "./api";
export type {
  BucketInfo,
  ObjectInfo,
  ListBucketsResponse,
  ListObjectsResponse,
  ApiError,
} from "./models";
