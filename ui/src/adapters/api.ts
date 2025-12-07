/**
 * API adapter layer
 * Encapsulates all fetch calls to the backend
 * All /api/* calls are proxied by vite/nginx to the backend
 */

import type {
  ListBucketsResponse,
  ListObjectsResponse,
  BucketDetails,
  CreateBucketRequest,
  VersioningStatus,
  ObjectMetadata,
  ListVersionsResponse,
  TagsResponse,
  TagsRequest,
  SuccessResponse,
  UploadOptions,
  ApiError,
} from "./models";

const API_BASE = "/api";

class ApiClient {
  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const url = `${API_BASE}${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: `HTTP ${response.status}`,
      }));
      throw new Error(error.error || `Request failed: ${response.status}`);
    }

    return response.json() as Promise<T>;
  }

  // ==========================================================================
  // Bucket Operations
  // ==========================================================================

  /**
   * List all buckets
   * GET /api/buckets
   */
  async listBuckets(): Promise<ListBucketsResponse> {
    return this.request<ListBucketsResponse>("/buckets");
  }

  /**
   * Create a new bucket
   * POST /api/buckets
   */
  async createBucket(name: string): Promise<SuccessResponse> {
    return this.request<SuccessResponse>("/buckets", {
      method: "POST",
      body: JSON.stringify({ name } as CreateBucketRequest),
    });
  }

  /**
   * Get bucket details
   * GET /api/buckets/{bucket}
   */
  async getBucket(bucketName: string): Promise<BucketDetails> {
    return this.request<BucketDetails>(
      `/buckets/${encodeURIComponent(bucketName)}`,
    );
  }

  /**
   * Delete a bucket
   * DELETE /api/buckets/{bucket}
   */
  async deleteBucket(bucketName: string): Promise<void> {
    const url = `${API_BASE}/buckets/${encodeURIComponent(bucketName)}`;
    const response = await fetch(url, { method: "DELETE" });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: `HTTP ${response.status}`,
      }));
      throw new Error(error.error || `Failed to delete bucket`);
    }
  }

  /**
   * Get bucket versioning status
   * GET /api/buckets/{bucket}/versioning
   */
  async getVersioning(bucketName: string): Promise<VersioningStatus> {
    return this.request<VersioningStatus>(
      `/buckets/${encodeURIComponent(bucketName)}/versioning`,
    );
  }

  /**
   * Enable or disable bucket versioning
   * PUT /api/buckets/{bucket}/versioning
   */
  async setVersioning(
    bucketName: string,
    enabled: boolean,
  ): Promise<SuccessResponse> {
    return this.request<SuccessResponse>(
      `/buckets/${encodeURIComponent(bucketName)}/versioning`,
      {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      },
    );
  }

  // ==========================================================================
  // Object Operations
  // ==========================================================================

  /**
   * List objects in a bucket
   * GET /api/buckets/{bucket}/objects?prefix=...&delimiter=...&marker=...&max-keys=...
   */
  async listObjects(
    bucketName: string,
    prefix?: string,
    delimiter?: string,
    marker?: string,
    maxKeys?: number,
  ): Promise<ListObjectsResponse> {
    const params = new URLSearchParams();
    if (prefix) params.append("prefix", prefix);
    if (delimiter) params.append("delimiter", delimiter);
    if (marker) params.append("marker", marker);
    if (maxKeys) params.append("max-keys", maxKeys.toString());

    const query = params.toString();
    const path =
      `/buckets/${encodeURIComponent(bucketName)}/objects` +
      (query ? `?${query}` : "");

    return this.request<ListObjectsResponse>(path);
  }

  /**
   * Get object metadata
   * GET /api/buckets/{bucket}/objects/{key}/metadata
   */
  async getObjectMetadata(
    bucketName: string,
    key: string,
  ): Promise<ObjectMetadata> {
    return this.request<ObjectMetadata>(
      `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}/metadata`,
    );
  }

  /**
   * Download an object
   * GET /api/buckets/{bucket}/objects/{key}/download
   * Returns a Blob for download
   */
  async downloadObject(bucketName: string, key: string): Promise<Blob> {
    const url = `${API_BASE}/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}/download`;
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Failed to download object: ${response.status}`);
    }

    return response.blob();
  }

  /**
   * Upload an object
   * POST /api/buckets/{bucket}/objects?key={key}
   */
  async uploadObject(
    bucketName: string,
    file: File | Blob,
    options: UploadOptions,
  ): Promise<SuccessResponse> {
    const params = new URLSearchParams({ key: options.key });
    const url = `${API_BASE}/buckets/${encodeURIComponent(bucketName)}/objects?${params}`;

    const headers: HeadersInit = {};
    if (options.contentType) {
      headers["Content-Type"] = options.contentType;
    }

    // Add metadata headers
    if (options.metadata) {
      for (const [key, value] of Object.entries(options.metadata)) {
        headers[`x-amz-meta-${key}`] = value;
      }
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: file,
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: `HTTP ${response.status}`,
      }));
      throw new Error(error.error || `Failed to upload object`);
    }

    return response.json();
  }

  /**
   * Delete an object
   * DELETE /api/buckets/{bucket}/objects/{key}
   */
  async deleteObject(bucketName: string, key: string): Promise<void> {
    const url = `${API_BASE}/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}`;
    const response = await fetch(url, { method: "DELETE" });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: `HTTP ${response.status}`,
      }));
      throw new Error(error.error || `Failed to delete object`);
    }
  }

  // ==========================================================================
  // Versioning Operations
  // ==========================================================================

  /**
   * List all versions of an object
   * GET /api/buckets/{bucket}/objects/{key}/versions
   */
  async listObjectVersions(
    bucketName: string,
    key: string,
  ): Promise<ListVersionsResponse> {
    return this.request<ListVersionsResponse>(
      `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}/versions`,
    );
  }

  // ==========================================================================
  // Tagging Operations
  // ==========================================================================

  /**
   * Get object tags
   * GET /api/buckets/{bucket}/objects/{key}/tags
   */
  async getObjectTags(
    bucketName: string,
    key: string,
  ): Promise<TagsResponse> {
    return this.request<TagsResponse>(
      `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}/tags`,
    );
  }

  /**
   * Set object tags
   * PUT /api/buckets/{bucket}/objects/{key}/tags
   */
  async setObjectTags(
    bucketName: string,
    key: string,
    tags: Record<string, string>,
  ): Promise<SuccessResponse> {
    return this.request<SuccessResponse>(
      `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(key)}/tags`,
      {
        method: "PUT",
        body: JSON.stringify({ tags } as TagsRequest),
      },
    );
  }
}

export const apiClient = new ApiClient();
