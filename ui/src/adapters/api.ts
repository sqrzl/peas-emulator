/**
 * API adapter layer
 * Encapsulates all fetch calls to the backend
 * All /api/* calls are proxied by vite/nginx to the backend
 */

import type {
  ListBucketsResponse,
  ListObjectsResponse,
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

  /**
   * List all buckets
   * GET /api/buckets
   */
  async listBuckets(): Promise<ListBucketsResponse> {
    return this.request<ListBucketsResponse>("/buckets");
  }

  /**
   * List objects in a bucket
   * GET /api/buckets/{bucket}/objects?prefix=...&delimiter=...
   */
  async listObjects(
    bucketName: string,
    prefix?: string,
    delimiter?: string,
  ): Promise<ListObjectsResponse> {
    const params = new URLSearchParams();
    if (prefix) params.append("prefix", prefix);
    if (delimiter) params.append("delimiter", delimiter);

    const query = params.toString();
    const path =
      `/buckets/${encodeURIComponent(bucketName)}/objects` +
      (query ? `?${query}` : "");

    return this.request<ListObjectsResponse>(path);
  }
}

export const apiClient = new ApiClient();
