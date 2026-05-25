import type {
  BucketDetails,
  ErrorResponse,
  ListBucketsResponse,
  ListObjectsResponse,
  ListVersionsResponse,
  ObjectMetadata,
  TagsRequest,
  TagsResponse,
  VersioningStatus,
} from './api.g';
import { api } from './index';
import type { FetchResponse } from '@fgrzl/fetch';

type RequestOptions = {
  signal?: AbortSignal;
};

type JsonRequestOptions = RequestOptions & {
  body?: unknown;
  headers?: HeadersInit;
  method?: string;
};

const defaultHeaders: HeadersInit = {
  accept: 'application/json',
};

export type BucketOverviewItem = {
  name: string;
  createdAt: string;
  versioningEnabled: boolean;
  objectCount: number;
};

export type BucketOverview = {
  totalBuckets: number;
  versioningEnabledBuckets: number;
  totalObjects: number;
  buckets: BucketOverviewItem[];
};

export type BucketDetail = {
  bucket: {
    name: string;
    createdAt: string;
    versioningEnabled: boolean;
  };
  versioning: VersioningStatus;
};

export type DownloadedObject = {
  blob: Blob;
  contentType: string;
  fileName: string;
};

export async function listBuckets({
  search,
  signal,
}: {
  search?: string;
  signal?: AbortSignal;
}): Promise<ListBucketsResponse> {
  const query = new URLSearchParams({ limit: '500' });
  if (search?.trim()) {
    query.set('search', search.trim());
  }

  return requestJson<ListBucketsResponse>(`/buckets?${query.toString()}`, {
    signal,
  });
}

export async function createBucket({
  name,
  signal,
}: {
  name: string;
  signal?: AbortSignal;
}): Promise<BucketDetails> {
  return requestJson<BucketDetails>('/buckets', {
    method: 'POST',
    signal,
    body: { name },
  });
}

export async function deleteBucket({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<void> {
  await requestVoid(`/buckets/${encodeURIComponent(bucketName)}`, {
    method: 'DELETE',
    signal,
  });
}

export async function getBucket({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<BucketDetails> {
  return requestJson<BucketDetails>(
    `/buckets/${encodeURIComponent(bucketName)}`,
    {
      signal,
    }
  );
}

export async function getBucketVersioning({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<VersioningStatus> {
  return requestJson<VersioningStatus>(
    `/buckets/${encodeURIComponent(bucketName)}/versioning`,
    {
      signal,
    }
  );
}

export async function setBucketVersioning({
  bucketName,
  enabled,
  signal,
}: {
  bucketName: string;
  enabled: boolean;
  signal?: AbortSignal;
}): Promise<VersioningStatus> {
  return requestJson<VersioningStatus>(
    `/buckets/${encodeURIComponent(bucketName)}/versioning`,
    {
      method: 'PUT',
      signal,
      body: { enabled },
    }
  );
}

export async function listObjects({
  bucketName,
  search,
  next,
  signal,
}: {
  bucketName: string;
  search?: string;
  next?: string;
  signal?: AbortSignal;
}): Promise<ListObjectsResponse> {
  const query = new URLSearchParams({ limit: '500' });
  if (search?.trim()) {
    query.set('search', search.trim());
  }
  if (next) {
    query.set('next', next);
  }

  return requestJson<ListObjectsResponse>(
    `/buckets/${encodeURIComponent(bucketName)}/objects?${query.toString()}`,
    {
      signal,
    }
  );
}

export async function getObjectMetadata({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<ObjectMetadata> {
  return requestJson<ObjectMetadata>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}`,
    {
      signal,
    }
  );
}

export async function downloadObjectContent({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<DownloadedObject> {
  const response = await requestResponse<Blob | string | null>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}/content`,
    {
      signal,
    }
  );

  const contentType =
    response.headers.get('content-type') ?? 'application/octet-stream';
  const content = response.data;
  const blob =
    content instanceof Blob
      ? content
      : new Blob([content ?? ''], {
          type: contentType,
        });

  return {
    blob,
    contentType,
    fileName: objectKey.split('/').filter(Boolean).pop() ?? objectKey,
  };
}

export async function putObjectContent({
  bucketName,
  objectKey,
  content,
  contentType,
  metadata,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  content: BodyInit;
  contentType?: string;
  metadata?: Record<string, string>;
  signal?: AbortSignal;
}): Promise<ObjectMetadata> {
  const headers = new Headers();

  headers.set('content-type', contentType ?? 'application/octet-stream');
  for (const [key, value] of Object.entries(metadata ?? {})) {
    headers.set(`x-amz-meta-${key}`, value);
  }

  const response = await requestResponse<ObjectMetadata>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}/content`,
    {
      method: 'PUT',
      signal,
      headers,
      body: content,
    }
  );

  return response.data as ObjectMetadata;
}

export async function deleteObject({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<void> {
  await requestVoid(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}`,
    {
      method: 'DELETE',
      signal,
    }
  );
}

export async function getObjectTags({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<TagsResponse> {
  return requestJson<TagsResponse>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}/tags`,
    {
      signal,
    }
  );
}

export async function putObjectTags({
  bucketName,
  objectKey,
  tags,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  tags: TagsRequest['tags'];
  signal?: AbortSignal;
}): Promise<TagsResponse> {
  return requestJson<TagsResponse>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}/tags`,
    {
      method: 'PUT',
      signal,
      body: { tags },
    }
  );
}

export async function listObjectVersions({
  bucketName,
  objectKey,
  search,
  next,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  search?: string;
  next?: string;
  signal?: AbortSignal;
}): Promise<ListVersionsResponse> {
  const query = new URLSearchParams({ limit: '500' });

  if (search?.trim()) {
    query.set('search', search.trim());
  }

  if (next) {
    query.set('next', next);
  }

  return requestJson<ListVersionsResponse>(
    `/buckets/${encodeURIComponent(bucketName)}/objects/${encodeURIComponent(objectKey)}/versions?${query.toString()}`,
    {
      signal,
    }
  );
}

export async function loadBucketOverview({
  search,
  signal,
}: {
  search?: string;
  signal?: AbortSignal;
}): Promise<BucketOverview> {
  const bucketPage = await listBuckets({ search, signal });
  const buckets = await Promise.all(
    bucketPage.items.map(async (bucket) => ({
      name: bucket.name,
      createdAt: bucket.created_at,
      versioningEnabled: bucket.versioning_enabled,
      objectCount: (await listObjects({ bucketName: bucket.name, signal }))
        .items.length,
    }))
  );

  const totalObjects = buckets.reduce(
    (count, bucket) => count + bucket.objectCount,
    0
  );

  return {
    totalBuckets: buckets.length,
    versioningEnabledBuckets: buckets.filter(
      (bucket) => bucket.versioningEnabled
    ).length,
    totalObjects,
    buckets,
  };
}

export async function loadBucketDetail({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<BucketDetail> {
  const [bucket, versioning] = await Promise.all([
    getBucket({ bucketName, signal }),
    getBucketVersioning({ bucketName, signal }),
  ]);

  return {
    bucket: {
      name: bucket.name,
      createdAt: bucket.created_at,
      versioningEnabled: bucket.versioning_enabled,
    },
    versioning,
  };
}

async function requestJson<T>(
  path: string,
  { body, headers, method, signal }: JsonRequestOptions = {}
): Promise<T> {
  const response = await requestResponse<T>(path, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: mergeHeaders(headers, body),
    method,
    signal,
  });

  return response.data as T;
}

async function requestVoid(
  path: string,
  { body, headers, method, signal }: JsonRequestOptions = {}
): Promise<void> {
  await requestResponse<void>(path, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: mergeHeaders(headers, body),
    method,
    signal,
  });
}

async function requestResponse<T>(
  path: string,
  init: RequestInit = {}
): Promise<FetchResponse<T>> {
  const response = await api.request<T>(path, init);

  if (!response.ok) {
    throw new Error(readErrorMessage(response));
  }

  return response;
}

function mergeHeaders(
  headers: HeadersInit | undefined,
  body: unknown
): Headers {
  const merged = new Headers(defaultHeaders);

  if (headers) {
    new Headers(headers).forEach((value, key) => {
      merged.set(key, value);
    });
  }

  if (body !== undefined && !merged.has('content-type')) {
    merged.set('content-type', 'application/json');
  }

  return merged;
}

function readErrorMessage(
  response: Pick<FetchResponse<unknown>, 'error' | 'statusText'>
): string {
  const errorBody = response.error?.body;

  if (errorBody && typeof errorBody === 'object') {
    const body = errorBody as Partial<ErrorResponse>;

    if (typeof body.details === 'string' && body.details.trim()) {
      return body.details;
    }

    if (typeof body.error === 'string' && body.error.trim()) {
      return body.error;
    }
  }

  return response.error?.message ?? response.statusText ?? 'Request failed';
}
