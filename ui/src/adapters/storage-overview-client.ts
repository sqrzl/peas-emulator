import { api } from './index';
import type {
  BucketInfo,
  ListBucketsResponse,
  ListObjectsResponse,
} from './api.g';
import type { FetchResponse } from '@fgrzl/fetch';

export type BucketSummary = {
  name: string;
  createdAt: string;
  versioningEnabled: boolean;
  objectCount: number;
};

export type StorageOverview = {
  totalBuckets: number;
  versioningEnabledBuckets: number;
  totalObjects: number;
  objectCounts: Array<{ label: string; value: number }>;
  bucketAges: Array<{ label: string; value: number }>;
  buckets: BucketSummary[];
};

export async function getStorageOverview({
  signal,
}: {
  signal: AbortSignal;
}): Promise<StorageOverview> {
  const bucketSummaries = await loadBucketSummaries(signal);
  const sortedByAge = [...bucketSummaries].sort(
    (left, right) => parseDate(right.createdAt) - parseDate(left.createdAt)
  );
  const sortedByCount = [...bucketSummaries].sort(
    (left, right) => right.objectCount - left.objectCount
  );

  const totalBuckets = bucketSummaries.length;
  const versioningEnabledBuckets = bucketSummaries.filter(
    (bucket) => bucket.versioningEnabled
  ).length;
  const totalObjects = bucketSummaries.reduce(
    (count, bucket) => count + bucket.objectCount,
    0
  );

  return {
    totalBuckets,
    versioningEnabledBuckets,
    totalObjects,
    objectCounts: sortedByCount.slice(0, 6).map((bucket) => ({
      label: bucket.name,
      value: bucket.objectCount,
    })),
    bucketAges: sortedByAge.slice(0, 6).map((bucket) => ({
      label: bucket.name,
      value: hoursSince(bucket.createdAt),
    })),
    buckets: sortedByAge,
  };
}

async function loadBucketSummaries(
  signal: AbortSignal
): Promise<BucketSummary[]> {
  const buckets = await listAllBuckets(signal);

  return Promise.all(
    buckets.map(async (bucket) => ({
      name: bucket.name,
      createdAt: bucket.created_at,
      versioningEnabled: bucket.versioning_enabled,
      objectCount: await countObjects(bucket.name, signal),
    }))
  );
}

async function listAllBuckets(signal: AbortSignal): Promise<BucketInfo[]> {
  const buckets: BucketInfo[] = [];
  let next: string | null = null;

  do {
    const response: FetchResponse<ListBucketsResponse> = await api.get(
      buildBucketsPath(next),
      undefined,
      {
        signal,
      }
    );
    if (!response.ok || response.data === null) {
      throw new Error(response.error?.message ?? 'Unable to load buckets.');
    }
    const bucketPage = response.data;
    buckets.push(...bucketPage.items);
    next = bucketPage.next;
  } while (next);

  return buckets;
}

async function countObjects(
  bucketName: string,
  signal: AbortSignal
): Promise<number> {
  let next: string | null = null;
  let objectCount = 0;

  do {
    const response: FetchResponse<ListObjectsResponse> = await api.get(
      buildObjectsPath(bucketName, next),
      undefined,
      {
        signal,
      }
    );
    if (!response.ok || response.data === null) {
      throw new Error(
        response.error?.message ?? `Unable to load objects for ${bucketName}.`
      );
    }
    const objectPage = response.data;
    objectCount += objectPage.items.length;
    next = objectPage.next;
  } while (next);

  return objectCount;
}

function buildBucketsPath(next: string | null): string {
  const query = new URLSearchParams({ limit: '500' });

  if (next) {
    query.set('next', next);
  }

  return `/buckets?${query.toString()}`;
}

function buildObjectsPath(bucketName: string, next: string | null): string {
  const query = new URLSearchParams({ limit: '500' });

  if (next) {
    query.set('next', next);
  }

  return `/buckets/${encodeURIComponent(bucketName)}/objects?${query.toString()}`;
}

function parseDate(value: string): number {
  return new Date(value).getTime();
}

function hoursSince(value: string): number {
  return Math.max(1, Math.round((Date.now() - parseDate(value)) / 3_600_000));
}
