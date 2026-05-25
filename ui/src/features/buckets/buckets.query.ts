import { adminApi } from '../../adapters';
import { unwrapProtectedResponse } from '../auth/admin-session';
import { countBucketObjects, loadObjectPage } from '../objects/objects.query';

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
  bucket: Omit<BucketOverviewItem, 'objectCount'>;
  versioning: { enabled: boolean };
};

export type BucketPage = {
  items: Array<Omit<BucketOverviewItem, 'objectCount'>>;
  next: string | null;
};

export async function loadBuckets({
  signal,
}: {
  signal: AbortSignal;
}): Promise<BucketOverview> {
  const buckets = await listEveryBucket({ signal });
  const items = await Promise.all(
    buckets.map(async (bucket) => ({
      name: bucket.name,
      createdAt: bucket.created_at,
      versioningEnabled: bucket.versioning_enabled,
      objectCount: await countBucketObjects({
        bucketName: bucket.name,
        signal,
      }),
    }))
  );

  items.sort((left, right) => right.createdAt.localeCompare(left.createdAt));

  return {
    totalBuckets: items.length,
    versioningEnabledBuckets: items.filter((bucket) => bucket.versioningEnabled)
      .length,
    totalObjects: items.reduce(
      (total, bucket) => total + bucket.objectCount,
      0
    ),
    buckets: items,
  };
}

export async function listBucketPage({
  next,
  search,
  signal,
}: {
  next?: string;
  search?: string;
  signal: AbortSignal;
}): Promise<BucketPage> {
  const data = unwrapProtectedResponse(
    await adminApi.listBuckets(
      { next, limit: 50, search: search?.trim() || undefined },
      { signal }
    )
  );

  return {
    items: data.items.map((bucket) => ({
      name: bucket.name,
      createdAt: bucket.created_at,
      versioningEnabled: bucket.versioning_enabled,
    })),
    next: data.next,
  };
}

export async function loadBucket({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal: AbortSignal;
}): Promise<BucketDetail> {
  const [bucket, versioning] = await Promise.all([
    adminApi.getBucket(bucketName, { signal }).then(unwrapProtectedResponse),
    adminApi
      .getBucketVersioning(bucketName, { signal })
      .then(unwrapProtectedResponse),
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

export async function createBucket({
  name,
  signal,
}: {
  name: string;
  signal?: AbortSignal;
}): Promise<BucketDetail['bucket']> {
  const data = unwrapProtectedResponse(
    await adminApi.createBucket({ name }, { signal })
  );
  return {
    name: data.name,
    createdAt: data.created_at,
    versioningEnabled: data.versioning_enabled,
  };
}

export async function deleteBucket({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<void> {
  unwrapProtectedResponse(await adminApi.deleteBucket(bucketName, { signal }));
}

export async function setBucketVersioning({
  bucketName,
  enabled,
  signal,
}: {
  bucketName: string;
  enabled: boolean;
  signal?: AbortSignal;
}): Promise<{ enabled: boolean }> {
  return unwrapProtectedResponse(
    await adminApi.setBucketVersioning(bucketName, { enabled }, { signal })
  );
}

export const loadBucketObjects = loadObjectPage;

async function listEveryBucket({ signal }: { signal: AbortSignal }) {
  const items = [];
  let next: string | undefined;

  do {
    const page = unwrapProtectedResponse(
      await adminApi.listBuckets({ next, limit: 500 }, { signal })
    );
    items.push(...page.items);
    next = page.next ?? undefined;
  } while (next);

  return items;
}
