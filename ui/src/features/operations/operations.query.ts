import { loadBuckets } from '../buckets/buckets.query';

export async function loadOperations({
  signal = new AbortController().signal,
}: {
  signal?: AbortSignal;
}) {
  const snapshot = await loadBuckets({ signal });
  const now = Date.now();

  return {
    ...snapshot,
    objectCounts: snapshot.buckets.map((bucket) => ({
      label: bucket.name,
      value: bucket.objectCount,
    })),
    bucketAges: snapshot.buckets.map((bucket) => ({
      label: bucket.name,
      value: Math.max(
        0,
        Math.round((now - Date.parse(bucket.createdAt)) / (60 * 60 * 1000))
      ),
    })),
  };
}
