import {
  loadBucketDetail,
  loadBucketOverview,
  listObjects,
} from '../../adapters/blob-api';

export function loadBuckets({
  signal,
  search,
}: {
  signal: AbortSignal;
  search?: string;
}) {
  return loadBucketOverview({ signal, search });
}

export function loadBucket({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal: AbortSignal;
}) {
  return loadBucketDetail({ bucketName, signal });
}

export function loadBucketObjects({
  bucketName,
  search,
  signal,
}: {
  bucketName: string;
  search?: string;
  signal: AbortSignal;
}) {
  return listObjects({ bucketName, search, signal });
}
