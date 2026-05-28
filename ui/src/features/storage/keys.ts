export const bucketListKey = 'buckets';

export function blobListKey(bucketName: string): string {
  return `blobs:${bucketName}`;
}
