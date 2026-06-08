import { route } from '@askrjs/askr/router';
import Buckets from './buckets';
import BucketPage from './bucket';
import BlobPage from './blob';
import { adminBucketsPath } from '../../shared/routes';

export const bucketFolderRouteDepth = 64;

type BucketFolderRouteParams = Record<string, string | undefined>;

function bucketFolderRouteSegments(depth: number): string {
  return Array.from({ length: depth }, (_, index) => `{path${index}}`).join(
    '/'
  );
}

export function bucketFolderRoutePaths(): string[] {
  return Array.from(
    { length: bucketFolderRouteDepth },
    (_, index) =>
      `${adminBucketsPath()}/{bucketName}/${bucketFolderRouteSegments(index + 1)}`
  );
}

export function pathPrefixFromBucketFolderRouteParams(
  params: BucketFolderRouteParams,
  depth: number
): string {
  return Array.from({ length: depth }, (_, index) => params[`path${index}`])
    .filter(Boolean)
    .join('/');
}

function registerBucketFolderRoutes(): void {
  bucketFolderRoutePaths().forEach((path, index) => {
    const depth = index + 1;
    route(path, (params: BucketFolderRouteParams) => (
      <BucketPage
        bucketName={params.bucketName ?? ''}
        pathPrefix={pathPrefixFromBucketFolderRouteParams(params, depth)}
      />
    ));
  });
}

export function registerAppRoutes(): void {
  route(adminBucketsPath(), Buckets);
  route(`${adminBucketsPath()}/{bucketName}`, (params) => (
    <BucketPage bucketName={params.bucketName ?? ''} />
  ));
  route(`${adminBucketsPath()}/{bucketName}/blob/{blobId}`, (params) => (
    <BlobPage
      bucketName={params.bucketName ?? ''}
      blobId={params.blobId ?? ''}
    />
  ));
  registerBucketFolderRoutes();
}
