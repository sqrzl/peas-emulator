import { navigate } from '@askrjs/askr/router';
import { ArrowLeftIcon, ArrowUpIcon } from '@askrjs/lucide';
import { Button, Stack } from '@askrjs/themes/components';
import BucketBreadcrumbs from '../../components/storage/bucket-breadcrumbs';
import BlobModal from '../../components/storage/blob-modal';
import BlobTable from '../../components/storage/blob-table';
import StoragePageHeader from '../../components/storage/storage-page-header';
import {
  normalizeStoragePathPrefix,
  parentStoragePathPrefix,
  storagePathLabel,
} from '../../features/storage/path';
import { adminBucketsPath, bucketFolderPath } from '../../shared/routes';

export default function Bucket({
  bucketName,
  pathPrefix = '',
}: {
  bucketName: string;
  pathPrefix?: string;
}) {
  const normalizedPrefix = normalizeStoragePathPrefix(pathPrefix);
  const locationLabel = storagePathLabel(bucketName, normalizedPrefix);

  return (
    <Stack gap="4">
      <BucketBreadcrumbs
        bucketName={bucketName}
        pathPrefix={normalizedPrefix}
      />

      <StoragePageHeader
        title={locationLabel}
        description={
          normalizedPrefix
            ? 'First-level folders and blobs in this path.'
            : 'First-level folders and blobs in this bucket.'
        }
        actions={
          <>
            <Button
              variant="secondary"
              onPress={() => navigate(adminBucketsPath())}
            >
              <ArrowLeftIcon aria-hidden="true" />
              Back to buckets
            </Button>
            {normalizedPrefix ? (
              <Button
                variant="secondary"
                onPress={() =>
                  navigate(
                    bucketFolderPath(
                      bucketName,
                      parentStoragePathPrefix(normalizedPrefix)
                    )
                  )
                }
              >
                <ArrowUpIcon aria-hidden="true" />
                Up one level
              </Button>
            ) : null}
            <BlobModal bucketName={bucketName} pathPrefix={normalizedPrefix} />
          </>
        }
      />

      <BlobTable bucketName={bucketName} pathPrefix={normalizedPrefix} />
    </Stack>
  );
}
