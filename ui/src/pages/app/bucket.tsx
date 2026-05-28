import { Link } from '@askrjs/askr/router';
import { Button } from '@askrjs/themes/controls';
import { Inline, Stack } from '@askrjs/themes/layouts';
import BlobModal from '../../components/storage/blob-modal';
import BlobTable from '../../components/storage/blob-table';
import { adminBucketsPath } from '../../shared/routes';

export default function Bucket({ bucketName }: { bucketName: string }) {
  return (
    <Stack gap="4">
      <Inline justify="between" align="center" gap="3" wrap="wrap">
        <Stack gap="1">
          <h1>{bucketName}</h1>
          <p>All blobs in this bucket.</p>
        </Stack>
        <Inline gap="2" align="center" wrap="wrap">
          <Button variant="secondary" asChild>
            <Link href={adminBucketsPath()}>Back to buckets</Link>
          </Button>
          <BlobModal bucketName={bucketName} />
        </Inline>
      </Inline>

      <BlobTable bucketName={bucketName} />
    </Stack>
  );
}
