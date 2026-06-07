import { Link } from '@askrjs/askr/router';
import {
  Breadcrumb,
  BreadcrumbCurrent,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbSeparator,
} from '@askrjs/themes/navs';
import { blobParentPrefix } from '../../features/storage/path';
import { bucketFolderPath, bucketPath } from '../../shared/routes';

export default function BlobBreadcrumbs({
  blobKey,
  bucketName,
}: {
  blobKey: string;
  bucketName: string;
}) {
  const parentPrefix = blobParentPrefix(blobKey);

  return (
    <Breadcrumb aria-label="Blob path">
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href={bucketPath(bucketName)}>{bucketName}</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          {parentPrefix ? (
            <BreadcrumbLink asChild>
              <Link href={bucketFolderPath(bucketName, parentPrefix)}>
                {parentPrefix.replace(/\/$/, '')}
              </Link>
            </BreadcrumbLink>
          ) : (
            <BreadcrumbCurrent>root</BreadcrumbCurrent>
          )}
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  );
}
