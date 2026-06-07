import { For } from '@askrjs/askr/control';
import { Link } from '@askrjs/askr/router';
import {
  Breadcrumb,
  BreadcrumbCurrent,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbSeparator,
} from '@askrjs/themes/navs';
import { storagePathCrumbs } from '../../features/storage/path';
import { adminBucketsPath, bucketFolderPath } from '../../shared/routes';

export default function BucketBreadcrumbs({
  bucketName,
  pathPrefix,
}: {
  bucketName: string;
  pathPrefix: string;
}) {
  const crumbs = storagePathCrumbs(pathPrefix);

  return (
    <Breadcrumb aria-label="Bucket path">
      <BreadcrumbList>
        <BreadcrumbItem>
          <BreadcrumbLink asChild>
            <Link href={adminBucketsPath()}>Buckets</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator />
        <BreadcrumbItem>
          {crumbs.length > 0 ? (
            <BreadcrumbLink asChild>
              <Link href={bucketFolderPath(bucketName, '')}>{bucketName}</Link>
            </BreadcrumbLink>
          ) : (
            <BreadcrumbCurrent>{bucketName}</BreadcrumbCurrent>
          )}
        </BreadcrumbItem>
        <For each={crumbs} by={(crumb) => crumb.prefix}>
          {(crumb) => (
            <BreadcrumbItem>
              <BreadcrumbSeparator />
              {crumb.current ? (
                <BreadcrumbCurrent>{crumb.label}</BreadcrumbCurrent>
              ) : (
                <BreadcrumbLink asChild>
                  <Link href={bucketFolderPath(bucketName, crumb.prefix)}>
                    {crumb.label}
                  </Link>
                </BreadcrumbLink>
              )}
            </BreadcrumbItem>
          )}
        </For>
      </BreadcrumbList>
    </Breadcrumb>
  );
}
