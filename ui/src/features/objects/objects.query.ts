import { adminApi } from '../../adapters';
import type {
  Acl,
  ListVersionsResponse,
  ObjectInfo,
  ObjectMetadata,
  TagsResponse,
} from '../../adapters/api.g';
import { unwrapProtectedResponse } from '../auth/admin-session';

export type ObjectPage = {
  items: ObjectInfo[];
  next: string | null;
};

export type DownloadedObject = {
  blob: Blob;
  contentType: string;
  fileName: string;
};

export async function loadObjectPage({
  bucketName,
  next,
  search,
  signal,
}: {
  bucketName: string;
  next?: string;
  search?: string;
  signal: AbortSignal;
}): Promise<ObjectPage> {
  return unwrapProtectedResponse(
    await adminApi.listObjects(
      bucketName,
      { next, limit: 50, search: search?.trim() || undefined },
      { signal }
    )
  );
}

export async function loadAllObjectPages({
  bucketName,
  search,
  signal,
}: {
  bucketName: string;
  search?: string;
  signal: AbortSignal;
}): Promise<ObjectInfo[]> {
  const items: ObjectInfo[] = [];
  let next: string | undefined;

  do {
    const page = await loadObjectPage({
      bucketName,
      next,
      search,
      signal,
    });

    items.push(...page.items);
    next = page.next ?? undefined;
  } while (next);

  return items;
}

export async function countBucketObjects({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal: AbortSignal;
}): Promise<number> {
  let count = 0;
  let next: string | undefined;

  do {
    const page = unwrapProtectedResponse(
      await adminApi.listObjects(bucketName, { next, limit: 500 }, { signal })
    );
    count += page.items.length;
    next = page.next ?? undefined;
  } while (next);

  return count;
}

export async function loadObjectMetadata({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal: AbortSignal;
}): Promise<ObjectMetadata> {
  return unwrapProtectedResponse(
    await adminApi.getObjectMetadata(bucketName, objectKey, { signal })
  );
}

export async function loadObjectTags({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal: AbortSignal;
}): Promise<TagsResponse> {
  return unwrapProtectedResponse(
    await adminApi.getObjectTags(bucketName, objectKey, { signal })
  );
}

export async function putObjectTags({
  bucketName,
  objectKey,
  tags,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  tags: Record<string, string>;
  signal?: AbortSignal;
}): Promise<TagsResponse> {
  return unwrapProtectedResponse(
    await adminApi.putObjectTags(bucketName, objectKey, { tags }, { signal })
  );
}

export async function loadObjectAcl({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal: AbortSignal;
}): Promise<Acl> {
  return unwrapProtectedResponse(
    await adminApi.getObjectAcl(bucketName, objectKey, { signal })
  );
}

export async function saveObjectAcl({
  bucketName,
  objectKey,
  acl,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  acl: Acl;
  signal?: AbortSignal;
}): Promise<Acl> {
  return unwrapProtectedResponse(
    await adminApi.setObjectAcl(bucketName, objectKey, acl, { signal })
  );
}

export async function loadObjectVersions({
  bucketName,
  objectKey,
  next,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  next?: string;
  signal: AbortSignal;
}): Promise<ListVersionsResponse> {
  return unwrapProtectedResponse(
    await adminApi.listObjectVersions(
      bucketName,
      objectKey,
      { next, limit: 25 },
      { signal }
    )
  );
}

export async function putObjectContent({
  bucketName,
  objectKey,
  content,
  contentType,
  metadata,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  content: BodyInit;
  contentType?: string;
  metadata?: Record<string, string>;
  signal?: AbortSignal;
}): Promise<ObjectMetadata> {
  const headers = new Headers();
  headers.set('content-type', contentType ?? 'application/octet-stream');
  Object.entries(metadata ?? {}).forEach(([name, value]) => {
    headers.set(`x-amz-meta-${name}`, value);
  });

  return unwrapProtectedResponse(
    await adminApi.putObjectContent(bucketName, objectKey, content, headers, {
      signal,
    })
  );
}

export async function downloadObjectContent({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<DownloadedObject> {
  const response = await adminApi.downloadObjectContent(bucketName, objectKey, {
    signal,
  });
  const content = unwrapProtectedResponse(response) as unknown;
  const contentType =
    response.headers.get('content-type') ?? 'application/octet-stream';
  const blob =
    content instanceof Blob
      ? content
      : new Blob([String(content ?? '')], { type: contentType });

  return {
    blob,
    contentType,
    fileName: objectKey.split('/').filter(Boolean).pop() ?? objectKey,
  };
}

export async function deleteObject({
  bucketName,
  objectKey,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  signal?: AbortSignal;
}): Promise<void> {
  unwrapProtectedResponse(
    await adminApi.deleteObject(bucketName, objectKey, { signal })
  );
}

export async function deleteAllBucketObjects({
  bucketName,
  signal,
}: {
  bucketName: string;
  signal?: AbortSignal;
}): Promise<number> {
  let deleted = 0;
  let keepDeleting = true;

  while (keepDeleting) {
    const page = await loadObjectPage({
      bucketName,
      next: undefined,
      signal: signal ?? new AbortController().signal,
    });

    if (page.items.length === 0) {
      keepDeleting = false;
      continue;
    }

    for (const object of page.items) {
      await deleteObject({ bucketName, objectKey: object.key, signal });
      deleted += 1;
    }
  }

  return deleted;
}

export async function deleteObjectVersion({
  bucketName,
  objectKey,
  versionId,
  signal,
}: {
  bucketName: string;
  objectKey: string;
  versionId: string;
  signal?: AbortSignal;
}): Promise<void> {
  unwrapProtectedResponse(
    await adminApi.deleteObjectVersion(bucketName, objectKey, versionId, {
      signal,
    })
  );
}
