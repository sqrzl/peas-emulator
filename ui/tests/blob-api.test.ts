import { describe, expect, it } from 'vite-plus/test';

import {
  createBucket,
  loadBuckets,
  setBucketVersioning,
} from '../src/features/buckets/buckets.query';
import {
  deleteObject,
  downloadObjectContent,
  loadObjectMetadata,
  loadObjectTags,
  loadObjectVersions,
  putObjectContent,
  putObjectTags,
} from '../src/features/objects/objects.query';

const originalFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
    },
  });
}

function binaryResponse(
  body: BodyInit,
  contentType = 'application/octet-stream'
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': contentType,
    },
  });
}

async function readBodyText(
  body: BodyInit | null | undefined
): Promise<string> {
  if (body === undefined || body === null) {
    return '';
  }

  if (typeof body === 'string') {
    return body;
  }

  if (body instanceof Blob) {
    return body.text();
  }

  if (body instanceof URLSearchParams) {
    return body.toString();
  }

  if (body instanceof ArrayBuffer) {
    return new TextDecoder().decode(body);
  }

  if (ArrayBuffer.isView(body)) {
    return new TextDecoder().decode(body);
  }

  return String(body);
}

function installBlobApiFetchMock(): void {
  const storedObjects = new Map<
    string,
    { body: string; contentType: string }
  >();
  let storedTags: Record<string, string> = {};

  const mockFetch: typeof fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit
  ) => {
    const requestUrl =
      typeof input === 'string' || input instanceof URL
        ? input.toString()
        : input.url;
    const url = new URL(requestUrl, 'http://localhost');
    const method = (
      init?.method ??
      (typeof input === 'string' || input instanceof URL
        ? 'GET'
        : input.method) ??
      'GET'
    ).toUpperCase();
    const headers = new Headers(
      init?.headers ??
        (typeof input === 'string' || input instanceof URL
          ? undefined
          : input.headers)
    );

    if (url.pathname === '/admin/v1/buckets' && method === 'GET') {
      return jsonResponse({
        items: [
          {
            name: 'alpha',
            created_at: '2026-05-25T09:00:00.000Z',
            versioning_enabled: true,
          },
          {
            name: 'beta',
            created_at: '2026-05-24T09:00:00.000Z',
            versioning_enabled: false,
          },
        ],
        next: null,
      });
    }

    if (url.pathname === '/admin/v1/buckets' && method === 'POST') {
      const body = JSON.parse(await readBodyText(init?.body)) as {
        name: string;
      };
      return jsonResponse(
        {
          name: body.name,
          created_at: '2026-05-25T10:30:00.000Z',
          versioning_enabled: false,
        },
        201
      );
    }

    if (
      url.pathname === '/admin/v1/buckets/alpha/versioning' &&
      method === 'PUT'
    ) {
      const body = JSON.parse(await readBodyText(init?.body)) as {
        enabled: boolean;
      };
      return jsonResponse({ enabled: body.enabled });
    }

    if (
      url.pathname === '/admin/v1/buckets/alpha/objects' &&
      method === 'GET'
    ) {
      return jsonResponse({
        items: [
          {
            key: 'docs/readme.txt',
            size: 5,
            etag: 'etag-alpha-1',
            last_modified: '2026-05-25T10:00:00.000Z',
            content_type: 'text/plain',
            storage_class: 'standard',
          },
        ],
        next: null,
      });
    }

    if (url.pathname === '/admin/v1/buckets/beta/objects' && method === 'GET') {
      return jsonResponse({
        items: [
          {
            key: 'image.png',
            size: 12,
            etag: 'etag-beta-1',
            last_modified: '2026-05-25T08:30:00.000Z',
            content_type: 'image/png',
            storage_class: 'standard',
          },
          {
            key: 'notes.txt',
            size: 18,
            etag: 'etag-beta-2',
            last_modified: '2026-05-25T08:35:00.000Z',
            content_type: 'text/plain',
            storage_class: 'standard',
          },
        ],
        next: null,
      });
    }

    if (
      url.pathname ===
        '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt/content' &&
      method === 'PUT'
    ) {
      const body = init?.body ?? '';
      const textBody = await readBodyText(body);
      storedObjects.set('docs/readme.txt', {
        body: textBody,
        contentType: headers.get('content-type') ?? 'application/octet-stream',
      });

      return jsonResponse(
        {
          key: 'docs/readme.txt',
          size: textBody.length,
          etag: 'etag-uploaded',
          last_modified: '2026-05-25T11:00:00.000Z',
          content_type: headers.get('content-type'),
          metadata: {
            owner: headers.get('x-amz-meta-owner') ?? '',
          },
          storage_class: 'standard',
          version_id: null,
        },
        201
      );
    }

    if (
      url.pathname ===
        '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt/content' &&
      method === 'GET'
    ) {
      const stored = storedObjects.get('docs/readme.txt');
      return binaryResponse(
        stored?.body ?? '',
        stored?.contentType ?? 'application/octet-stream'
      );
    }

    if (
      url.pathname === '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt' &&
      method === 'DELETE'
    ) {
      storedObjects.delete('docs/readme.txt');
      return new Response(null, { status: 204 });
    }

    if (
      url.pathname === '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt' &&
      method === 'GET'
    ) {
      return jsonResponse({
        key: 'docs/readme.txt',
        size: 5,
        etag: 'etag-uploaded',
        last_modified: '2026-05-25T11:00:00.000Z',
        content_type: 'text/plain',
        metadata: { owner: 'alice' },
        storage_class: 'standard',
        version_id: 'v1',
      });
    }

    if (
      url.pathname ===
        '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt/tags' &&
      method === 'PUT'
    ) {
      const body = JSON.parse(await readBodyText(init?.body)) as {
        tags: Record<string, string>;
      };
      storedTags = body.tags;
      return jsonResponse({ tags: storedTags });
    }

    if (
      url.pathname ===
        '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt/tags' &&
      method === 'GET'
    ) {
      return jsonResponse({ tags: storedTags });
    }

    if (
      url.pathname ===
        '/admin/v1/buckets/alpha/objects/docs%2Freadme.txt/versions' &&
      method === 'GET'
    ) {
      return jsonResponse({
        items: [
          {
            key: 'docs/readme.txt',
            version_id: 'v1',
            is_latest: true,
            size: 5,
            etag: 'etag-uploaded',
            last_modified: '2026-05-25T11:00:00.000Z',
          },
        ],
        next: null,
      });
    }

    throw new Error(
      `Unexpected request: ${method} ${url.pathname}${url.search}`
    );
  };

  (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch = mockFetch;
}

function restoreFetch(): void {
  (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch =
    originalFetch;
}

describe('generated admin feature workflows', () => {
  it('loads bucket overview through generated operations', async () => {
    installBlobApiFetchMock();

    try {
      const created = await createBucket({ name: 'gamma' });
      const versioning = await setBucketVersioning({
        bucketName: 'alpha',
        enabled: true,
      });
      const snapshot = await loadBuckets({
        signal: new AbortController().signal,
      });

      expect(created.name).toBe('gamma');
      expect(created.createdAt).toBe('2026-05-25T10:30:00.000Z');
      expect(versioning.enabled).toBe(true);
      expect(snapshot.totalBuckets).toBe(2);
      expect(snapshot.versioningEnabledBuckets).toBe(1);
      expect(snapshot.totalObjects).toBe(3);
      expect(snapshot.buckets[0].name).toBe('alpha');
      expect(snapshot.buckets[0].objectCount).toBe(1);
    } finally {
      restoreFetch();
    }
  });

  it('uploads, downloads, and deletes object content through fgrzl/fetch', async () => {
    installBlobApiFetchMock();

    try {
      const upload = await putObjectContent({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
        content: new Blob(['hello'], { type: 'text/plain' }),
        contentType: 'text/plain',
        metadata: { owner: 'alice' },
      });

      const download = await downloadObjectContent({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
      });

      await deleteObject({ bucketName: 'alpha', objectKey: 'docs/readme.txt' });

      expect(upload.key).toBe('docs/readme.txt');
      expect(upload.content_type).toBe('text/plain');
      expect(upload.metadata.owner).toBe('alice');
      expect(upload.size).toBe(5);
      expect(download.fileName).toBe('readme.txt');
      expect(download.contentType).toBe('text/plain');
      expect(await download.blob.text()).toBe('hello');
    } finally {
      restoreFetch();
    }
  });

  it('loads metadata and edits tags and versions through generated operations', async () => {
    installBlobApiFetchMock();
    const signal = new AbortController().signal;

    try {
      const metadata = await loadObjectMetadata({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
        signal,
      });
      await putObjectTags({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
        tags: { env: 'test' },
      });
      const tags = await loadObjectTags({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
        signal,
      });
      const versions = await loadObjectVersions({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
        signal,
      });

      expect(metadata.metadata.owner).toBe('alice');
      expect(tags.tags.env).toBe('test');
      expect(versions.items[0].version_id).toBe('v1');
    } finally {
      restoreFetch();
    }
  });
});
