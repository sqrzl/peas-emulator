import { describe, expect, it } from 'vite-plus/test';

import {
  createBucket,
  deleteObject,
  downloadObjectContent,
  loadBucketOverview,
  putObjectContent,
  setBucketVersioning,
} from '../src/adapters/blob-api';

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
    { body: BodyInit; contentType: string }
  >();

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

    if (url.pathname === '/buckets' && method === 'GET') {
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

    if (url.pathname === '/buckets' && method === 'POST') {
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

    if (url.pathname === '/buckets/alpha/versioning' && method === 'PUT') {
      const body = JSON.parse(await readBodyText(init?.body)) as {
        enabled: boolean;
      };
      return jsonResponse({ enabled: body.enabled });
    }

    if (url.pathname === '/buckets/alpha/objects' && method === 'GET') {
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

    if (url.pathname === '/buckets/beta/objects' && method === 'GET') {
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
      url.pathname === '/buckets/alpha/objects/docs%2Freadme.txt/content' &&
      method === 'PUT'
    ) {
      const body = init?.body ?? '';
      storedObjects.set('docs/readme.txt', {
        body,
        contentType: headers.get('content-type') ?? 'application/octet-stream',
      });

      const textBody = await readBodyText(body);
      return jsonResponse(
        {
          key: 'docs/readme.txt',
          size: textBody.length,
          etag: 'etag-uploaded',
          last_modified: '2026-05-25T11:00:00.000Z',
          content_type: headers.get('content-type'),
          metadata: {},
          storage_class: 'standard',
          version_id: null,
        },
        201
      );
    }

    if (
      url.pathname === '/buckets/alpha/objects/docs%2Freadme.txt/content' &&
      method === 'GET'
    ) {
      const stored = storedObjects.get('docs/readme.txt');
      return binaryResponse(
        stored?.body ?? new Blob([''], { type: 'application/octet-stream' }),
        stored?.contentType ?? 'application/octet-stream'
      );
    }

    if (
      url.pathname === '/buckets/alpha/objects/docs%2Freadme.txt' &&
      method === 'DELETE'
    ) {
      storedObjects.delete('docs/readme.txt');
      return new Response(null, { status: 204 });
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

describe('blob adapter', () => {
  it('loads bucket overview from the shared fetch client', async () => {
    installBlobApiFetchMock();

    try {
      const created = await createBucket({ name: 'gamma' });
      const versioning = await setBucketVersioning({
        bucketName: 'alpha',
        enabled: true,
      });
      const snapshot = await loadBucketOverview({});

      expect(created.name).toBe('gamma');
      expect(created.created_at).toBe('2026-05-25T10:30:00.000Z');
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
      });

      const download = await downloadObjectContent({
        bucketName: 'alpha',
        objectKey: 'docs/readme.txt',
      });

      await deleteObject({ bucketName: 'alpha', objectKey: 'docs/readme.txt' });

      expect(upload.key).toBe('docs/readme.txt');
      expect(upload.content_type).toBe('text/plain');
      expect(upload.size).toBe(5);
      expect(download.fileName).toBe('readme.txt');
      expect(download.contentType).toBe('text/plain');
      expect(await download.blob.text()).toBe('hello');
    } finally {
      restoreFetch();
    }
  });
});
