import { cleanupApp, createSPA } from '@askrjs/askr/boot';
import { clearRoutes, getRoutes } from '@askrjs/askr/router';
import { describe, expect, it } from 'vite-plus/test';
import {
  bucketFolderRouteDepth,
  bucketFolderRoutePaths,
  pathPrefixFromBucketFolderRouteParams,
  registerAppRoutes,
} from '../src/pages/app/_routes';
import {
  adminBucketsPath,
  blobIdFromBlobKey,
  blobPath,
  bucketFolderPath,
  bucketPath,
  loginPath,
  logoutPath,
} from '../src/shared/routes';

const originalFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('shared route helpers', () => {
  it('builds deterministic uuid-style blob ids from blob keys', () => {
    const nestedBlobId = blobIdFromBlobKey('dir1/dir2/blobkey.png');

    expect(nestedBlobId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(nestedBlobId).toBe(blobIdFromBlobKey('dir1/dir2/blobkey.png'));
    expect(nestedBlobId).not.toBe(blobIdFromBlobKey('blobkey.png'));
    expect(blobPath('demo-bucket', 'dir1/dir2/blobkey.png')).toBe(
      `${bucketPath('demo-bucket')}/blob/${nestedBlobId}`
    );
    expect(blobPath('demo-bucket', 'dir1/dir2/blobkey.png')).not.toContain(
      '%2F'
    );
  });

  it('points the canonical ui routes at the admin surface', () => {
    expect(adminBucketsPath()).toBe('/admin/buckets');
    expect(bucketPath('demo bucket')).toBe('/admin/buckets/demo%20bucket');
    expect(bucketFolderPath('demo bucket', 'dir one/child/')).toBe(
      '/admin/buckets/demo%20bucket/dir%20one/child'
    );
    expect(loginPath()).toBe('/login');
    expect(logoutPath()).toBe('/logout');
  });

  it('registers bounded multi-level bucket folder routes', () => {
    const folderRoutes = bucketFolderRoutePaths();

    expect(folderRoutes).toHaveLength(bucketFolderRouteDepth);
    expect(folderRoutes).toContain('/admin/buckets/{bucketName}/{path0}');
    expect(folderRoutes).toContain(
      '/admin/buckets/{bucketName}/{path0}/{path1}'
    );
    expect(
      pathPrefixFromBucketFolderRouteParams(
        { bucketName: 'demo', path0: 'docs', path1: 'api' },
        2
      )
    ).toBe('docs/api');

    clearRoutes();
    try {
      registerAppRoutes();
      const paths = getRoutes().map((route) => route.path);

      expect(paths).toContain('/admin/buckets/{bucketName}/blob/{blobId}');
      expect(paths).toContain('/admin/buckets/{bucketName}/{path0}/{path1}');
      expect(paths).not.toContain('/admin/buckets/{bucketName}/*');
    } finally {
      clearRoutes();
    }
  });

  it('resolves multi-level bucket folder routes to the bucket page', async () => {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const request =
        typeof input === 'string' || input instanceof URL
          ? new Request(input, init)
          : input;
      const url = new URL(request.url, 'http://localhost');

      if (
        url.pathname === '/admin/v1/buckets/demo/objects' &&
        request.method === 'GET'
      ) {
        expect(url.searchParams.get('search')).toBe('docs/api/');
        return jsonResponse({
          items: [
            {
              key: 'docs/api/openapi.json',
              size: 17,
              etag: 'etag-openapi',
              last_modified: '2026-05-25T11:15:00.000Z',
              content_type: 'application/json',
              storage_class: 'standard',
            },
          ],
          next: null,
        });
      }

      throw new Error(
        `Unexpected request: ${request.method} ${url.pathname}${url.search}`
      );
    };

    const originalUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const root = document.createElement('div');
    document.body.appendChild(root);

    try {
      clearRoutes();
      registerAppRoutes();
      const routes = getRoutes();
      window.history.pushState(null, '', '/admin/buckets/demo/docs/api');

      await createSPA({ root, routes });
      await flush();

      expect(root.textContent).toContain('openapi.json');
      expect(root.textContent).toContain('demo');
      expect(root.textContent).toContain('docs');
      expect(root.textContent).toContain('api');
    } finally {
      cleanupApp(root);
      root.remove();
      clearRoutes();
      window.history.pushState(null, '', originalUrl || '/');
      globalThis.fetch = originalFetch;
    }
  });
});
