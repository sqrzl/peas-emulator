import { describe, expect, it } from 'vite-plus/test';

import { loadOperations } from '../src/features/operations/operations.query';

const originalFetch = globalThis.fetch;
let observedAbort = false;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
    },
  });
}

function installStorageApiFetchMock(): void {
  const mockFetch: typeof fetch = async (input: RequestInfo | URL) => {
    const requestUrl =
      typeof input === 'string' || input instanceof URL
        ? input.toString()
        : input.url;
    const url = new URL(requestUrl, 'http://localhost');

    if (
      url.pathname === '/admin/v1/buckets' &&
      url.searchParams.get('limit') === '500'
    ) {
      if (url.searchParams.get('next') === 'page-2') {
        return jsonResponse({
          items: [
            {
              name: 'beta',
              created_at: '2026-05-24T09:00:00.000Z',
              versioning_enabled: false,
            },
          ],
          next: null,
        });
      }

      return jsonResponse({
        items: [
          {
            name: 'alpha',
            created_at: '2026-05-25T09:00:00.000Z',
            versioning_enabled: true,
          },
        ],
        next: 'page-2',
      });
    }

    if (
      url.pathname === '/admin/v1/buckets/alpha/objects' &&
      url.searchParams.get('limit') === '500'
    ) {
      if (url.searchParams.get('next') === 'object-2') {
        return jsonResponse({
          items: [{ key: 'two' }],
          next: null,
        });
      }

      return jsonResponse({
        items: [{ key: 'one' }],
        next: 'object-2',
      });
    }

    if (
      url.pathname === '/admin/v1/buckets/beta/objects' &&
      url.searchParams.get('limit') === '500'
    ) {
      return jsonResponse({
        items: [{ key: 'three' }],
        next: null,
      });
    }

    throw new Error(`Unexpected request: ${url.pathname}${url.search}`);
  };

  (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch = mockFetch;
}

function installAbortAwareFetchMock(): void {
  observedAbort = false;
  const mockFetch: typeof fetch = (
    _input: RequestInfo | URL,
    init?: RequestInit
  ) =>
    new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;

      if (signal?.aborted) {
        reject(new DOMException('Operation aborted', 'AbortError'));
        return;
      }

      signal?.addEventListener(
        'abort',
        () => {
          observedAbort = true;
          reject(new DOMException('Operation aborted', 'AbortError'));
        },
        { once: true }
      );
    });

  (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch = mockFetch;
}

function restoreFetch(): void {
  (globalThis as typeof globalThis & { fetch: typeof fetch }).fetch =
    originalFetch;
}

describe('operations data flow', () => {
  it('paginates complete storage totals through the feature query boundary', async () => {
    installStorageApiFetchMock();

    try {
      const snapshot = await loadOperations({});

      expect(snapshot.totalBuckets).toBe(2);
      expect(snapshot.versioningEnabledBuckets).toBe(1);
      expect(snapshot.totalObjects).toBe(3);
      expect(snapshot.objectCounts[0]).toEqual({ label: 'alpha', value: 2 });
      expect(snapshot.bucketAges[0].value).toBeLessThan(24 * 365);
      expect(snapshot.buckets[0].name).toBe('alpha');
    } finally {
      restoreFetch();
    }
  });

  it('keeps cancellation owned by the adapter', async () => {
    installAbortAwareFetchMock();

    const controller = new AbortController();
    const request = loadOperations({ signal: controller.signal });

    controller.abort();

    try {
      await expect(request).rejects.toThrow(/failed to fetch/i);
      expect(observedAbort).toBe(true);
    } finally {
      restoreFetch();
    }
  });
});
