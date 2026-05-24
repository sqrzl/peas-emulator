import { describe, expect, it } from 'vite-plus/test';
import { getOperationsSnapshot } from '../src/adapters/operations-client';
import { loadOperations } from '../src/features/operations/operations.query';

describe('operations data flow', () => {
  it('loads the dashboard snapshot through the feature query boundary', async () => {
    const snapshot = await loadOperations({});

    expect(snapshot.metrics.length).toBeGreaterThan(0);
    expect(snapshot.runs.length).toBeGreaterThan(0);
    expect(snapshot.lastEventId).toMatch(/^evt_/);
  });

  it('keeps cancellation owned by the adapter', async () => {
    const controller = new AbortController();
    const request = getOperationsSnapshot({ signal: controller.signal });

    controller.abort();

    await expect(request).rejects.toThrow(/aborted/i);
  });
});
