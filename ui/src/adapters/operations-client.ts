import type { RunStatus } from '../components/shared/status-badge';

export type OperationRun = {
  id: string;
  title: string;
  status: RunStatus;
  owner: string;
  updatedAt: string;
};

export type OperationsSnapshot = {
  version: number;
  consistency: 'fresh' | 'pending-write' | 'stale';
  lastEventId: string;
  metrics: Array<{ label: string; value: string; trend: string }>;
  throughput: Array<{ label: string; value: number }>;
  lag: Array<{ label: string; value: number }>;
  runs: OperationRun[];
};

export async function getOperationsSnapshot({
  signal,
}: {
  signal: AbortSignal;
}): Promise<OperationsSnapshot> {
  await delay(220, signal);

  return {
    version: 42,
    consistency: 'fresh',
    lastEventId: 'evt_18442',
    metrics: [
      { label: 'Active runs', value: '12', trend: '+3 today' },
      { label: 'Pending approvals', value: '3', trend: '2 urgent' },
      { label: 'Projection lag', value: '1.2s', trend: 'healthy' },
    ],
    throughput: [
      { label: 'Research', value: 18 },
      { label: 'Review', value: 11 },
      { label: 'Deploy', value: 7 },
      { label: 'Audit', value: 9 },
    ],
    lag: [
      { label: '10:00', value: 4 },
      { label: '10:10', value: 3 },
      { label: '10:20', value: 2 },
      { label: '10:30', value: 1 },
      { label: '10:40', value: 2 },
      { label: '10:50', value: 1 },
    ],
    runs: [
      {
        id: 'run_4812',
        title: 'Summarize renewal risk',
        status: 'running',
        owner: 'Revenue ops',
        updatedAt: '2026-05-22T09:52:00.000Z',
      },
      {
        id: 'run_4811',
        title: 'Approve workspace migration',
        status: 'requires-action',
        owner: 'Platform',
        updatedAt: '2026-05-22T09:40:00.000Z',
      },
      {
        id: 'run_4810',
        title: 'Reconcile audit events',
        status: 'succeeded',
        owner: 'Security',
        updatedAt: '2026-05-22T09:25:00.000Z',
      },
    ],
  };
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = globalThis.setTimeout(resolve, ms);

    signal.addEventListener(
      'abort',
      () => {
        globalThis.clearTimeout(timeout);
        reject(new DOMException('Operation aborted', 'AbortError'));
      },
      { once: true }
    );
  });
}
