import { getStorageOverview } from '../../adapters/storage-overview-client';

export function loadOperations({
  signal = new AbortController().signal,
}: {
  signal?: AbortSignal;
}) {
  return getStorageOverview({ signal });
}
