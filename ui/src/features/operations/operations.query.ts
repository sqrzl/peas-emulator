import { getOperationsSnapshot } from '../../adapters/operations-client';

export function loadOperations({
  signal = new AbortController().signal,
}: {
  signal?: AbortSignal;
}) {
  return getOperationsSnapshot({ signal });
}
