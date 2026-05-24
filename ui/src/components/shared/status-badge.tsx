import { Badge } from '@askrjs/themes/surfaces';

export type RunStatus =
  | 'queued'
  | 'running'
  | 'requires-action'
  | 'succeeded'
  | 'failed';

export type StatusBadgeProps = {
  status: RunStatus;
};

const labels: Record<RunStatus, string> = {
  queued: 'queued',
  running: 'running',
  'requires-action': 'needs review',
  succeeded: 'succeeded',
  failed: 'failed',
};

export default function StatusBadge({ status }: StatusBadgeProps) {
  return <Badge data-status={status}>{labels[status]}</Badge>;
}
