import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import { Inline } from '@askrjs/themes/layouts';

export type MetricCardProps = {
  label: string;
  value: string;
  trend: string;
};

export default function MetricCard({ label, value, trend }: MetricCardProps) {
  return (
    <Card class="metric-card">
      <CardHeader>
        <Inline justify="between" align="center" gap="3">
          <CardDescription>{label}</CardDescription>
          <span class="metric-trend">{trend}</span>
        </Inline>
        <CardTitle>{value}</CardTitle>
      </CardHeader>
    </Card>
  );
}
