import { resource } from '@askrjs/askr/resources';
import { AlertCircleIcon, RefreshCwIcon } from '@askrjs/lucide';
import { Button } from '@askrjs/themes/controls';
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Skeleton,
} from '@askrjs/themes/surfaces';
import { Block, Inline, Section, Stack } from '@askrjs/themes/layouts';
import { EmptyState } from '@askrjs/themes/feedback';
import MetricCard from '../../components/shared/metric-card';
import { loadOperations } from '../../features/operations/operations.query';
import { formatRelativeTime } from '../../shared/format';

export default function AdminHomePage() {
  const operations = resource(({ signal }) => loadOperations({ signal }), []);
  const snapshot = operations.value;

  if (operations.error && !snapshot) {
    return (
      <Section>
        <EmptyState
          icon={<AlertCircleIcon size={24} aria-hidden="true" />}
          title="Storage overview could not load"
          description="The dashboard keeps failures recoverable. Retry the live admin API call instead of hiding the error in a toast."
          actions={<Button onPress={() => operations.refresh()}>Retry</Button>}
        />
      </Section>
    );
  }

  if (snapshot && snapshot.totalBuckets === 0) {
    return (
      <Section>
        <EmptyState
          icon={<AlertCircleIcon size={24} aria-hidden="true" />}
          title="No buckets yet"
          description="Create a bucket through the admin API and this overview will populate with live storage data."
          actions={
            <Button onPress={() => operations.refresh()}>Refresh</Button>
          }
        />
      </Section>
    );
  }

  return (
    <Stack gap="5">
      <section class="page-heading">
        <Stack gap="2">
          <Badge>overview</Badge>
          <h1>Storage overview</h1>
          <p class="lead">Live bucket inventory from the admin API.</p>
        </Stack>
        <Inline gap="2" align="center">
          {operations.pending && snapshot ? <Badge>refreshing</Badge> : null}
          <Button variant="secondary" onPress={() => operations.refresh()}>
            <RefreshCwIcon size={14} aria-hidden="true" /> Refresh
          </Button>
        </Inline>
      </section>

      {operations.pending && !snapshot ? (
        <Stack gap="3">
          <Skeleton style="height: 6rem" />
          <Skeleton style="height: 6rem" />
          <Skeleton style="height: 18rem" />
        </Stack>
      ) : null}

      {snapshot ? (
        <>
          <Block size="sm" gap="4" class="metric-grid">
            <MetricCard
              label="Buckets"
              value={snapshot.totalBuckets.toString()}
              trend={
                snapshot.buckets[0]
                  ? `newest ${formatRelativeTime(snapshot.buckets[0].createdAt)}`
                  : 'no buckets'
              }
            />
            <MetricCard
              label="Versioning enabled"
              value={snapshot.versioningEnabledBuckets.toString()}
              trend={
                snapshot.totalBuckets > 0
                  ? `${Math.round(
                      (snapshot.versioningEnabledBuckets /
                        snapshot.totalBuckets) *
                        100
                    )}% enabled`
                  : '0% enabled'
              }
            />
            <MetricCard
              label="Objects"
              value={snapshot.totalObjects.toString()}
              trend={
                snapshot.totalBuckets > 0
                  ? `${Math.round(snapshot.totalObjects / snapshot.totalBuckets)} avg per bucket`
                  : '0 avg'
              }
            />
          </Block>

          <Card>
            <CardHeader>
              <CardTitle>Recent buckets</CardTitle>
              <CardDescription>Bucket metadata comes from the live API.</CardDescription>
            </CardHeader>
            <CardContent>
              <div class="run-table-wrap">
                <table class="run-table">
                  <thead>
                    <tr>
                      <th>Bucket</th>
                      <th>Objects</th>
                      <th>Versioning</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapshot.buckets.map((bucket) => (
                      <tr key={bucket.name}>
                        <td>
                          <strong>{bucket.name}</strong>
                          <span>
                            {bucket.versioningEnabled
                              ? 'versioning on'
                              : 'versioning off'}
                          </span>
                        </td>
                        <td>{bucket.objectCount}</td>
                        <td>
                          <Badge>
                            {bucket.versioningEnabled ? 'enabled' : 'disabled'}
                          </Badge>
                        </td>
                        <td>{formatRelativeTime(bucket.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      ) : null}
    </Stack>
  );
}
