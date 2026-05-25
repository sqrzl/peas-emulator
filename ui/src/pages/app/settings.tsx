import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import { Block, Stack } from '@askrjs/themes/layouts';
import { adminApiPath } from '../../adapters';

export default function SettingsPage() {
  return (
    <Stack gap="5">
      <section class="page-heading">
        <Stack gap="2">
          <Badge>environment</Badge>
          <h1>Settings</h1>
          <p class="lead">
            The admin API client is configured once in the adapter boundary and
            reused by every real data source.
          </p>
        </Stack>
      </section>

      <Block size="lg" gap="4" align="start" class="settings-grid">
        <Card>
          <CardHeader>
            <CardTitle>Admin API client</CardTitle>
            <CardDescription>
              Keep transport concerns in the adapter layer and out of route
              components.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              <Badge>baseUrl {adminApiPath}</Badge>
              <Badge>credentials same-origin</Badge>
              <Badge>FetchClient exported from src/adapters/index.ts</Badge>
            </Stack>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Real data policy</CardTitle>
            <CardDescription>
              The UI now reflects live admin resources instead of fabricated
              projection data.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              <Badge>live bucket inventory</Badge>
              <Badge>real object counts</Badge>
              <Badge>manual refresh available</Badge>
            </Stack>
          </CardContent>
        </Card>
      </Block>
    </Stack>
  );
}
