import { resource } from '@askrjs/askr/resources';
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
import { loadAdminSession } from '../../features/auth/admin-session';

export default function SettingsPage() {
  const session = resource(({ signal }) => loadAdminSession({ signal }), []);

  return (
    <Stack gap="5">
      <section class="page-heading">
        <Stack gap="2">
          <Badge>environment</Badge>
          <h1>Environment and integration</h1>
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
              <Badge>generated OpenAPI adapter</Badge>
            </Stack>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Resolved session</CardTitle>
            <CardDescription>
              Session status is reported by the documented admin auth operation.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              {session.pending ? <Badge>checking session</Badge> : null}
              {session.value ? (
                <>
                  <Badge>mode {session.value.mode}</Badge>
                  <Badge>
                    username {session.value.username ?? 'not required'}
                  </Badge>
                </>
              ) : null}
              {session.error ? <Badge>session unavailable</Badge> : null}
            </Stack>
          </CardContent>
        </Card>
      </Block>
    </Stack>
  );
}
