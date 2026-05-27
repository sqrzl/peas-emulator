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
          <Badge>integration</Badge>
          <h1>Session and transport</h1>
          <p class="lead">The UI uses the generated adapter and same-origin cookies.</p>
        </Stack>
      </section>

      <Block size="lg" gap="4" align="start" class="settings-grid">
        <Card>
          <CardHeader>
            <CardTitle>Transport</CardTitle>
            <CardDescription>One adapter owns the admin API base URL and cookie policy.</CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              <Badge>baseUrl {adminApiPath}</Badge>
              <Badge>same-origin cookies</Badge>
              <Badge>generated adapter</Badge>
            </Stack>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Session</CardTitle>
            <CardDescription>Session state comes from the admin auth endpoint.</CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              {session.pending ? <Badge>checking session</Badge> : null}
              {session.value ? (
                <>
                  <Badge>mode {session.value.mode}</Badge>
                  <Badge>username {session.value.username ?? 'not required'}</Badge>
                </>
              ) : (
                <Badge>no active session</Badge>
              )}
              {session.error ? <Badge>session unavailable</Badge> : null}
            </Stack>
          </CardContent>
        </Card>
      </Block>
    </Stack>
  );
}
