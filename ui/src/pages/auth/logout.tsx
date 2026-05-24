import { resource } from '@askrjs/askr/resources';
import { Link } from '@askrjs/askr/router';
import { LogOutIcon } from '@askrjs/lucide';
import { Button } from '@askrjs/themes/controls';
import { Container, Section, Stack } from '@askrjs/themes/layouts';
import { EmptyState } from '@askrjs/themes/feedback';
import { logoutAdminSession } from '../../shared/admin-auth';

export default function LogoutPage() {
  const logout = resource(({ signal }) => logoutAdminSession({ signal }), []);

  const isSigningOut = logout.pending;
  const signOutFailed = Boolean(logout.error);

  return (
    <Section size="4">
      <Container size="sm">
        <EmptyState
          icon={<LogOutIcon size={24} aria-hidden="true" />}
          title={
            signOutFailed
              ? 'Sign out failed'
              : isSigningOut
                ? 'Signing you out...'
                : 'Signed out'
          }
          description={
            signOutFailed
              ? 'The auth cookie could not be cleared right now.'
              : isSigningOut
                ? 'Clearing the auth cookie now.'
                : 'You can return to login whenever you want to start a new session.'
          }
          actions={
            signOutFailed ? (
              <Stack gap="3">
                <Button onPress={() => logout.refresh()}>Try again</Button>
                <Button variant="secondary" asChild>
                  <Link href="/auth">Go to login</Link>
                </Button>
              </Stack>
            ) : isSigningOut ? null : (
              <Button asChild>
                <Link href="/auth">Go to login</Link>
              </Button>
            )
          }
        />
      </Container>
    </Section>
  );
}
