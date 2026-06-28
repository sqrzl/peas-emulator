import { resource } from '@askrjs/askr/resources';
import { Link } from '@askrjs/askr/router';
import { LogOutIcon } from '@askrjs/lucide';
import {
  Button,
  Container,
  EmptyState,
  Section,
  Stack,
} from '@askrjs/themes/components';
import {
  isDevAuthBypassed,
  logoutAdminSession,
} from '../../features/auth/admin-session';
import { adminBucketsPath, loginPath } from '../../shared/routes';

export default function LogoutPage() {
  if (isDevAuthBypassed()) {
    return (
      <Section size="4">
        <Container size="sm">
          <EmptyState
            icon={<LogOutIcon size={24} aria-hidden="true" />}
            title="Local development mode"
            description="Sign out is disabled while admin auth bypass is active."
            actions={
              <Button asChild>
                <Link href={adminBucketsPath()}>Return to buckets</Link>
              </Button>
            }
          />
        </Container>
      </Section>
    );
  }

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
                : 'Return to login to start a new session.'
          }
          actions={
            signOutFailed ? (
              <Stack gap="3">
                <Button onPress={() => logout.refresh()}>Try again</Button>
                <Button variant="secondary" asChild>
                  <Link href={loginPath()}>Go to login</Link>
                </Button>
              </Stack>
            ) : isSigningOut ? null : (
              <Button asChild>
                <Link href={loginPath()}>Go to login</Link>
              </Button>
            )
          }
        />
      </Container>
    </Section>
  );
}
