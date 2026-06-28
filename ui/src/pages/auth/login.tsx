import { state } from '@askrjs/askr';
import { navigate } from '@askrjs/askr/router';
import { Input } from '@askrjs/ui';
import {
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Container,
  Field,
  Section,
  Stack,
} from '@askrjs/themes/components';
import {
  isDevAuthBypassed,
  loginAdminSession,
} from '../../features/auth/admin-session';
import { adminBucketsPath } from '../../shared/routes';

function returnPath(): string {
  if (typeof window === 'undefined') {
    return adminBucketsPath();
  }

  const candidate = new URLSearchParams(window.location.search).get('next');
  return candidate?.startsWith('/') && !candidate.startsWith('//')
    ? candidate
    : adminBucketsPath();
}

export default function LoginPage() {
  const [error, setError] = state('');
  const [pending, setPending] = state(false);
  const devAuthBypassed = isDevAuthBypassed();
  let usernameInput: HTMLInputElement | null = null;
  let passwordInput: HTMLInputElement | null = null;

  if (devAuthBypassed) {
    return (
      <Section size="4">
        <Container size="sm">
          <Card variant="raised">
            <CardHeader>
              <CardTitle>Local development mode</CardTitle>
            </CardHeader>
            <CardContent>
              <Stack gap="4">
                <p>Admin sign-in is bypassed while running the local dev UI.</p>
                <Button onPress={() => navigate(returnPath())}>
                  Open buckets
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Container>
      </Section>
    );
  }

  async function handleSubmit(event: Event) {
    if (pending()) {
      return;
    }

    if (!(event.target instanceof Element)) {
      return;
    }

    const credentials = {
      username: usernameInput?.value.trim() ?? '',
      password: passwordInput?.value ?? '',
    };

    setPending(true);
    setError('');

    try {
      await loginAdminSession(credentials);
      navigate(returnPath());
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin server is unavailable right now.'
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <Section size="4">
      <Container size="sm">
        <Card variant="raised">
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={(event: Event) => {
                event.preventDefault();
                void handleSubmit(event);
              }}
            >
              <Stack gap="4">
                <Field>
                  <label htmlFor="username">Username</label>
                  <Input
                    id="username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    disabled={pending()}
                    placeholder="username"
                    ref={(node: HTMLInputElement | null) => {
                      usernameInput = node;
                    }}
                  />
                </Field>
                <Field>
                  <label htmlFor="password">Password</label>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    disabled={pending()}
                    placeholder="password"
                    ref={(node: HTMLInputElement | null) => {
                      passwordInput = node;
                    }}
                  />
                </Field>
                {error() ? <p role="alert">{error()}</p> : null}
                <Button type="submit" disabled={pending()}>
                  {pending() ? 'Signing in...' : 'Sign in'}
                </Button>
              </Stack>
            </form>
          </CardContent>
        </Card>
      </Container>
    </Section>
  );
}
