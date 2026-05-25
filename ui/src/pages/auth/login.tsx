import { state } from '@askrjs/askr';
import { navigate } from '@askrjs/askr/router';
import { LockKeyholeIcon } from '@askrjs/lucide';
import { Input } from '@askrjs/ui';
import { Button, Field, FieldHint } from '@askrjs/themes/controls';
import { Container, Section, Stack } from '@askrjs/themes/layouts';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import { loginAdminSession } from '../../features/auth/admin-session';

function returnPath(): string {
  if (typeof window === 'undefined') {
    return '/app';
  }

  const candidate = new URLSearchParams(window.location.search).get('next');
  return candidate?.startsWith('/') && !candidate.startsWith('//')
    ? candidate
    : '/app';
}

export default function LoginPage() {
  const [username, setUsername] = state('admin');
  const [password, setPassword] = state('admin');
  const [error, setError] = state('');
  const [pending, setPending] = state(false);

  async function handleSubmit() {
    if (pending()) {
      return;
    }

    const credentials = {
      username: username().trim(),
      password: password(),
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
            <span class="card-icon">
              <LockKeyholeIcon size={18} aria-hidden="true" />
            </span>
            <CardTitle>Login</CardTitle>
            <CardDescription>
              Use the admin credentials from docker compose to enter the
              console.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={(event: Event) => {
                event.preventDefault();
                void handleSubmit();
              }}
            >
              <Stack gap="4">
                <Field>
                  <label for="username">Username</label>
                  <Input
                    id="username"
                    type="text"
                    value={username()}
                    onInput={(event: Event) =>
                      setUsername(
                        (event.currentTarget as HTMLInputElement).value
                      )
                    }
                    autoComplete="username"
                    disabled={pending()}
                  />
                </Field>
                <Field>
                  <label for="password">Password</label>
                  <Input
                    id="password"
                    type="password"
                    value={password()}
                    onInput={(event: Event) =>
                      setPassword(
                        (event.currentTarget as HTMLInputElement).value
                      )
                    }
                    autoComplete="current-password"
                    disabled={pending()}
                  />
                  <FieldHint>
                    Demo credentials are prefilled as admin / admin.
                  </FieldHint>
                </Field>
                {error() ? (
                  <p role="alert" class="form-error">
                    {error()}
                  </p>
                ) : null}
                <Button
                  type="submit"
                  onPress={() => void handleSubmit()}
                  disabled={pending()}
                >
                  {pending()
                    ? 'Checking credentials...'
                    : 'Continue to console'}
                </Button>
              </Stack>
            </form>
          </CardContent>
        </Card>
      </Container>
    </Section>
  );
}
