import { state } from '@askrjs/askr';
import { Input } from '@askrjs/ui';
import {
  Button,
  Field,
  FieldHint,
  InputGroup,
  InputGroupText,
} from '@askrjs/themes/controls';
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import { Block, Stack } from '@askrjs/themes/layouts';

export default function SettingsPage() {
  const [endpoint, setEndpoint] = state(
    'https://api.example.test'
  ) as unknown as [
    ReturnType<typeof state<string>>,
    ReturnType<typeof state<string>>['set'],
  ];

  return (
    <Stack gap="5">
      <section class="page-heading">
        <Stack gap="2">
          <Badge>environment</Badge>
          <h1>Settings</h1>
          <p class="lead">
            Configuration stays in shared boundaries and adapters receive it
            through one clear path.
          </p>
        </Stack>
      </section>

      <Block size="lg" gap="4" align="start" class="settings-grid">
        <Card>
          <CardHeader>
            <CardTitle>API adapter</CardTitle>
            <CardDescription>
              Keep generated clients and transport concerns out of route
              components.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Field>
              <label for="api-endpoint">Base URL</label>
              <InputGroup>
                <InputGroupText>URL</InputGroupText>
                <Input
                  id="api-endpoint"
                  value={endpoint()}
                  onInput={(event: Event) =>
                    setEndpoint((event.currentTarget as HTMLInputElement).value)
                  }
                />
              </InputGroup>
              <FieldHint>
                Demo-only value. Real apps should validate public config at
                startup.
              </FieldHint>
            </Field>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Consistency policy</CardTitle>
            <CardDescription>
              Event-sourced apps should expose lag, retries, and stale states
              directly.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="3">
              <Badge>pending-write copy enabled</Badge>
              <Badge>projection lag visible</Badge>
              <Badge>manual refresh available</Badge>
              <Button variant="secondary">Save settings</Button>
            </Stack>
          </CardContent>
        </Card>
      </Block>
    </Stack>
  );
}
