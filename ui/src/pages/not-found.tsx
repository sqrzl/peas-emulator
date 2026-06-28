import { Link } from '@askrjs/askr/router';
import {
  Button,
  Container,
  EmptyState,
  Section,
} from '@askrjs/themes/components';

export default function NotFoundPage() {
  return (
    <Section size="4">
      <Container size="sm">
        <EmptyState
          title="Page not found"
          description="The route tree is explicit, so unknown paths fall back here."
          actions={
            <Button asChild>
              <Link href="/">Return home</Link>
            </Button>
          }
        />
      </Container>
    </Section>
  );
}
