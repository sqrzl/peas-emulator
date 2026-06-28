import { ArrowLeftIcon, ArrowRightIcon } from '@askrjs/lucide';
import { Button, ButtonGroup, Inline } from '@askrjs/themes/components';

export default function CursorPagination({
  hasNext,
  hasPrevious,
  onNext,
  onPrevious,
}: {
  hasNext: boolean;
  hasPrevious: boolean;
  onNext: () => void;
  onPrevious: () => void;
}) {
  return (
    <Inline justify="end" align="center" gap="2" wrap>
      <ButtonGroup>
        <Button
          variant="secondary"
          disabled={!hasPrevious}
          onPress={onPrevious}
        >
          <ArrowLeftIcon aria-hidden="true" />
          Previous
        </Button>
        <Button variant="secondary" disabled={!hasNext} onPress={onNext}>
          Next
          <ArrowRightIcon aria-hidden="true" />
        </Button>
      </ButtonGroup>
    </Inline>
  );
}
