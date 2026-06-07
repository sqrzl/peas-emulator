import { Button, ButtonGroup } from '@askrjs/themes/controls';
import { Flex } from '@askrjs/themes/layouts';

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
    <Flex
      justify={{ initial: 'end' }}
      align={{ initial: 'center' }}
      gap="2"
      wrap={{ initial: 'wrap' }}
    >
      <ButtonGroup>
        <Button
          variant="secondary"
          disabled={!hasPrevious}
          onPress={onPrevious}
        >
          Previous
        </Button>
        <Button variant="secondary" disabled={!hasNext} onPress={onNext}>
          Next
        </Button>
      </ButtonGroup>
    </Flex>
  );
}
