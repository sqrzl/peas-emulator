import { Button, ButtonGroup } from "@askrjs/themes/controls";
import { Inline } from "@askrjs/themes/layouts";

export default function CursorPagination({
  hasNext,
  hasPrevious,
  onNext,
  onPrevious,
  pageCount,
  page,
  pageSize,
  totalItems,
}: {
  hasNext: boolean;
  hasPrevious: boolean;
  onNext: () => void;
  onPrevious: () => void;
  pageCount: number;
  page: number;
  pageSize: number;
  totalItems: number;
}) {
  const start = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);

  return (
    <Inline justify="between" align="center" gap="2" wrap="wrap">
      <div>
        <p>Page {page} of {pageCount}</p>
        <p>
          {totalItems === 0
            ? "No items"
            : `Showing ${start}-${end} of ${totalItems}`}
        </p>
      </div>
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
    </Inline>
  );
}
