import { Show } from '@askrjs/askr/control';
import { Button } from '@askrjs/themes/controls';
import { EmptyState, Spinner } from '@askrjs/themes/feedback';
import { Inline, Stack } from '@askrjs/themes/layouts';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import CursorPagination from './cursor-pagination';
import StorageSearchForm from './storage-search-form';

export default function DataTableCard({
  title,
  searchInputId,
  searchLabel,
  onSearch,
  loading,
  errored,
  empty,
  emptyTitle,
  emptyDescription,
  errorTitle,
  errorDescription,
  onRetry,
  hasNext,
  hasPrevious,
  onNext,
  onPrevious,
  children,
}: {
  title: string;
  searchInputId: string;
  searchLabel: string;
  onSearch: (value: string) => void;
  loading: boolean;
  errored: boolean;
  empty: boolean;
  emptyTitle: string;
  emptyDescription: string;
  errorTitle: string;
  errorDescription: string;
  onRetry: () => void;
  hasNext: boolean;
  hasPrevious: boolean;
  onNext: () => void;
  onPrevious: () => void;
  children?: unknown;
}) {
  return (
    <Card>
      <CardHeader>
        <Stack gap="3">
          <CardTitle>{title}</CardTitle>
          <StorageSearchForm
            inputId={searchInputId}
            label={searchLabel}
            onSearch={onSearch}
          />
        </Stack>
      </CardHeader>
      <CardContent>
        <Show when={errored}>
          <EmptyState
            title={errorTitle}
            description={errorDescription}
            actions={<Button onPress={onRetry}>Retry</Button>}
          />
        </Show>

        <Show when={!errored && loading}>
          <Inline justify="center" align="center">
            <Spinner />
          </Inline>
        </Show>

        <Show when={!errored && !loading && empty}>
          <EmptyState title={emptyTitle} description={emptyDescription} />
        </Show>

        <Show when={!errored && !loading && !empty}>
          <Stack gap="3">
            {children}
            <CursorPagination
              hasNext={hasNext}
              hasPrevious={hasPrevious}
              onNext={onNext}
              onPrevious={onPrevious}
            />
          </Stack>
        </Show>
      </CardContent>
    </Card>
  );
}
