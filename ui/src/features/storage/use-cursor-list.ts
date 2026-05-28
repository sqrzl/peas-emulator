import { state } from '@askrjs/askr';
import { createQuery } from '@askrjs/askr/data';

export type CursorPage<T> = {
  items: T[];
  next: string | null;
};

export type CursorListController<T> = {
  items: () => T[];
  pending: () => boolean;
  error: () => Error | null;
  refresh: () => void;
  search: () => string;
  setSearch: (value: string) => void;
  hasNext: () => boolean;
  hasPrevious: () => boolean;
  next: () => void;
  previous: () => void;
};

export function useCursorList<T>(
  keyPrefix: string,
  fetchPage: (opts: {
    next?: string;
    search?: string;
    signal: AbortSignal;
  }) => Promise<CursorPage<T>>
): CursorListController<T> {
  const [search, setSearchValue] = state('');
  const [cursor, setCursor] = state<string | undefined>(undefined);
  const [history, setHistory] = state<Array<string | undefined>>([]);

  const query = createQuery<CursorPage<T>>({
    key: `${keyPrefix}:search=${search()}:cursor=${cursor() ?? ''}`,
    fetch: ({ signal }) =>
      fetchPage({
        next: cursor(),
        search: search() || undefined,
        signal,
      }),
  });

  function setSearch(value: string) {
    if (value === search()) {
      return;
    }
    setSearchValue(value);
    setCursor(undefined);
    setHistory([]);
  }

  function next() {
    const token = query.data?.next;
    if (!token) {
      return;
    }
    setHistory((stack) => [...stack, cursor()]);
    setCursor(token);
  }

  function previous() {
    const stack = history();
    if (stack.length === 0) {
      return;
    }
    const previousCursor = stack[stack.length - 1];
    setHistory(stack.slice(0, -1));
    setCursor(previousCursor);
  }

  return {
    items: () => query.data?.items ?? [],
    pending: () => query.loading,
    error: () => (query.error as Error | null) ?? null,
    refresh: () => void query.refresh(),
    search,
    setSearch,
    hasNext: () => Boolean(query.data?.next),
    hasPrevious: () => history().length > 0,
    next,
    previous,
  };
}
