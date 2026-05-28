import { state } from "@askrjs/askr";
import { For, Show } from "@askrjs/askr/control";
import { resource } from "@askrjs/askr/resources";
import { Link } from "@askrjs/askr/router";
import { Button } from "@askrjs/themes/controls";
import { EmptyState } from "@askrjs/themes/feedback";
import { Stack } from "@askrjs/themes/layouts";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@askrjs/themes/surfaces";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
} from "@askrjs/ui";
import BucketDeleteDialog, {
  type BucketDeleteTarget,
} from "./bucket-delete-dialog";
import CursorPagination from "./cursor-pagination";
import StorageSearchForm from "./storage-search-form";
import { loadAllBucketPages } from "../../features/buckets/buckets.query";
import { deleteBucketWithContents } from "../../features/buckets/buckets.query";
import { countBucketObjects } from "../../features/objects/objects.query";
import { formatRelativeTime } from "../../shared/format";
import { bucketPath } from "../../shared/routes";
import { DeleteIcon } from "@askrjs/lucide";

type BucketSortField = "createdAt" | "name";
type SortDirection = "asc" | "desc";
const pageSize = 50;

const bucketNameCollator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

function sortBuckets(
  items: Array<{ name: string; createdAt: string; versioningEnabled: boolean }>,
  field: BucketSortField,
  direction: SortDirection,
) {
  const sorted = [...items].sort((left, right) => {
    if (field === "name") {
      return bucketNameCollator.compare(left.name, right.name);
    }

    return left.createdAt.localeCompare(right.createdAt);
  });

  if (direction === "desc") {
    sorted.reverse();
  }

  return sorted;
}

function bucketSortLabel(
  field: BucketSortField,
  direction: SortDirection,
): string {
  if (field === "name") {
    return `Bucket (${direction === "asc" ? "A-Z" : "Z-A"})`;
  }

  return `Created (${direction === "asc" ? "oldest first" : "newest first"})`;
}

function BucketRows({
  buckets,
  onSort,
  onDelete,
  sortDirection,
  sortField,
}: {
  buckets: Array<{ createdAt: string; name: string }>;
  onDelete: (bucketName: string) => void;
  onSort: (field: BucketSortField) => void;
  sortDirection: SortDirection;
  sortField: BucketSortField;
}) {
  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableHeaderCell>
            <Button variant="secondary" onPress={() => onSort("name")}>
              {sortField === "name"
                ? bucketSortLabel("name", sortDirection)
                : "Bucket"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>
            <Button variant="secondary" onPress={() => onSort("createdAt")}>
              {sortField === "createdAt"
                ? bucketSortLabel("createdAt", sortDirection)
                : "Created"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>Actions</TableHeaderCell>
        </TableRow>
      </TableHead>
      <TableBody>
        <For each={buckets} by={(bucket) => bucket.name}>
          {(bucket) => (
            <TableRow key={bucket.name}>
              <TableCell>
                <Link href={bucketPath(bucket.name)}>{bucket.name}</Link>
              </TableCell>
              <TableCell>{formatRelativeTime(bucket.createdAt)}</TableCell>
              <TableCell>
                <Button
                  variant="secondary"
                  onPress={() => {
                    onDelete(bucket.name);
                  }}
                >
                  <DeleteIcon />
                </Button>
              </TableCell>
            </TableRow>
          )}
        </For>
      </TableBody>
    </Table>
  );
}

export default function BucketTable({
  reloadKey,
  key: _key,
}: {
  reloadKey: number;
  key?: string;
}) {
  const [activeSearch, setActiveSearch] = state("");
  const [pageIndex, setPageIndex] = state(0);
  const [sortField, setSortField] = state<BucketSortField>("createdAt");
  const [sortDirection, setSortDirection] = state<SortDirection>("desc");
  const [deleteTarget, setDeleteTarget] = state<BucketDeleteTarget | null>(
    null,
  );

  const buckets = resource(
    ({ signal }) =>
      loadAllBucketPages({
        search: activeSearch() || undefined,
        signal,
      }),
    [activeSearch(), reloadKey],
  );

  function applySearch(event: Event) {
    event.preventDefault();
    const target = event.target instanceof Element ? event.target : null;
    const form = target?.closest("form");
    const searchField = form?.querySelector("#bucket-search");
    const nextSearch =
      searchField instanceof HTMLInputElement ? searchField.value.trim() : "";

    setActiveSearch(nextSearch);
    setPageIndex(0);
  }

  function clearSearch() {
    setActiveSearch("");
    setPageIndex(0);
  }

  function cycleSort(field: BucketSortField) {
    setPageIndex(0);

    if (sortField() === field) {
      setSortDirection((value) => (value === "asc" ? "desc" : "asc"));
      return;
    }

    setSortField(field);
    setSortDirection(field === "createdAt" ? "desc" : "asc");
  }

  function showPreviousPage() {
    if (pageIndex() > 0) {
      setPageIndex((value) => value - 1);
    }
  }

  function showNextPage(pageCount: number) {
    if (pageIndex() < pageCount - 1) {
      setPageIndex((value) => value + 1);
    }
  }

  function clampPageIndex(totalItems: number) {
    const maxPageIndex = Math.max(Math.ceil(totalItems / pageSize) - 1, 0);
    setPageIndex((value) => Math.min(value, maxPageIndex));
  }

  async function openDeleteDialog(bucketName: string) {
    setDeleteTarget({
      bucketName,
      blobCount: null,
      deleting: false,
      error: "",
      pendingCount: true,
    });

    try {
      const blobCount = await countBucketObjects({
        bucketName,
        signal: new AbortController().signal,
      });
      setDeleteTarget((value) =>
        value?.bucketName === bucketName
          ? { ...value, blobCount, pendingCount: false }
          : value,
      );
    } catch (caughtError) {
      setDeleteTarget((value) =>
        value?.bucketName === bucketName
          ? {
              ...value,
              error:
                caughtError instanceof Error
                  ? caughtError.message
                  : "Blob count could not be loaded.",
              pendingCount: false,
            }
          : value,
      );
    }
  }

  async function confirmDeleteBucket() {
    const target = deleteTarget();
    if (!target || target.deleting || target.pendingCount) {
      return;
    }

    setDeleteTarget({ ...target, deleting: true, error: "" });

    try {
      await deleteBucketWithContents({ bucketName: target.bucketName });
      setDeleteTarget(null);

      await buckets.refresh();
      clampPageIndex(buckets.value?.length ?? 0);
    } catch (caughtError) {
      setDeleteTarget((value) =>
        value
          ? {
              ...value,
              deleting: false,
              error:
                caughtError instanceof Error
                  ? caughtError.message
                  : "Bucket could not be deleted.",
            }
          : value,
      );
    }
  }

  if (buckets.error && !buckets.value) {
    return (
      <EmptyState
        title="Buckets could not load"
        description="Retry the admin API call to see the bucket list."
        actions={<Button onPress={() => buckets.refresh()}>Retry</Button>}
      />
    );
  }

  const items = sortBuckets(buckets.value ?? [], sortField(), sortDirection());
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPageIndex = Math.min(pageIndex(), pageCount - 1);
  const startIndex = currentPageIndex * pageSize;
  const visibleBuckets = items.slice(startIndex, startIndex + pageSize);
  const hasBuckets = visibleBuckets.length > 0;
  const hasSearch = activeSearch().length > 0;

  return (
    <>
      <Card>
        <CardHeader>
          <Stack gap="3">
            <CardTitle>Buckets</CardTitle>
            <StorageSearchForm
              inputId="bucket-search"
              label="Search buckets"
              onClear={clearSearch}
              onSubmit={applySearch}
            />
          </Stack>
        </CardHeader>
        <CardContent>
          <Show when={buckets.pending && !buckets.value}>
            <p>Loading buckets...</p>
          </Show>

          <Show when={!hasBuckets && !buckets.pending}>
            <EmptyState
              title={
                hasSearch ? "No buckets match this search" : "No buckets yet"
              }
              description={
                hasSearch
                  ? "Try a different name or clear the current search."
                  : "Create a bucket to start using the emulator."
              }
            />
          </Show>

          <Show when={hasBuckets}>
            <Stack gap="3">
              <BucketRows
                buckets={visibleBuckets}
                onSort={cycleSort}
                onDelete={(bucketName) => {
                  void openDeleteDialog(bucketName);
                }}
                sortDirection={sortDirection()}
                sortField={sortField()}
              />
              <CursorPagination
                hasNext={currentPageIndex < pageCount - 1}
                hasPrevious={currentPageIndex > 0}
                onNext={() => showNextPage(pageCount)}
                onPrevious={showPreviousPage}
                page={currentPageIndex + 1}
                pageCount={pageCount}
                pageSize={pageSize}
                totalItems={items.length}
              />
            </Stack>
          </Show>
        </CardContent>
      </Card>

      <BucketDeleteDialog
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          void confirmDeleteBucket();
        }}
        target={deleteTarget()}
      />
    </>
  );
}
