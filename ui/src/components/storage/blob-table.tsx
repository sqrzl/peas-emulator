import { state } from "@askrjs/askr";
import { For, Show } from "@askrjs/askr/control";
import { resource } from "@askrjs/askr/resources";
import { Link } from "@askrjs/askr/router";
import { Button } from "@askrjs/themes/controls";
import { EmptyState } from "@askrjs/themes/feedback";
import { Stack } from "@askrjs/themes/layouts";
import { Card, CardContent, CardHeader, CardTitle } from "@askrjs/themes/surfaces";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
} from "@askrjs/ui";
import BlobDeleteDialog, { type BlobDeleteTarget } from "./blob-delete-dialog";
import CursorPagination from "./cursor-pagination";
import StorageSearchForm from "./storage-search-form";
import { deleteBlob, loadAllBlobPages, type BlobInfo } from "../../features/blobs/blobs.query";
import { formatBytes, formatRelativeTime } from "../../shared/format";
import { blobPath } from "../../shared/routes";

type BlobSortField = "content_type" | "key" | "last_modified" | "size";
type SortDirection = "asc" | "desc";
const pageSize = 50;

const blobKeyCollator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

function sortBlobs(
  items: BlobInfo[],
  field: BlobSortField,
  direction: SortDirection
) {
  const sorted = [...items].sort((left, right) => {
    switch (field) {
      case "content_type":
        return blobKeyCollator.compare(
          left.content_type ?? "",
          right.content_type ?? ""
        );
      case "key":
        return blobKeyCollator.compare(left.key, right.key);
      case "size":
        return left.size - right.size;
      default:
        return left.last_modified.localeCompare(right.last_modified);
    }
  });

  if (direction === "desc") {
    sorted.reverse();
  }

  return sorted;
}

function blobSortLabel(field: BlobSortField, direction: SortDirection): string {
  if (field === "size") {
    return `Size (${direction === "asc" ? "smallest first" : "largest first"})`;
  }

  if (field === "last_modified") {
    return `Last modified (${direction === "asc" ? "oldest first" : "newest first"})`;
  }

  return `${field === "content_type" ? "Content type" : "Blob"} (${direction === "asc" ? "A-Z" : "Z-A"})`;
}

function formatBlobSize(size: number): string {
  return `${formatBytes(size)} (${size.toLocaleString()} bytes)`;
}

function BlobRows({
  bucketName,
  blobs,
  onSort,
  onDelete,
  sortDirection,
  sortField,
}: {
  blobs: BlobInfo[];
  bucketName: string;
  onDelete: (blobKey: string) => void;
  onSort: (field: BlobSortField) => void;
  sortDirection: SortDirection;
  sortField: BlobSortField;
}) {
  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableHeaderCell>
            <Button variant="secondary" onPress={() => onSort("key")}>
              {sortField === "key"
                ? blobSortLabel("key", sortDirection)
                : "Blob"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>
            <Button variant="secondary" onPress={() => onSort("content_type")}>
              {sortField === "content_type"
                ? blobSortLabel("content_type", sortDirection)
                : "Content type"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>
            <Button variant="secondary" onPress={() => onSort("size")}>
              {sortField === "size"
                ? blobSortLabel("size", sortDirection)
                : "Size"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>
            <Button
              variant="secondary"
              onPress={() => onSort("last_modified")}
            >
              {sortField === "last_modified"
                ? blobSortLabel("last_modified", sortDirection)
                : "Last modified"}
            </Button>
          </TableHeaderCell>
          <TableHeaderCell>Actions</TableHeaderCell>
        </TableRow>
      </TableHead>
      <TableBody>
        <For each={blobs} by={(blob) => blob.key}>
          {(blob) => (
            <TableRow key={blob.key}>
              <TableCell>
                <Link href={blobPath(bucketName, blob.key)}>{blob.key}</Link>
              </TableCell>
              <TableCell>
                {blob.content_type ?? "application/octet-stream"}
              </TableCell>
              <TableCell>{formatBlobSize(blob.size)}</TableCell>
              <TableCell>{formatRelativeTime(blob.last_modified)}</TableCell>
              <TableCell>
                <Button
                  variant="secondary"
                  onPress={() => {
                    onDelete(blob.key);
                  }}
                >
                  Delete
                </Button>
              </TableCell>
            </TableRow>
          )}
        </For>
      </TableBody>
    </Table>
  );
}

export default function BlobTable({
  bucketName,
  reloadKey,
  key: _key,
}: {
  bucketName: string;
  reloadKey: number;
  key?: string;
}) {
  const [activeSearch, setActiveSearch] = state("");
  const [pageIndex, setPageIndex] = state(0);
  const [sortField, setSortField] = state<BlobSortField>("last_modified");
  const [sortDirection, setSortDirection] = state<SortDirection>("desc");
  const [deleteTarget, setDeleteTarget] = state<BlobDeleteTarget | null>(null);

  const blobs = resource(
    ({ signal }) => 
      loadAllBlobPages({
        bucketName,
        search: activeSearch() || undefined,
        signal,
      }),
    [activeSearch(), bucketName, reloadKey]
  );

  function applySearch(event: Event) {
    event.preventDefault();
    const target = event.target instanceof Element ? event.target : null;
    const form = target?.closest("form");
    const searchField = form?.querySelector("#blob-search");
    const nextSearch =
      searchField instanceof HTMLInputElement
        ? searchField.value.trim()
        : "";

    setActiveSearch(nextSearch);
    setPageIndex(0);
  }

  function clearSearch() {
    setActiveSearch("");
    setPageIndex(0);
  }

  function cycleSort(field: BlobSortField) {
    setPageIndex(0);

    if (sortField() === field) {
      setSortDirection((value) => (value === "asc" ? "desc" : "asc"));
      return;
    }

    setSortField(field);
    setSortDirection(field === "size" || field === "last_modified" ? "desc" : "asc");
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

  async function confirmDeleteBlob() {
    const target = deleteTarget();
    if (!target || target.deleting) {
      return;
    }

    setDeleteTarget({ ...target, deleting: true, error: "" });

    try {
      await deleteBlob({ bucketName, objectKey: target.blobKey });
      setDeleteTarget(null);

      await blobs.refresh();
      clampPageIndex(blobs.value?.length ?? 0);
    } catch (caughtError) {
      setDeleteTarget((value) =>
        value
          ? {
              ...value,
              deleting: false,
              error:
                caughtError instanceof Error
                  ? caughtError.message
                  : "Blob could not be deleted.",
            }
          : value
      );
    }
  }

  if (blobs.error && !blobs.value) {
    return (
      <EmptyState
        title="Blobs could not load"
        description="Retry the admin API call to see the blob list."
        actions={<Button onPress={() => blobs.refresh()}>Retry</Button>}
      />
    );
  }

  const items = sortBlobs(
    blobs.value ?? [],
    sortField(),
    sortDirection()
  );
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPageIndex = Math.min(pageIndex(), pageCount - 1);
  const startIndex = currentPageIndex * pageSize;
  const visibleBlobs = items.slice(startIndex, startIndex + pageSize);
  const hasBlobs = visibleBlobs.length > 0;
  const hasSearch = activeSearch().length > 0;

  return (
    <>
      <Card>
        <CardHeader>
          <Stack gap="3">
            <CardTitle>Blobs</CardTitle>
            <StorageSearchForm
              inputId="blob-search"
              label="Search blobs"
              onClear={clearSearch}
              onSubmit={applySearch}
            />
          </Stack>
        </CardHeader>
        <CardContent>
          <Show when={blobs.pending && !blobs.value}>
            <p>Loading blobs...</p>
          </Show>

          <Show when={!hasBlobs && !blobs.pending}>
            <EmptyState
              title={hasSearch ? "No blobs match this search" : "No blobs in this bucket"}
              description={
                hasSearch
                  ? "Try a different blob key or clear the current search."
                  : "Upload a file to create the first blob."
              }
            />
          </Show>

          <Show when={hasBlobs}>
            <Stack gap="3">
              <BlobRows
                blobs={visibleBlobs}
                bucketName={bucketName}
                onSort={cycleSort}
                onDelete={(blobKey) =>
                  setDeleteTarget({
                    deleting: false,
                    error: "",
                    blobKey,
                  })
                }
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

      <BlobDeleteDialog
        bucketName={bucketName}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          void confirmDeleteBlob();
        }}
        target={deleteTarget()}
      />
    </>
  );
}
