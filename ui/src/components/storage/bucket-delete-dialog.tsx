import { Button, ButtonGroup, FieldError } from "@askrjs/themes/controls";
import { Stack } from "@askrjs/themes/layouts";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogOverlay,
  AlertDialogPortal,
  AlertDialogTitle,
} from "@askrjs/ui";
import { Show } from "@askrjs/askr/control";

export type BucketDeleteTarget = {
  blobCount: number | null;
  bucketName: string;
  deleting: boolean;
  error: string;
  pendingCount: boolean;
};

export default function BucketDeleteDialog({
  onCancel,
  onConfirm,
  target,
}: {
  onCancel: () => void;
  onConfirm: () => void;
  target: BucketDeleteTarget | null;
}) {
  return (
    <AlertDialog
      open={Boolean(target)}
      onOpenChange={(open) => {
        if (!open) {
          onCancel();
        }
      }}
    >
      <AlertDialogPortal>
        <AlertDialogOverlay />
        <AlertDialogContent>
          <Stack gap="4">
            <Stack gap="1">
              <AlertDialogTitle>Delete bucket</AlertDialogTitle>
              <AlertDialogDescription>
                {target?.pendingCount
                  ? "Checking how many blobs are in this bucket."
                  : target
                    ? `You are going to delete ${target.blobCount ?? 0} blobs from ${target.bucketName}.`
                    : "You are going to delete this bucket."}
              </AlertDialogDescription>
              <p>This also removes the bucket itself.</p>
            </Stack>
            <Show when={target?.error}>
              <FieldError role="alert">{target?.error}</FieldError>
            </Show>
            <ButtonGroup>
              <Button
                type="button"
                disabled={target?.pendingCount || target?.deleting}
                onPress={onConfirm}
              >
                {target?.deleting
                  ? "Deleting..."
                  : target
                    ? `Delete bucket and ${target.blobCount ?? 0} blobs`
                    : "Delete bucket"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={target?.deleting}
                onPress={onCancel}
              >
                Cancel
              </Button>
            </ButtonGroup>
          </Stack>
        </AlertDialogContent>
      </AlertDialogPortal>
    </AlertDialog>
  );
}
