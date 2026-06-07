import { Show } from '@askrjs/askr/control';
import { Button, FieldError } from '@askrjs/themes/controls';
import { Stack } from '@askrjs/themes/layouts';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogOverlay,
  AlertDialogPortal,
} from '@askrjs/ui';
import type { DeleteTarget } from '../../features/storage/use-delete-target';
import StorageDialogFooter from './storage-dialog-footer';
import StorageDialogHeader from './storage-dialog-header';

export type BlobDeleteTarget = DeleteTarget<{ blobKey: string }>;

export default function BlobDeleteDialog({
  bucketName,
  onCancel,
  onConfirm,
  target,
}: {
  bucketName: string;
  onCancel: () => void;
  onConfirm: () => void;
  target: BlobDeleteTarget | null;
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
            <StorageDialogHeader title="Delete blob">
              <p>
                {target
                  ? `Delete ${target.blobKey} from ${bucketName}.`
                  : 'Delete this blob.'}
              </p>
            </StorageDialogHeader>
            <Show when={target?.error}>
              <FieldError role="alert">{target?.error}</FieldError>
            </Show>
            <StorageDialogFooter>
              <Button
                type="button"
                variant="secondary"
                disabled={target?.deleting}
                onPress={onCancel}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                disabled={target?.deleting}
                onPress={onConfirm}
              >
                {target?.deleting ? 'Deleting...' : 'Delete blob'}
              </Button>
            </StorageDialogFooter>
          </Stack>
        </AlertDialogContent>
      </AlertDialogPortal>
    </AlertDialog>
  );
}
