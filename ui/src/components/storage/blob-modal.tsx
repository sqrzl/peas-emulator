import { state } from '@askrjs/askr';
import { Show } from '@askrjs/askr/control';
import { createMutation } from '@askrjs/askr/data';
import { UploadIcon } from '@askrjs/lucide';
import { Button, Field, FieldError } from '@askrjs/themes/controls';
import { Stack } from '@askrjs/themes/layouts';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogOverlay,
  DialogPortal,
  Input,
  Label,
} from '@askrjs/ui';
import { putObjectContent as putBlobContent } from '../../features/objects/objects.query';
import { blobListKey } from '../../features/storage/keys';
import {
  normalizeStoragePathPrefix,
  resolveUploadObjectKey,
} from '../../features/storage/path';
import StorageDialogFooter from './storage-dialog-footer';
import StorageDialogForm from './storage-dialog-form';
import StorageDialogHeader from './storage-dialog-header';

export default function BlobModal({
  bucketName,
  pathPrefix = '',
}: {
  bucketName: string;
  pathPrefix?: string;
}) {
  const [isOpen, setOpen] = state(false);
  const [error, setError] = state('');
  const [blobKey, setBlobKey] = state('');
  const currentBlobKey = blobKey();
  const normalizedPrefix = normalizeStoragePathPrefix(pathPrefix);
  const uploadDescription = normalizedPrefix
    ? `Without a key, the file name is placed in ${normalizedPrefix}.`
    : 'Without a key, the file name is placed in the bucket root.';

  const upload = createMutation({
    action: (
      input: { objectKey: string; content: File; contentType?: string },
      { signal }
    ) => putBlobContent({ bucketName, ...input, signal }),
    affects: () => [blobListKey(bucketName)],
    afterSuccess: 'invalidate',
  });

  async function submit(event: Event) {
    event.preventDefault();
    if (upload.pending) {
      return;
    }

    const form =
      event.target instanceof Element ? event.target.closest('form') : null;
    const fileInput = form?.querySelector('#blob-file');
    const selectedFile =
      fileInput instanceof HTMLInputElement
        ? (fileInput.files?.[0] ?? null)
        : null;

    if (!selectedFile) {
      setError('Choose a file to upload.');
      return;
    }

    const typedKey = currentBlobKey.trim();
    const objectKey = resolveUploadObjectKey({
      fileName: selectedFile.name,
      pathPrefix: normalizedPrefix,
      typedKey,
    });

    setError('');

    try {
      await upload.execute({
        objectKey,
        content: selectedFile,
        contentType: selectedFile.type || undefined,
      });
      form?.reset();
      setBlobKey('');
      setOpen(false);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Blob could not be uploaded.'
      );
    }
  }

  function onOpenChange(nextOpen: boolean): void {
    if (!nextOpen) {
      setBlobKey('');
      setError('');
    }
    setOpen(nextOpen);
  }

  function onKeyInput(event: Event) {
    const value =
      event.target instanceof HTMLInputElement ? event.target.value : '';
    setBlobKey(value);
  }

  function openDialog(): void {
    setBlobKey('');
    setError('');
    setOpen(true);
  }

  return (
    <>
      <Button onPress={openDialog}>
        <UploadIcon aria-hidden="true" /> Add blob
      </Button>
      <Dialog open={isOpen()} onOpenChange={onOpenChange}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent>
            <Stack gap="4">
              <StorageDialogHeader title="Add blob">
                <p>{uploadDescription}</p>
              </StorageDialogHeader>
              <StorageDialogForm onSubmit={(event) => void submit(event)}>
                <Field>
                  <Label for="blob-key">Blob key</Label>
                  <Input
                    id="blob-key"
                    name="blob-key"
                    disabled={upload.pending}
                    onInput={onKeyInput}
                  />
                </Field>
                <Field>
                  <Label for="blob-file">File</Label>
                  <Input
                    id="blob-file"
                    name="blob-file"
                    type="file"
                    disabled={upload.pending}
                  />
                </Field>
                <Show when={error()}>
                  <FieldError role="alert">{error()}</FieldError>
                </Show>
                <StorageDialogFooter>
                  <DialogClose asChild onPress={() => setError('')}>
                    <Button variant="secondary" disabled={upload.pending}>
                      Cancel
                    </Button>
                  </DialogClose>
                  <Button type="submit" disabled={upload.pending}>
                    {upload.pending ? 'Uploading...' : 'Upload blob'}
                  </Button>
                </StorageDialogFooter>
              </StorageDialogForm>
            </Stack>
          </DialogContent>
        </DialogPortal>
      </Dialog>
    </>
  );
}
