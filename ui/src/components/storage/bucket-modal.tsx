import { state } from '@askrjs/askr';
import { Show } from '@askrjs/askr/control';
import { createMutation } from '@askrjs/askr/data';
import { PlusIcon } from '@askrjs/lucide';
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
import { createBucket } from '../../features/buckets/buckets.query';
import { bucketListKey } from '../../features/storage/keys';
import StorageDialogFooter from './storage-dialog-footer';
import StorageDialogForm from './storage-dialog-form';
import StorageDialogHeader from './storage-dialog-header';

export default function BucketModal() {
  const [isOpen, setOpen] = state(false);
  const [error, setError] = state('');
  const [bucketName, setBucketName] = state('');

  const create = createMutation({
    action: (name: string, { signal }) => createBucket({ name, signal }),
    affects: () => [bucketListKey],
    afterSuccess: 'invalidate',
  });

  async function submit(event: Event) {
    event.preventDefault();
    if (create.pending) {
      return;
    }

    const name = bucketName().trim();

    if (!name) {
      setError('Bucket name is required.');
      return;
    }

    setError('');

    try {
      await create.execute(name);
      setBucketName('');
      setOpen(false);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Bucket could not be created.'
      );
    }
  }

  function onOpenChange(nextOpen: boolean): void {
    if (!nextOpen) {
      setBucketName('');
      setError('');
    }
    setOpen(nextOpen);
  }

  function onNameInput(event: Event) {
    const value =
      event.target instanceof HTMLInputElement ? event.target.value : '';
    setBucketName(value);
  }

  function openDialog(): void {
    setBucketName('');
    setError('');
    setOpen(true);
  }

  return (
    <>
      <Button onPress={openDialog}>
        <PlusIcon aria-hidden="true" /> Add bucket
      </Button>
      <Dialog open={isOpen()} onOpenChange={onOpenChange}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent>
            <Stack gap="4">
              <StorageDialogHeader title="Add bucket">
                <p>Create a bucket in the emulator.</p>
              </StorageDialogHeader>
              <StorageDialogForm onSubmit={(event) => void submit(event)}>
                <Field>
                  <Label for="bucket-name">Bucket name</Label>
                  <Input
                    id="bucket-name"
                    name="bucket-name"
                    disabled={create.pending}
                    onInput={onNameInput}
                  />
                </Field>
                <Show when={error()}>
                  <FieldError role="alert">{error()}</FieldError>
                </Show>
                <StorageDialogFooter>
                  <DialogClose asChild onPress={() => setError('')}>
                    <Button variant="secondary" disabled={create.pending}>
                      Cancel
                    </Button>
                  </DialogClose>
                  <Button type="submit" disabled={create.pending}>
                    {create.pending ? 'Creating...' : 'Create bucket'}
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
