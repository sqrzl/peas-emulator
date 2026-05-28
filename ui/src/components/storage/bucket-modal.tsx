import { state } from "@askrjs/askr";
import { Show } from "@askrjs/askr/control";
import { Button, ButtonGroup, Field, FieldError } from "@askrjs/themes/controls";
import { Stack } from "@askrjs/themes/layouts";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  Input,
  Label,
} from "@askrjs/ui";
import { createBucket } from "../../features/buckets/buckets.query";

export default function BucketModal({
  onCreated,
}: {
  onCreated?: () => void;
}) {
  const [isOpen, setOpen] = state(false);
  const [error, setError] = state("");
  const [pending, setPending] = state(false);

  async function handleSubmit(event: Event) {
    event.preventDefault();
    if (pending()) {
      return;
    }

    const target = event.target instanceof Element ? event.target : null;
    const form = target?.closest("form");

    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    const bucketNameInput = form.querySelector("#bucket-name");
    const name =
      bucketNameInput instanceof HTMLInputElement
        ? bucketNameInput.value.trim()
        : "";

    if (!name) {
      setError("Bucket name is required.");
      return;
    }

    setPending(true);
    setError("");

    try {
      await createBucket({ name });
      form.reset();
      setOpen(false);
      onCreated?.();
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Bucket could not be created."
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button onPress={() => setOpen(true)}>Add bucket</Button>
      <Dialog open={isOpen()} onOpenChange={setOpen}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent>
            <Stack gap="4">
              <Stack gap="1">
                <DialogTitle>Add bucket</DialogTitle>
                <DialogDescription>Create a bucket in the emulator.</DialogDescription>
              </Stack>
              <form
                onSubmit={(event: Event) => {
                  void handleSubmit(event);
                }}
              >
                <Stack gap="4">
                  <Field>
                    <Label for="bucket-name">Bucket name</Label>
                    <Input id="bucket-name" name="bucket-name" disabled={pending()} />
                  </Field>
                  <Show when={error()}>
                    <FieldError role="alert">{error()}</FieldError>
                  </Show>
                  <ButtonGroup>
                    <Button type="submit" disabled={pending()}>
                      {pending() ? "Creating..." : "Create bucket"}
                    </Button>
                    <DialogClose
                      asChild
                      onPress={() => {
                        setError("");
                      }}
                    >
                      <Button variant="secondary" disabled={pending()}>
                        Cancel
                      </Button>
                    </DialogClose>
                  </ButtonGroup>
                </Stack>
              </form>
            </Stack>
          </DialogContent>
        </DialogPortal>
      </Dialog>
    </>
  );
}
