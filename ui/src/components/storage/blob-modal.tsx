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
import { putBlobContent } from "../../features/blobs/blobs.query";

export default function BlobModal({
  bucketName,
  onUploaded,
}: {
  bucketName: string;
  onUploaded?: () => void;
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

    const blobKeyInput = form.querySelector("#blob-key");
    const fileInput = form.querySelector("#blob-file");
    const blob =
      fileInput instanceof HTMLInputElement ? fileInput.files?.[0] ?? null : null;
    const key =
      (blobKeyInput instanceof HTMLInputElement
        ? blobKeyInput.value.trim()
        : "") || blob?.name || "";

    if (!blob) {
      setError("Choose a file to upload.");
      return;
    }

    if (!key) {
      setError("Blob key is required.");
      return;
    }

    setPending(true);
    setError("");

    try {
      await putBlobContent({
        bucketName,
        objectKey: key,
        content: blob,
        contentType: blob.type || undefined,
      });
      form.reset();
      setOpen(false);
      onUploaded?.();
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : "Blob could not be uploaded."
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button onPress={() => setOpen(true)}>Add blob</Button>
      <Dialog open={isOpen()} onOpenChange={setOpen}>
        <DialogPortal>
          <DialogOverlay />
          <DialogContent>
            <Stack gap="4">
              <Stack gap="1">
                <DialogTitle>Add blob</DialogTitle>
                <DialogDescription>Upload a file into {bucketName}.</DialogDescription>
              </Stack>
              <form
                onSubmit={(event: Event) => {
                  void handleSubmit(event);
                }}
              >
                <Stack gap="4">
                  <Field>
                    <Label for="blob-key">Blob key</Label>
                    <Input id="blob-key" name="blob-key" disabled={pending()} />
                  </Field>
                  <Field>
                    <Label for="blob-file">File</Label>
                    <Input
                      id="blob-file"
                      name="blob-file"
                      type="file"
                      disabled={pending()}
                    />
                  </Field>
                  <Show when={error()}>
                    <FieldError role="alert">{error()}</FieldError>
                  </Show>
                  <ButtonGroup>
                    <Button type="submit" disabled={pending()}>
                      {pending() ? "Uploading..." : "Upload blob"}
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
