import { Button, Field } from "@askrjs/themes/controls";
import { Inline } from "@askrjs/themes/layouts";
import { Input, Label } from "@askrjs/ui";

export default function StorageSearchForm({
  inputId,
  label,
  onClear,
  onSubmit,
}: {
  inputId: string;
  label: string;
  onClear: () => void;
  onSubmit: (event: Event) => void;
}) {
  function submitForm() {
    if (typeof document === "undefined") {
      return;
    }

    const input = document.getElementById(inputId);
    const form = input?.closest("form");

    if (form instanceof HTMLFormElement) {
      form.requestSubmit();
    }
  }

  function clearForm() {
    if (typeof document !== "undefined") {
      const input = document.getElementById(inputId);
      if (input instanceof HTMLInputElement) {
        input.value = "";
      }
    }

    onClear();
  }

  return (
    <form onSubmit={onSubmit}>
      <Inline align="end" gap="2" wrap="wrap">
        <Field>
          <Label for={inputId}>{label}</Label>
          <Input id={inputId} name={inputId} />
        </Field>
        <Button type="button" onPress={submitForm}>
          Search
        </Button>
        <Button
          type="button"
          variant="secondary"
          onPress={clearForm}
        >
          Clear
        </Button>
      </Inline>
    </form>
  );
}
