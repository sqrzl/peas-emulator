import { Button, Field } from '@askrjs/themes/controls';
import { Inline } from '@askrjs/themes/layouts';
import { Input, Label } from '@askrjs/ui';

const debounceMs = 250;

export default function StorageSearchForm({
  inputId,
  label,
  onSearch,
}: {
  inputId: string;
  label: string;
  onSearch: (value: string) => void;
}) {
  let timer: ReturnType<typeof setTimeout> | undefined;

  function inputElement(): HTMLInputElement | null {
    const element = document.getElementById(inputId);
    return element instanceof HTMLInputElement ? element : null;
  }

  function handleInput(event: Event) {
    const value =
      event.target instanceof HTMLInputElement ? event.target.value : '';
    clearTimeout(timer);
    timer = setTimeout(() => onSearch(value.trim()), debounceMs);
  }

  function searchNow() {
    clearTimeout(timer);
    onSearch(inputElement()?.value.trim() ?? '');
  }

  function clearSearch() {
    clearTimeout(timer);
    const input = inputElement();
    if (input) {
      input.value = '';
    }
    onSearch('');
  }

  return (
    <div>
      <Inline align="end" gap="2" wrap="wrap">
        <Field>
          <Label for={inputId}>{label}</Label>
          <Input id={inputId} name={inputId} onInput={handleInput} />
        </Field>
        <Button type="button" onPress={searchNow}>
          Search
        </Button>
        <Button type="button" variant="secondary" onPress={clearSearch}>
          Clear
        </Button>
      </Inline>
    </div>
  );
}
