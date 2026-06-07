import { SearchIcon } from '@askrjs/lucide';
import { Button, ButtonGroup, Field } from '@askrjs/themes/controls';
import { Box, Flex } from '@askrjs/themes/layouts';
import { Input, Label } from '@askrjs/ui';

export default function StorageSearchForm({
  inputId,
  label,
  defaultValue,
  onSearch,
}: {
  inputId: string;
  label: string;
  defaultValue?: string;
  onSearch: (value: string) => void;
}) {
  let inputRef: HTMLInputElement | null = null;

  function inputElement(): HTMLInputElement | null {
    return inputRef;
  }

  function initializeInput(element: HTMLInputElement | null) {
    inputRef = element;
    if (!element) {
      return;
    }

    // Keep the field uncontrolled while still hydrating from URL-derived search state.
    if ((element.value ?? '').trim() === '' && defaultValue) {
      element.value = defaultValue;
    }
  }

  function searchNow(event?: Event) {
    event?.preventDefault();
    onSearch(inputElement()?.value.trim() ?? '');
  }

  function clearSearch() {
    const input = inputElement();
    if (input) {
      input.value = '';
      input.focus();
    }
    onSearch('');
  }

  return (
    <form data-peas-slot="storage-search-form" onSubmit={searchNow}>
      <Flex align={{ initial: 'end' }} gap="3" wrap={{ initial: 'wrap' }}>
        <Box
          data-peas-slot="storage-search-field"
          flexGrow="1"
          minWidth={{ initial: '100%', sm: '18rem' }}
          maxWidth={{ initial: '100%', md: '28rem' }}
        >
          <Field>
            <Label for={inputId}>{label}</Label>
            <Input id={inputId} name={inputId} ref={initializeInput} />
          </Field>
        </Box>
        <ButtonGroup attached={false}>
          <Button type="submit">
            <SearchIcon aria-hidden="true" /> Search
          </Button>
          <Button type="button" variant="secondary" onPress={clearSearch}>
            Clear
          </Button>
        </ButtonGroup>
      </Flex>
    </form>
  );
}
