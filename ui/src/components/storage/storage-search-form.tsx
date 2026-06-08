import { SearchIcon } from '@askrjs/lucide';
import { state } from '@askrjs/askr';
import { resource } from '@askrjs/askr/resources';
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
  const [searchValue, setSearchValue] = state(defaultValue ?? '');
  let searchInput: HTMLInputElement | null = null;

  resource(() => {
    const next = defaultValue ?? '';
    if (searchValue() !== next) {
      setSearchValue(next);
    }

    return null;
  }, [defaultValue]);

  function updateSearch(event: Event) {
    const value =
      event.target instanceof HTMLInputElement ? event.target.value : '';
    setSearchValue(value);
    onSearch(value.trim());
  }

  function searchNow(event?: Event) {
    event?.preventDefault();
    onSearch(searchValue().trim());
  }

  function clearSearch() {
    if (searchInput) {
      searchInput.value = '';
      searchInput.focus();
    }

    setSearchValue('');
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
            <Input
              id={inputId}
              name={inputId}
              onInput={updateSearch}
              ref={(node: HTMLInputElement | null) => {
                searchInput = node;
                if (node && node.value !== searchValue()) {
                  node.value = searchValue();
                }
              }}
            />
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
