import { Stack } from '@askrjs/themes/layouts';

export default function StorageDialogForm({
  children,
  onSubmit,
}: {
  children?: unknown;
  onSubmit: (event: Event) => void;
}) {
  return (
    <Stack
      asChild
      data-peas-slot="storage-dialog-form"
      align={{ initial: 'stretch' }}
      gap="4"
      width={{ initial: '100%' }}
    >
      <form onSubmit={onSubmit}>{children}</form>
    </Stack>
  );
}
