import { Stack } from '@askrjs/themes/layouts';

export default function StorageDialogHeader({
  children,
  title,
}: {
  children?: unknown;
  title: string;
}) {
  return (
    <Stack
      data-peas-slot="storage-dialog-header"
      align={{ initial: 'stretch' }}
      gap="1"
      width={{ initial: '100%' }}
    >
      <h2 data-peas-slot="storage-dialog-title">{title}</h2>
      <Stack data-peas-slot="storage-dialog-description" gap="1">
        {children}
      </Stack>
    </Stack>
  );
}
