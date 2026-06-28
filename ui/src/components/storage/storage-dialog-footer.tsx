import { Inline } from '@askrjs/themes/components';

export default function StorageDialogFooter({
  children,
}: {
  children?: unknown;
}) {
  return (
    <Inline
      data-peas-slot="storage-dialog-footer"
      justify="end"
      align="center"
      gap="2"
      wrap
      width="full"
    >
      {children}
    </Inline>
  );
}
