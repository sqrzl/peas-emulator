import { Flex } from '@askrjs/themes/layouts';

export default function StorageDialogFooter({
  children,
}: {
  children?: unknown;
}) {
  return (
    <Flex
      data-peas-slot="storage-dialog-footer"
      justify={{ initial: 'end' }}
      align={{ initial: 'center' }}
      gap="2"
      wrap={{ initial: 'wrap' }}
      width={{ initial: '100%' }}
    >
      {children}
    </Flex>
  );
}
