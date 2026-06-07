import { Flex, Stack } from '@askrjs/themes/layouts';

export default function StoragePageHeader({
  actions,
  description,
  title,
}: {
  actions?: unknown;
  description?: string;
  title: string;
}) {
  return (
    <Flex
      data-peas-slot="storage-page-header"
      justify={{ initial: 'between' }}
      align={{ initial: 'start' }}
      gap="3"
      wrap={{ initial: 'wrap' }}
    >
      <Stack gap="1">
        <h1 data-peas-slot="storage-page-title">{title}</h1>
        {description ? (
          <p data-peas-slot="storage-page-description">{description}</p>
        ) : null}
      </Stack>
      {actions ? (
        <Flex gap="2" align={{ initial: 'center' }} wrap={{ initial: 'wrap' }}>
          {actions}
        </Flex>
      ) : null}
    </Flex>
  );
}
