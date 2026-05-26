import { state } from '@askrjs/askr';
import { resource } from '@askrjs/askr/resources';
import { Button, Field } from '@askrjs/themes/controls';
import { Inline, Stack } from '@askrjs/themes/layouts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@askrjs/themes/surfaces';
import type { Acl } from '../../adapters/api.g';
import { loadObjectAcl, saveObjectAcl } from './objects.query';
import { parseJson, prettyJson } from '../../shared/json';

export default function ObjectAclSection({
  bucketName,
  objectKey,
}: {
  bucketName: string;
  objectKey: string;
}) {
  const [aclDrafts, setAclDrafts] = state<Record<string, string>>({});
  const [aclErrors, setAclErrors] = state<Record<string, string>>({});
  const [aclBusy, setAclBusy] = state(false);

  const defaultAcl: Acl = { canned: 'private', grants: [] };
  const bucketId = encodeURIComponent(bucketName);
  const objectId = encodeURIComponent(objectKey);
  const scopeKey = `${bucketName}::${objectKey}`;
  const aclDraft = () => aclDrafts()[scopeKey] ?? '';
  const aclError = () => aclErrors()[scopeKey] ?? '';

  function updateAclDraft(value: string) {
    setAclDrafts({ ...aclDrafts(), [scopeKey]: value });
  }

  function updateAclError(value: string) {
    setAclErrors({ ...aclErrors(), [scopeKey]: value });
  }

  const objectAcl = resource(
    ({ signal }) => loadObjectAcl({ bucketName, objectKey, signal }),
    [bucketName, objectKey]
  );

  async function handleSaveAcl() {
    if (aclBusy()) {
      return;
    }

    const source = aclDraft().trim() || prettyJson(objectAcl.value ?? defaultAcl);
    let acl: Acl;
    try {
      acl = parseJson<Acl>(source);
    } catch (caughtError) {
      updateAclError(
        caughtError instanceof Error ? caughtError.message : 'Invalid JSON'
      );
      return;
    }

    setAclBusy(true);
    updateAclError('');

    try {
      await saveObjectAcl({ bucketName, objectKey, acl });
      updateAclDraft('');
      objectAcl.refresh();
    } catch (caughtError) {
      updateAclError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not update the object ACL.'
      );
    } finally {
      setAclBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Object ACL</CardTitle>
        <CardDescription>
          Object ACLs are edited as raw JSON and stored through the admin API.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Stack gap="4">
          {objectAcl.error ? (
            <p class="muted">No object ACL stored yet.</p>
          ) : null}
          <Field>
            <label for={`object-acl-${bucketId}-${objectId}`}>ACL JSON</label>
            <textarea
              id={`object-acl-${bucketId}-${objectId}`}
              class="json-editor"
              value={aclDraft() || prettyJson(objectAcl.value ?? defaultAcl)}
              onInput={(event: Event) => {
                updateAclError('');
                updateAclDraft((event.currentTarget as HTMLTextAreaElement).value);
              }}
              rows={10}
              disabled={aclBusy()}
            />
          </Field>
          {aclError() ? (
            <p role="alert" class="form-error">
              {aclError()}
            </p>
          ) : null}
          <Inline gap="2" align="center" wrap="wrap">
            <Button onPress={() => void handleSaveAcl()} disabled={aclBusy()}>
              Save ACL
            </Button>
            <Button
              variant="secondary"
              onPress={() => objectAcl.refresh()}
              disabled={aclBusy()}
            >
              Reload
            </Button>
          </Inline>
        </Stack>
      </CardContent>
    </Card>
  );
}
