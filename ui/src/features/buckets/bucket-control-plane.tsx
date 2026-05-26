import { state } from '@askrjs/askr';
import { resource } from '@askrjs/askr/resources';
import { RefreshCwIcon } from '@askrjs/lucide';
import { Button, Field } from '@askrjs/themes/controls';
import { Inline, Stack } from '@askrjs/themes/layouts';
import { Badge } from '@askrjs/themes/surfaces';
import type {
  Acl,
  BucketPolicyDocument,
  LifecycleConfiguration,
} from '../../adapters/api.g';
import {
  abortMultipartUpload,
  deleteBucketLifecycle,
  deleteBucketPolicy,
  loadBucketAcl,
  loadBucketLifecycle,
  loadBucketPolicy,
  listMultipartUploads,
  loadMultipartUpload,
  saveBucketAcl,
  saveBucketLifecycle,
  saveBucketPolicy,
} from './buckets.query';
import { formatBytes, formatRelativeTime } from '../../shared/format';
import { parseJson, prettyJson } from '../../shared/json';

export default function BucketControlPlaneSection({
  bucketName,
}: {
  bucketName: string;
}) {
  const [aclDrafts, setAclDrafts] = state<Record<string, string>>({});
  const [policyDrafts, setPolicyDrafts] = state<Record<string, string>>({});
  const [lifecycleDrafts, setLifecycleDrafts] = state<Record<string, string>>(
    {}
  );
  const [selectedUploadIds, setSelectedUploadIds] = state<Record<string, string>>(
    {}
  );
  const [uploadNextPages, setUploadNextPages] = state<
    Record<string, string | undefined>
  >({});
  const [controlErrors, setControlErrors] = state<Record<string, string>>({});
  const [controlBusy, setControlBusy] = state(false);

  const defaultAcl: Acl = { canned: 'private', grants: [] };
  const defaultPolicy: BucketPolicyDocument = {
    Version: '2012-10-17',
    Statement: [],
  };
  const defaultLifecycle: LifecycleConfiguration = { rules: [] };
  const bucketId = encodeURIComponent(bucketName);
  const aclDraft = () => aclDrafts()[bucketName] ?? '';
  const policyDraft = () => policyDrafts()[bucketName] ?? '';
  const lifecycleDraft = () => lifecycleDrafts()[bucketName] ?? '';
  const selectedUploadId = () => selectedUploadIds()[bucketName] ?? '';
  const uploadNext = () => uploadNextPages()[bucketName];
  const controlError = () => controlErrors()[bucketName] ?? '';

  function updateAclDraft(value: string) {
    setAclDrafts({ ...aclDrafts(), [bucketName]: value });
  }

  function updatePolicyDraft(value: string) {
    setPolicyDrafts({ ...policyDrafts(), [bucketName]: value });
  }

  function updateLifecycleDraft(value: string) {
    setLifecycleDrafts({ ...lifecycleDrafts(), [bucketName]: value });
  }

  function updateSelectedUploadId(value: string) {
    setSelectedUploadIds({ ...selectedUploadIds(), [bucketName]: value });
  }

  function updateUploadNext(value: string | undefined) {
    setUploadNextPages({ ...uploadNextPages(), [bucketName]: value });
  }

  function updateControlError(value: string) {
    setControlErrors({ ...controlErrors(), [bucketName]: value });
  }

  const bucketAcl = resource(
    ({ signal }) => loadBucketAcl({ bucketName, signal }),
    [bucketName]
  );
  const bucketPolicy = resource(
    ({ signal }) => loadBucketPolicy({ bucketName, signal }),
    [bucketName]
  );
  const bucketLifecycle = resource(
    ({ signal }) => loadBucketLifecycle({ bucketName, signal }),
    [bucketName]
  );
  const uploads = resource(
    ({ signal }) =>
      listMultipartUploads({
        bucketName,
        next: uploadNext(),
        signal,
      }),
    [bucketName, uploadNext()]
  );
  const selectedUpload = resource(
    ({ signal }) =>
      selectedUploadId()
        ? loadMultipartUpload({
            bucketName,
            uploadId: selectedUploadId(),
            signal,
          })
        : Promise.resolve(null),
    [bucketName, selectedUploadId()]
  );

  async function runControlMutation(
    operation: () => Promise<void>,
    refresh: () => void
  ) {
    if (controlBusy()) {
      return;
    }

    setControlBusy(true);
    updateControlError('');

    try {
      await operation();
      refresh();
    } catch (caughtError) {
      updateControlError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not update the selected bucket control plane.'
      );
    } finally {
      setControlBusy(false);
    }
  }

  async function handleSaveAcl() {
    const source = aclDraft().trim() || prettyJson(bucketAcl.value ?? defaultAcl);
    let acl: Acl;
    try {
      acl = parseJson<Acl>(source);
    } catch (caughtError) {
      updateControlError(
        caughtError instanceof Error ? caughtError.message : 'Invalid JSON'
      );
      return;
    }

    await runControlMutation(
      async () => {
        await saveBucketAcl({ bucketName, acl });
        updateAclDraft('');
      },
      () => bucketAcl.refresh()
    );
  }

  async function handleSavePolicy() {
    const source =
      policyDraft().trim() || prettyJson(bucketPolicy.value ?? defaultPolicy);
    let policy: BucketPolicyDocument;
    try {
      policy = parseJson<BucketPolicyDocument>(source);
    } catch (caughtError) {
      updateControlError(
        caughtError instanceof Error ? caughtError.message : 'Invalid JSON'
      );
      return;
    }

    await runControlMutation(
      async () => {
        await saveBucketPolicy({ bucketName, policy });
        updatePolicyDraft('');
      },
      () => bucketPolicy.refresh()
    );
  }

  async function handleDeletePolicy() {
    await runControlMutation(
      async () => {
        await deleteBucketPolicy({ bucketName });
        updatePolicyDraft('');
      },
      () => bucketPolicy.refresh()
    );
  }

  async function handleSaveLifecycle() {
    const source =
      lifecycleDraft().trim() ||
      prettyJson(bucketLifecycle.value ?? defaultLifecycle);
    let lifecycle: LifecycleConfiguration;
    try {
      lifecycle = parseJson<LifecycleConfiguration>(source);
    } catch (caughtError) {
      updateControlError(
        caughtError instanceof Error ? caughtError.message : 'Invalid JSON'
      );
      return;
    }

    await runControlMutation(
      async () => {
        await saveBucketLifecycle({ bucketName, lifecycle });
        updateLifecycleDraft('');
      },
      () => bucketLifecycle.refresh()
    );
  }

  async function handleDeleteLifecycle() {
    await runControlMutation(
      async () => {
        await deleteBucketLifecycle({ bucketName });
        updateLifecycleDraft('');
      },
      () => bucketLifecycle.refresh()
    );
  }

  async function handleAbortUpload(uploadId: string) {
    await runControlMutation(
      async () => {
        await abortMultipartUpload({ bucketName, uploadId });
        if (selectedUploadId() === uploadId) {
          updateSelectedUploadId('');
        }
      },
      () => {
        uploads.refresh();
        if (selectedUploadId()) {
          selectedUpload.refresh();
        }
      }
    );
  }

  return (
    <Stack gap="4" class="control-plane-stack">
      <Inline justify="between" align="center" gap="2" wrap="wrap">
        <Stack gap="none">
          <h3>Bucket control plane</h3>
          <p class="muted">
            ACL, policy, lifecycle, and multipart uploads are edited directly as
            JSON so the UI stays aligned with the backend contract.
          </p>
        </Stack>
        <Inline gap="2" align="center" wrap="wrap">
          {controlBusy() ? <Badge>saving</Badge> : null}
          <Button
            variant="secondary"
            onPress={() => {
              bucketAcl.refresh();
              bucketPolicy.refresh();
              bucketLifecycle.refresh();
              uploads.refresh();
              if (selectedUploadId()) {
                selectedUpload.refresh();
              }
            }}
            disabled={controlBusy()}
          >
            <RefreshCwIcon size={14} aria-hidden="true" /> Refresh controls
          </Button>
        </Inline>
      </Inline>

      {controlError() ? (
        <p role="alert" class="form-error">
          {controlError()}
        </p>
      ) : null}

      <Stack gap="4" class="control-plane-grid">
        <section class="control-plane-section">
          <Stack gap="3">
            <Inline justify="between" align="center" gap="2" wrap="wrap">
              <Stack gap="none">
                <h4>Bucket ACL</h4>
                <p class="muted">Set a canned ACL or raw grant list.</p>
              </Stack>
              <Button
                variant="secondary"
                onPress={() => bucketAcl.refresh()}
                disabled={controlBusy()}
              >
                Reload
              </Button>
            </Inline>
            <Field>
              <label for={`bucket-acl-${bucketId}`}>ACL JSON</label>
              <textarea
                id={`bucket-acl-${bucketId}`}
                class="json-editor"
                value={aclDraft() || prettyJson(bucketAcl.value ?? defaultAcl)}
                onInput={(event: Event) => {
                  updateControlError('');
                  updateAclDraft((event.currentTarget as HTMLTextAreaElement).value);
                }}
                rows={10}
                disabled={controlBusy()}
              />
            </Field>
            <Inline gap="2" align="center" wrap="wrap">
              <Button onPress={() => void handleSaveAcl()} disabled={controlBusy()}>
                Save ACL
              </Button>
            </Inline>
          </Stack>
        </section>

        <section class="control-plane-section">
          <Stack gap="3">
            <Inline justify="between" align="center" gap="2" wrap="wrap">
              <Stack gap="none">
                <h4>Bucket policy</h4>
                <p class="muted">Policies are stored in the backend JSON model.</p>
              </Stack>
              <Inline gap="2" align="center" wrap="wrap">
                <Button
                  variant="secondary"
                  onPress={() => bucketPolicy.refresh()}
                  disabled={controlBusy()}
                >
                  Reload
                </Button>
                <Button
                  variant="secondary"
                  onPress={() => void handleDeletePolicy()}
                  disabled={controlBusy()}
                >
                  Delete
                </Button>
              </Inline>
            </Inline>
            {bucketPolicy.error ? (
              <p class="muted">No bucket policy stored yet.</p>
            ) : null}
            <Field>
              <label for={`bucket-policy-${bucketId}`}>Policy JSON</label>
              <textarea
                id={`bucket-policy-${bucketId}`}
                class="json-editor"
                value={
                  policyDraft() || prettyJson(bucketPolicy.value ?? defaultPolicy)
                }
                onInput={(event: Event) => {
                  updateControlError('');
                  updatePolicyDraft(
                    (event.currentTarget as HTMLTextAreaElement).value
                  );
                }}
                rows={12}
                disabled={controlBusy()}
              />
            </Field>
            <Inline gap="2" align="center" wrap="wrap">
              <Button onPress={() => void handleSavePolicy()} disabled={controlBusy()}>
                Save policy
              </Button>
            </Inline>
          </Stack>
        </section>

        <section class="control-plane-section">
          <Stack gap="3">
            <Inline justify="between" align="center" gap="2" wrap="wrap">
              <Stack gap="none">
                <h4>Bucket lifecycle</h4>
                <p class="muted">Lifecycle rules map directly to storage models.</p>
              </Stack>
              <Inline gap="2" align="center" wrap="wrap">
                <Button
                  variant="secondary"
                  onPress={() => bucketLifecycle.refresh()}
                  disabled={controlBusy()}
                >
                  Reload
                </Button>
                <Button
                  variant="secondary"
                  onPress={() => void handleDeleteLifecycle()}
                  disabled={controlBusy()}
                >
                  Delete
                </Button>
              </Inline>
            </Inline>
            {bucketLifecycle.error ? (
              <p class="muted">No bucket lifecycle stored yet.</p>
            ) : null}
            <Field>
              <label for={`bucket-lifecycle-${bucketId}`}>Lifecycle JSON</label>
              <textarea
                id={`bucket-lifecycle-${bucketId}`}
                class="json-editor"
                value={
                  lifecycleDraft() ||
                  prettyJson(bucketLifecycle.value ?? defaultLifecycle)
                }
                onInput={(event: Event) => {
                  updateControlError('');
                  updateLifecycleDraft(
                    (event.currentTarget as HTMLTextAreaElement).value
                  );
                }}
                rows={12}
                disabled={controlBusy()}
              />
            </Field>
            <Inline gap="2" align="center" wrap="wrap">
              <Button
                onPress={() => void handleSaveLifecycle()}
                disabled={controlBusy()}
              >
                Save lifecycle
              </Button>
            </Inline>
          </Stack>
        </section>

        <section class="control-plane-section">
          <Stack gap="3">
            <Inline justify="between" align="center" gap="2" wrap="wrap">
              <Stack gap="none">
                <h4>Multipart uploads</h4>
                <p class="muted">
                  Inspect active upload sessions and abort stale ones.
                </p>
              </Stack>
              <Inline gap="2" align="center" wrap="wrap">
                <Button
                  variant="secondary"
                  onPress={() => {
                    updateUploadNext(undefined);
                  }}
                  disabled={controlBusy()}
                >
                  First page
                </Button>
                <Button
                  variant="secondary"
                  onPress={() => updateUploadNext(uploads.value?.next ?? undefined)}
                  disabled={!uploads.value?.next || controlBusy()}
                >
                  Next page
                </Button>
              </Inline>
            </Inline>

            <div class="run-table-wrap">
              <table class="run-table">
                <thead>
                  <tr>
                    <th>Upload</th>
                    <th>Key</th>
                    <th>Initiated</th>
                    <th>Parts</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {uploads.value?.items.map((upload) => (
                    <tr
                      key={upload.upload_id}
                      data-selected={
                        selectedUploadId() === upload.upload_id ? 'true' : 'false'
                      }
                    >
                      <td>
                        <strong>{upload.upload_id}</strong>
                        <span>
                          {upload.content_type ?? 'application/octet-stream'}
                        </span>
                      </td>
                      <td>{upload.key}</td>
                      <td>{formatRelativeTime(upload.initiated)}</td>
                      <td>{upload.parts.length}</td>
                      <td>
                        <Inline gap="2" align="center" justify="end" wrap="wrap">
                          <Button
                            variant="secondary"
                            onPress={() => updateSelectedUploadId(upload.upload_id)}
                            disabled={controlBusy()}
                          >
                            Inspect
                          </Button>
                          <Button
                            variant="secondary"
                            onPress={() => void handleAbortUpload(upload.upload_id)}
                            disabled={controlBusy()}
                          >
                            Abort
                          </Button>
                        </Inline>
                      </td>
                    </tr>
                  ))}
                  {!uploads.pending && (uploads.value?.items.length ?? 0) === 0 ? (
                    <tr>
                      <td colSpan={5}>No active multipart uploads.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>

            <section class="control-plane-detail">
              <Inline justify="between" align="center" gap="2" wrap="wrap">
                <Stack gap="none">
                  <h4>Upload details</h4>
                  <p class="muted">
                    Review the selected upload's metadata and part list.
                  </p>
                </Stack>
                {selectedUploadId() ? (
                  <Badge>{selectedUploadId()}</Badge>
                ) : (
                  <Badge>none selected</Badge>
                )}
              </Inline>

              {selectedUpload.pending ? (
                <p class="muted">Loading upload details...</p>
              ) : selectedUpload.value ? (
                <Stack gap="3">
                  <div class="hero-row">
                    <span>Object key</span>
                    <strong>{selectedUpload.value.key}</strong>
                  </div>
                  <div class="hero-row">
                    <span>Initiated</span>
                    <strong>
                      {formatRelativeTime(selectedUpload.value.initiated)}
                    </strong>
                  </div>
                  <div class="hero-row">
                    <span>Content type</span>
                    <strong>
                      {selectedUpload.value.content_type ??
                        'application/octet-stream'}
                    </strong>
                  </div>
                  <h5>Parts</h5>
                  <div class="run-table-wrap">
                    <table class="run-table">
                      <thead>
                        <tr>
                          <th>Part</th>
                          <th>Etag</th>
                          <th>Size</th>
                          <th>Modified</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedUpload.value.parts.map((part) => (
                          <tr key={`${part.part_number}-${part.etag}`}>
                            <td>{part.part_number}</td>
                            <td>{part.etag}</td>
                            <td>{formatBytes(part.size)}</td>
                            <td>{formatRelativeTime(part.last_modified)}</td>
                          </tr>
                        ))}
                        {selectedUpload.value.parts.length === 0 ? (
                          <tr>
                            <td colSpan={4}>
                              This upload does not have any parts yet.
                            </td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                </Stack>
              ) : (
                <p class="muted">
                  Select an upload from the table to inspect its parts.
                </p>
              )}
            </section>
          </Stack>
        </section>
      </Stack>
    </Stack>
  );
}
