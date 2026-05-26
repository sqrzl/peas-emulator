import { state } from '@askrjs/askr';
import { resource } from '@askrjs/askr/resources';
import { Link, navigate } from '@askrjs/askr/router';
import { AlertCircleIcon, RefreshCwIcon } from '@askrjs/lucide';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogOverlay,
  AlertDialogPortal,
  AlertDialogTitle,
  AlertDialogTrigger,
  Input,
} from '@askrjs/ui';
import { Button, Field, FieldHint } from '@askrjs/themes/controls';
import { EmptyState } from '@askrjs/themes/feedback';
import { Block, Inline, Section, Stack } from '@askrjs/themes/layouts';
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@askrjs/themes/surfaces';
import MetricCard from '../../components/shared/metric-card';
import {
  createBucket,
  deleteBucket,
  loadBucket,
  loadBucketObjects,
  loadBuckets,
  listBucketPage,
  setBucketVersioning,
} from '../../features/buckets/buckets.query';
import {
  deleteObjectVersion,
  deleteObject,
  downloadObjectContent,
  loadObjectMetadata,
  loadObjectTags,
  loadObjectVersions,
  putObjectContent,
  putObjectTags,
} from '../../features/objects/objects.query';
import BucketControlPlaneSection from '../../features/buckets/bucket-control-plane';
import ObjectAclSection from '../../features/objects/object-acl-section';
import { formatBytes, formatRelativeTime } from '../../shared/format';

function currentBucketName(): string {
  if (typeof window === 'undefined') {
    return '';
  }

  return new URLSearchParams(window.location.search).get('bucket') ?? '';
}

function currentObjectKey(): string {
  if (typeof window === 'undefined') {
    return '';
  }

  return new URLSearchParams(window.location.search).get('object') ?? '';
}

function bucketHref(bucketName: string, objectKey?: string): string {
  const query = new URLSearchParams({ bucket: bucketName });
  if (objectKey) {
    query.set('object', objectKey);
  }

  return `/app/buckets?${query.toString()}`;
}

function parseKeyValueLines(value: string): Record<string, string> {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce<Record<string, string>>((items, line) => {
      const separator = line.indexOf('=');
      if (separator > 0) {
        items[line.slice(0, separator).trim()] = line
          .slice(separator + 1)
          .trim();
      }
      return items;
    }, {});
}

export default function BucketsPage() {
  const [bucketSearch, setBucketSearch] = state('');
  const [newBucketName, setNewBucketName] = state('');
  const [objectSearch, setObjectSearch] = state('');
  const [objectKey, setObjectKey] = state('');
  const [selectedFile, setSelectedFile] = state<File | null>(null);
  const [uploadMetadata, setUploadMetadata] = state('');
  const [tagsEditor, setTagsEditor] = state('');
  const [bucketNext, setBucketNext] = state<string | undefined>(undefined);
  const [objectNext, setObjectNext] = state<string | undefined>(undefined);
  const [versionNext, setVersionNext] = state<string | undefined>(undefined);
  const [bucketError, setBucketError] = state('');
  const [objectError, setObjectError] = state('');
  const [bucketBusy, setBucketBusy] = state(false);
  const [objectBusy, setObjectBusy] = state(false);

  const selectedBucketName = currentBucketName();
  const selectedObjectKey = currentObjectKey();

  const inventory = resource(({ signal }) => loadBuckets({ signal }), []);
  const bucketResults = resource(
    ({ signal }) =>
      listBucketPage({
        next: bucketNext(),
        search: bucketSearch().trim() || undefined,
        signal,
      }),
    [bucketSearch(), bucketNext()]
  );
  const bucketDetail = resource(
    ({ signal }) =>
      selectedBucketName
        ? loadBucket({ bucketName: selectedBucketName, signal })
        : Promise.resolve(null),
    [selectedBucketName]
  );
  const objects = resource(
    ({ signal }) =>
      selectedBucketName
        ? loadBucketObjects({
            bucketName: selectedBucketName,
            next: objectNext(),
            search: objectSearch().trim() || undefined,
            signal,
          })
        : Promise.resolve({ items: [], next: null }),
    [selectedBucketName, objectSearch(), objectNext()]
  );
  const metadata = resource(
    ({ signal }) =>
      selectedBucketName && selectedObjectKey
        ? loadObjectMetadata({
            bucketName: selectedBucketName,
            objectKey: selectedObjectKey,
            signal,
          })
        : Promise.resolve(null),
    [selectedBucketName, selectedObjectKey]
  );
  const tags = resource(
    ({ signal }) =>
      selectedBucketName && selectedObjectKey
        ? loadObjectTags({
            bucketName: selectedBucketName,
            objectKey: selectedObjectKey,
            signal,
          })
        : Promise.resolve(null),
    [selectedBucketName, selectedObjectKey]
  );
  const versions = resource(
    ({ signal }) =>
      selectedBucketName && selectedObjectKey
        ? loadObjectVersions({
            bucketName: selectedBucketName,
            objectKey: selectedObjectKey,
            next: versionNext(),
            signal,
          })
        : Promise.resolve(null),
    [selectedBucketName, selectedObjectKey, versionNext()]
  );

  const snapshot = inventory.value;
  const visibleBuckets = bucketResults.value?.items ?? [];
  const selectedBucket = bucketDetail.value;
  const objectList = objects.value;
  const selectedBucketSummary = snapshot?.buckets.find(
    (bucket) => bucket.name === selectedBucketName
  );

  async function handleCreateBucket() {
    const name = newBucketName().trim();
    if (!name || bucketBusy()) {
      return;
    }

    setBucketBusy(true);
    setBucketError('');

    try {
      const created = await createBucket({ name });
      setNewBucketName('');
      navigate(bucketHref(created.name));
      inventory.refresh();
      bucketResults.refresh();
    } catch (caughtError) {
      setBucketError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not create the bucket.'
      );
    } finally {
      setBucketBusy(false);
    }
  }

  async function handleDeleteBucket(bucketName: string) {
    if (bucketBusy()) {
      return;
    }

    setBucketBusy(true);
    setBucketError('');

    try {
      await deleteBucket({ bucketName });
      inventory.refresh();
      bucketResults.refresh();

      if (selectedBucketName === bucketName) {
        navigate('/app/buckets');
      }
    } catch (caughtError) {
      setBucketError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not delete the bucket.'
      );
    } finally {
      setBucketBusy(false);
    }
  }

  async function handleToggleVersioning() {
    if (!selectedBucketName || bucketBusy()) {
      return;
    }

    setBucketBusy(true);
    setBucketError('');

    try {
      await setBucketVersioning({
        bucketName: selectedBucketName,
        enabled: !selectedBucket?.versioning.enabled,
      });
      bucketDetail.refresh();
      inventory.refresh();
    } catch (caughtError) {
      setBucketError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not change versioning.'
      );
    } finally {
      setBucketBusy(false);
    }
  }

  async function handleUploadObject() {
    if (!selectedBucketName || objectBusy()) {
      return;
    }

    const file = selectedFile();
    const key = objectKey().trim() || file?.name || '';

    if (!file || !key) {
      setObjectError('Pick a file and provide an object key.');
      return;
    }

    setObjectBusy(true);
    setObjectError('');

    try {
      await putObjectContent({
        bucketName: selectedBucketName,
        objectKey: key,
        content: file,
        contentType: file.type || 'application/octet-stream',
        metadata: parseKeyValueLines(uploadMetadata()),
      });
      setSelectedFile(null);
      setObjectKey('');
      setUploadMetadata('');
      objects.refresh();
      inventory.refresh();
    } catch (caughtError) {
      setObjectError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not upload the object.'
      );
    } finally {
      setObjectBusy(false);
    }
  }

  async function handleDownloadObject(objectKeyValue: string) {
    if (!selectedBucketName || objectBusy()) {
      return;
    }

    setObjectBusy(true);
    setObjectError('');

    try {
      const { blob, fileName } = await downloadObjectContent({
        bucketName: selectedBucketName,
        objectKey: objectKeyValue,
      });

      const objectUrl = globalThis.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = fileName;
      anchor.rel = 'noreferrer';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      globalThis.URL.revokeObjectURL(objectUrl);
    } catch (caughtError) {
      setObjectError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not download the object.'
      );
    } finally {
      setObjectBusy(false);
    }
  }

  async function handleDeleteObject(objectKeyValue: string) {
    if (!selectedBucketName || objectBusy()) {
      return;
    }

    setObjectBusy(true);
    setObjectError('');

    try {
      await deleteObject({
        bucketName: selectedBucketName,
        objectKey: objectKeyValue,
      });
      objects.refresh();
      inventory.refresh();
      if (selectedObjectKey === objectKeyValue) {
        navigate(bucketHref(selectedBucketName));
      }
    } catch (caughtError) {
      setObjectError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not delete the object.'
      );
    } finally {
      setObjectBusy(false);
    }
  }

  async function handleDeleteVersion(versionId: string) {
    if (!selectedBucketName || !selectedObjectKey || objectBusy()) {
      return;
    }

    setObjectBusy(true);
    setObjectError('');

    try {
      await deleteObjectVersion({
        bucketName: selectedBucketName,
        objectKey: selectedObjectKey,
        versionId,
      });
      metadata.refresh();
      objects.refresh();
      versions.refresh();
      inventory.refresh();
    } catch (caughtError) {
      setObjectError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not delete the object version.'
      );
    } finally {
      setObjectBusy(false);
    }
  }

  async function handleSaveTags() {
    if (!selectedBucketName || !selectedObjectKey || objectBusy()) {
      return;
    }

    setObjectBusy(true);
    setObjectError('');
    try {
      await putObjectTags({
        bucketName: selectedBucketName,
        objectKey: selectedObjectKey,
        tags: parseKeyValueLines(tagsEditor()),
      });
      tags.refresh();
      setTagsEditor('');
    } catch (caughtError) {
      setObjectError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The admin API could not update object tags.'
      );
    } finally {
      setObjectBusy(false);
    }
  }

  if (inventory.error && !snapshot) {
    return (
      <Section>
        <EmptyState
          icon={<AlertCircleIcon size={24} aria-hidden="true" />}
          title="Buckets could not load"
          description="The blob workbench reads the live admin API. Retry the owning resource instead of hiding the error in a toast."
          actions={<Button onPress={() => inventory.refresh()}>Retry</Button>}
        />
      </Section>
    );
  }

  return (
    <Stack gap="5">
      <section class="page-heading">
        <Stack gap="2">
          <Badge>blob workbench</Badge>
          <h1>Buckets and objects</h1>
          <p class="lead">
            Create buckets, inspect objects, upload content, and download or
            delete blobs against the live admin API.
          </p>
        </Stack>
        <Inline gap="2" align="center" wrap="wrap">
          {inventory.pending && snapshot ? <Badge>refreshing</Badge> : null}
          <Button variant="secondary" onPress={() => inventory.refresh()}>
            <RefreshCwIcon size={14} aria-hidden="true" /> Refresh
          </Button>
        </Inline>
      </section>

      {snapshot ? (
        <Block size="sm" gap="4" class="metric-grid">
          <MetricCard
            label="Buckets"
            value={snapshot.totalBuckets.toString()}
            trend={
              snapshot.buckets[0]
                ? `latest ${formatRelativeTime(snapshot.buckets[0].createdAt)}`
                : 'no buckets'
            }
          />
          <MetricCard
            label="Versioning enabled"
            value={snapshot.versioningEnabledBuckets.toString()}
            trend={
              snapshot.totalBuckets > 0
                ? `${Math.round(
                    (snapshot.versioningEnabledBuckets /
                      snapshot.totalBuckets) *
                      100
                  )}% enabled`
                : '0% enabled'
            }
          />
          <MetricCard
            label="Objects"
            value={snapshot.totalObjects.toString()}
            trend={
              snapshot.totalBuckets > 0
                ? `${Math.round(snapshot.totalObjects / snapshot.totalBuckets)} avg per bucket`
                : '0 avg'
            }
          />
        </Block>
      ) : null}

      <Block size="lg" gap="4" align="stretch" class="operations-grid">
        <Card>
          <CardHeader>
            <CardTitle>Create bucket</CardTitle>
            <CardDescription>
              Buckets are the top-level container for objects and versions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={(event: Event) => {
                event.preventDefault();
                void handleCreateBucket();
              }}
            >
              <Stack gap="3">
                <Field>
                  <label for="bucket-name">Bucket name</label>
                  <Input
                    id="bucket-name"
                    value={newBucketName()}
                    onInput={(event: Event) =>
                      setNewBucketName(
                        (event.currentTarget as HTMLInputElement).value
                      )
                    }
                    disabled={bucketBusy()}
                    placeholder="photos"
                  />
                  <FieldHint>
                    Bucket names are sent directly to the admin API.
                  </FieldHint>
                </Field>
                {bucketError() ? (
                  <p role="alert" class="form-error">
                    {bucketError()}
                  </p>
                ) : null}
                <Button
                  type="submit"
                  onPress={() => void handleCreateBucket()}
                  disabled={bucketBusy()}
                >
                  {bucketBusy() ? 'Creating...' : 'Create bucket'}
                </Button>
              </Stack>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Bucket browser</CardTitle>
            <CardDescription>
              Search, open, and delete buckets from the live inventory.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack gap="4">
              <Field>
                <label for="bucket-search">Search buckets</label>
                <Input
                  id="bucket-search"
                  value={bucketSearch()}
                  onInput={(event: Event) => {
                    setBucketNext(undefined);
                    setBucketSearch(
                      (event.currentTarget as HTMLInputElement).value
                    );
                  }}
                  disabled={bucketBusy()}
                  placeholder="Filter by bucket name"
                />
              </Field>

              <div class="run-table-wrap">
                <table class="run-table">
                  <thead>
                    <tr>
                      <th>Bucket</th>
                      <th>Objects</th>
                      <th>Versioning</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleBuckets.map((bucket) => {
                      const isSelected = bucket.name === selectedBucketName;
                      const totals = snapshot?.buckets.find(
                        (item) => item.name === bucket.name
                      );

                      return (
                        <tr
                          key={bucket.name}
                          data-selected={isSelected ? 'true' : 'false'}
                        >
                          <td>
                            <strong>{bucket.name}</strong>
                            <span>
                              {isSelected ? 'selected' : 'click open'}
                            </span>
                          </td>
                          <td>{totals?.objectCount ?? '-'}</td>
                          <td>
                            <Badge>
                              {bucket.versioningEnabled
                                ? 'enabled'
                                : 'disabled'}
                            </Badge>
                          </td>
                          <td>{formatRelativeTime(bucket.createdAt)}</td>
                          <td>
                            <Inline
                              gap="2"
                              align="center"
                              justify="end"
                              wrap="wrap"
                            >
                              <Button variant="secondary" asChild>
                                <Link href={bucketHref(bucket.name)}>Open</Link>
                              </Button>
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="secondary"
                                    disabled={bucketBusy()}
                                  >
                                    Delete
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogPortal>
                                  <AlertDialogOverlay />
                                  <AlertDialogContent>
                                    <AlertDialogTitle>
                                      Delete bucket {bucket.name}?
                                    </AlertDialogTitle>
                                    <AlertDialogDescription>
                                      Deletion succeeds only after all contained
                                      objects are removed.
                                    </AlertDialogDescription>
                                    <Inline gap="2" align="center">
                                      <AlertDialogAction asChild>
                                        <Button
                                          onPress={() =>
                                            handleDeleteBucket(bucket.name)
                                          }
                                          disabled={bucketBusy()}
                                        >
                                          Confirm delete
                                        </Button>
                                      </AlertDialogAction>
                                      <AlertDialogCancel asChild>
                                        <Button variant="secondary">
                                          Cancel
                                        </Button>
                                      </AlertDialogCancel>
                                    </Inline>
                                  </AlertDialogContent>
                                </AlertDialogPortal>
                              </AlertDialog>
                            </Inline>
                          </td>
                        </tr>
                      );
                    })}
                    {!bucketResults.pending && visibleBuckets.length === 0 ? (
                      <tr>
                        <td colSpan={5}>No buckets match this search.</td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
              <Inline gap="2" align="center" justify="end">
                <Button
                  variant="secondary"
                  onPress={() => setBucketNext(undefined)}
                  disabled={!bucketNext() || bucketBusy()}
                >
                  First page
                </Button>
                <Button
                  variant="secondary"
                  onPress={() =>
                    setBucketNext(bucketResults.value?.next ?? undefined)
                  }
                  disabled={!bucketResults.value?.next || bucketBusy()}
                >
                  Next page
                </Button>
              </Inline>
            </Stack>
          </CardContent>
        </Card>
      </Block>

      <Block size="lg" gap="4" align="stretch" class="operations-grid">
        <Card>
          <CardHeader>
            <CardTitle>Selected bucket</CardTitle>
            <CardDescription>
              Bucket metadata and versioning are read from the live admin API.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {selectedBucketName ? (
              selectedBucket ? (
                <Stack gap="4">
                  <Inline justify="between" align="center" gap="3" wrap="wrap">
                    <Stack gap="none">
                      <h3>{selectedBucket.bucket.name}</h3>
                      <p class="muted">
                        Created{' '}
                        {formatRelativeTime(selectedBucket.bucket.createdAt)}
                      </p>
                    </Stack>
                    <Inline gap="2" align="center" wrap="wrap">
                      <Badge>
                        {selectedBucket.versioning.enabled
                          ? 'versioning on'
                          : 'versioning off'}
                      </Badge>
                      <Button
                        variant="secondary"
                        onPress={() => handleToggleVersioning()}
                        disabled={bucketBusy()}
                      >
                        {selectedBucket.versioning.enabled
                          ? 'Disable versioning'
                          : 'Enable versioning'}
                      </Button>
                    </Inline>
                  </Inline>

                  {bucketError() ? (
                    <p role="alert" class="form-error">
                      {bucketError()}
                    </p>
                  ) : null}

                  <div class="hero-row">
                    <span>Object count</span>
                    <strong>{selectedBucketSummary?.objectCount ?? 0}</strong>
                  </div>

                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="secondary" disabled={bucketBusy()}>
                        Delete bucket
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogPortal>
                      <AlertDialogOverlay />
                      <AlertDialogContent>
                        <AlertDialogTitle>
                          Delete bucket {selectedBucket.bucket.name}?
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                          Deletion succeeds only after all contained objects are
                          removed.
                        </AlertDialogDescription>
                        <Inline gap="2" align="center">
                          <AlertDialogAction asChild>
                            <Button
                              onPress={() =>
                                handleDeleteBucket(selectedBucket.bucket.name)
                              }
                              disabled={bucketBusy()}
                            >
                              Confirm delete
                            </Button>
                          </AlertDialogAction>
                          <AlertDialogCancel asChild>
                            <Button variant="secondary">Cancel</Button>
                          </AlertDialogCancel>
                        </Inline>
                      </AlertDialogContent>
                    </AlertDialogPortal>
                  </AlertDialog>

                  <BucketControlPlaneSection
                    bucketName={selectedBucket.bucket.name}
                  />
                </Stack>
              ) : (
                <EmptyState
                  icon={<AlertCircleIcon size={24} aria-hidden="true" />}
                  title="Loading bucket"
                  description="The selected bucket is being loaded from the admin API."
                />
              )
            ) : (
              <EmptyState
                icon={<AlertCircleIcon size={24} aria-hidden="true" />}
                title="Select a bucket"
                description="Choose a bucket from the list on the left to browse its objects and upload content."
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Objects</CardTitle>
            <CardDescription>
              Upload files, inspect object metadata, download content, and
              remove blobs.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {selectedBucketName ? (
              <Stack gap="4">
                <form
                  onSubmit={(event: Event) => {
                    event.preventDefault();
                    void handleUploadObject();
                  }}
                >
                  <Stack gap="3">
                    <Field>
                      <label for="object-key">Object key</label>
                      <Input
                        id="object-key"
                        value={objectKey()}
                        onInput={(event: Event) =>
                          setObjectKey(
                            (event.currentTarget as HTMLInputElement).value
                          )
                        }
                        disabled={objectBusy()}
                        placeholder="docs/readme.txt"
                      />
                    </Field>
                    <Field>
                      <label for="object-file">File</label>
                      <Input
                        id="object-file"
                        type="file"
                        disabled={objectBusy()}
                        onInput={(event: Event) => {
                          const file =
                            (event.currentTarget as HTMLInputElement)
                              .files?.[0] ?? null;
                          setSelectedFile(file);

                          if (file && !objectKey().trim()) {
                            setObjectKey(file.name);
                          }
                        }}
                      />
                      <FieldHint>
                        Uploading replaces the content stored at the object key.
                      </FieldHint>
                    </Field>
                    <Field>
                      <label for="object-metadata">Custom metadata</label>
                      <textarea
                        id="object-metadata"
                        value={uploadMetadata()}
                        onInput={(event: Event) =>
                          setUploadMetadata(
                            (event.currentTarget as HTMLTextAreaElement).value
                          )
                        }
                        disabled={objectBusy()}
                        placeholder={'owner=alice\npurpose=docs'}
                        rows={3}
                      />
                      <FieldHint>
                        One key=value pair per line is sent as x-amz-meta upload
                        headers.
                      </FieldHint>
                    </Field>
                    {objectError() ? (
                      <p role="alert" class="form-error">
                        {objectError()}
                      </p>
                    ) : null}
                    <Button
                      type="submit"
                      onPress={() => void handleUploadObject()}
                      disabled={objectBusy()}
                    >
                      {objectBusy() ? 'Uploading...' : 'Upload object'}
                    </Button>
                  </Stack>
                </form>

                <Field>
                  <label for="object-search">Search objects</label>
                  <Input
                    id="object-search"
                    value={objectSearch()}
                    onInput={(event: Event) => {
                      setObjectNext(undefined);
                      setObjectSearch(
                        (event.currentTarget as HTMLInputElement).value
                      );
                    }}
                    disabled={objectBusy()}
                    placeholder="Filter by object key"
                  />
                </Field>

                <div class="run-table-wrap">
                  <table class="run-table">
                    <thead>
                      <tr>
                        <th>Object</th>
                        <th>Size</th>
                        <th>Type</th>
                        <th>Updated</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {objectList?.items.map((object) => (
                        <tr key={object.key}>
                          <td>
                            <strong>{object.key}</strong>
                            <span>{object.etag}</span>
                          </td>
                          <td>{formatBytes(object.size)}</td>
                          <td>
                            {object.content_type ?? 'application/octet-stream'}
                          </td>
                          <td>{formatRelativeTime(object.last_modified)}</td>
                          <td>
                            <Inline
                              gap="2"
                              align="center"
                              justify="end"
                              wrap="wrap"
                            >
                              <Button variant="secondary" asChild>
                                <Link
                                  href={bucketHref(
                                    selectedBucketName,
                                    object.key
                                  )}
                                >
                                  Inspect
                                </Link>
                              </Button>
                              <Button
                                variant="secondary"
                                onPress={() => handleDownloadObject(object.key)}
                                disabled={objectBusy()}
                              >
                                Download
                              </Button>
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="secondary"
                                    disabled={objectBusy()}
                                  >
                                    Delete
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogPortal>
                                  <AlertDialogOverlay />
                                  <AlertDialogContent>
                                    <AlertDialogTitle>
                                      Delete object {object.key}?
                                    </AlertDialogTitle>
                                    <AlertDialogDescription>
                                      This removes the latest object content.
                                    </AlertDialogDescription>
                                    <Inline gap="2" align="center">
                                      <AlertDialogAction asChild>
                                        <Button
                                          onPress={() =>
                                            handleDeleteObject(object.key)
                                          }
                                          disabled={objectBusy()}
                                        >
                                          Confirm delete
                                        </Button>
                                      </AlertDialogAction>
                                      <AlertDialogCancel asChild>
                                        <Button variant="secondary">
                                          Cancel
                                        </Button>
                                      </AlertDialogCancel>
                                    </Inline>
                                  </AlertDialogContent>
                                </AlertDialogPortal>
                              </AlertDialog>
                            </Inline>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {objectList?.next ? (
                  <Button
                    variant="secondary"
                    onPress={() => setObjectNext(objectList.next ?? undefined)}
                    disabled={objectBusy()}
                  >
                    Next object page
                  </Button>
                ) : null}
                {objectNext() ? (
                  <Button
                    variant="secondary"
                    onPress={() => setObjectNext(undefined)}
                    disabled={objectBusy()}
                  >
                    First object page
                  </Button>
                ) : null}
              </Stack>
            ) : (
              <EmptyState
                icon={<AlertCircleIcon size={24} aria-hidden="true" />}
                title="No bucket selected"
                description="Open a bucket from the browser on the left to inspect and edit its objects."
              />
            )}
          </CardContent>
        </Card>
      </Block>

      {selectedBucketName && selectedObjectKey ? (
        <Block size="lg" gap="4" align="stretch" class="operations-grid">
          <Card>
            <CardHeader>
              <CardTitle>Object metadata</CardTitle>
              <CardDescription>{selectedObjectKey}</CardDescription>
            </CardHeader>
            <CardContent>
              {metadata.value ? (
                <Stack gap="3">
                  <Badge>
                    type{' '}
                    {metadata.value.content_type ?? 'application/octet-stream'}
                  </Badge>
                  <Badge>size {formatBytes(metadata.value.size)}</Badge>
                  <Badge>etag {metadata.value.etag}</Badge>
                  <Badge>
                    version {metadata.value.version_id ?? 'unversioned'}
                  </Badge>
                  <h3>Custom metadata</h3>
                  {Object.entries(metadata.value.metadata).length ? (
                    Object.entries(metadata.value.metadata).map(
                      ([name, value]) => (
                        <div class="hero-row" key={name}>
                          <span>{name}</span>
                          <strong>{value}</strong>
                        </div>
                      )
                    )
                  ) : (
                    <p class="muted">No custom metadata recorded.</p>
                  )}
                </Stack>
              ) : metadata.pending ? (
                <p class="muted">Loading object metadata...</p>
              ) : (
                <p role="alert" class="form-error">
                  Object metadata could not be loaded.
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Object tags</CardTitle>
              <CardDescription>
                Replace the current tag set using key=value lines.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Stack gap="4">
                {tags.value && Object.entries(tags.value.tags).length ? (
                  Object.entries(tags.value.tags).map(([name, value]) => (
                    <div class="hero-row" key={name}>
                      <span>{name}</span>
                      <strong>{value}</strong>
                    </div>
                  ))
                ) : (
                  <p class="muted">No tags recorded.</p>
                )}
                <form
                  onSubmit={(event: Event) => {
                    event.preventDefault();
                    void handleSaveTags();
                  }}
                >
                  <Stack gap="3">
                    <Field>
                      <label for="object-tags">Replacement tags</label>
                      <textarea
                        id="object-tags"
                        value={tagsEditor()}
                        onInput={(event: Event) =>
                          setTagsEditor(
                            (event.currentTarget as HTMLTextAreaElement).value
                          )
                        }
                        rows={4}
                        placeholder={'env=dev\nowner=alice'}
                        disabled={objectBusy()}
                      />
                    </Field>
                    <Button
                      type="submit"
                      onPress={() => void handleSaveTags()}
                      disabled={objectBusy()}
                    >
                      Save tags
                    </Button>
                  </Stack>
                </form>
              </Stack>
            </CardContent>
          </Card>

          <ObjectAclSection
            bucketName={selectedBucketName}
            objectKey={selectedObjectKey}
          />

          <Card>
            <CardHeader>
              <CardTitle>Version history</CardTitle>
              <CardDescription>
                Paged versions returned for the selected object.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Stack gap="3">
                <div class="run-table-wrap">
                  <table class="run-table">
                    <thead>
                      <tr>
                        <th>Version</th>
                        <th>Latest</th>
                        <th>Size</th>
                        <th>Modified</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {versions.value?.items.map((version) => (
                        <tr key={version.version_id}>
                          <td>{version.version_id}</td>
                          <td>{version.is_latest ? 'yes' : 'no'}</td>
                          <td>{formatBytes(version.size)}</td>
                          <td>{formatRelativeTime(version.last_modified)}</td>
                          <td>
                            <Inline gap="2" align="center" justify="end" wrap="wrap">
                              <Button
                                variant="secondary"
                                onPress={() =>
                                  void handleDeleteVersion(version.version_id)
                                }
                                disabled={objectBusy()}
                              >
                                Delete
                              </Button>
                            </Inline>
                          </td>
                        </tr>
                      ))}
                      {!versions.pending &&
                      (versions.value?.items.length ?? 0) === 0 ? (
                        <tr>
                          <td colSpan={5}>No version history available.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                <Inline gap="2" align="center">
                  <Button
                    variant="secondary"
                    onPress={() => setVersionNext(undefined)}
                    disabled={!versionNext()}
                  >
                    First page
                  </Button>
                  <Button
                    variant="secondary"
                    onPress={() =>
                      setVersionNext(versions.value?.next ?? undefined)
                    }
                    disabled={!versions.value?.next}
                  >
                    Next page
                  </Button>
                </Inline>
              </Stack>
            </CardContent>
          </Card>
        </Block>
      ) : null}
    </Stack>
  );
}
