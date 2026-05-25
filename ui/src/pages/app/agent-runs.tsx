import { state } from '@askrjs/askr';
import { resource } from '@askrjs/askr/resources';
import { Link, navigate } from '@askrjs/askr/router';
import { AlertCircleIcon, RefreshCwIcon } from '@askrjs/lucide';
import { Input } from '@askrjs/ui';
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
  deleteObject,
  downloadObjectContent,
  putObjectContent,
  setBucketVersioning,
} from '../../adapters/blob-api';
import {
  loadBucket,
  loadBucketObjects,
  loadBuckets,
} from '../../features/buckets/buckets.query';
import { formatRelativeTime } from '../../shared/format';

function currentBucketName(): string {
  if (typeof window === 'undefined') {
    return '';
  }

  return new URLSearchParams(window.location.search).get('bucket') ?? '';
}

function bucketHref(bucketName: string): string {
  return `/app/buckets?bucket=${encodeURIComponent(bucketName)}`;
}

function matchesBucketSearch(bucketName: string, query: string): boolean {
  return bucketName.toLowerCase().includes(query.trim().toLowerCase());
}

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }

  const kib = size / 1024;
  if (kib < 1024) {
    return `${kib.toFixed(kib >= 10 ? 0 : 1)} KiB`;
  }

  const mib = kib / 1024;
  return `${mib.toFixed(mib >= 10 ? 0 : 1)} MiB`;
}

export default function BucketInventoryPage() {
  const [bucketSearch, setBucketSearch] = state('');
  const [newBucketName, setNewBucketName] = state('');
  const [objectSearch, setObjectSearch] = state('');
  const [objectKey, setObjectKey] = state('');
  const [selectedFile, setSelectedFile] = state<File | null>(null);
  const [bucketError, setBucketError] = state('');
  const [objectError, setObjectError] = state('');
  const [bucketBusy, setBucketBusy] = state(false);
  const [objectBusy, setObjectBusy] = state(false);

  const selectedBucketName = currentBucketName();

  const inventory = resource(({ signal }) => loadBuckets({ signal }), []);
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
            search: objectSearch().trim() || undefined,
            signal,
          })
        : Promise.resolve({ items: [], next: null }),
    [selectedBucketName, objectSearch()]
  );

  const snapshot = inventory.value;
  const selectedBucket = bucketDetail.value;
  const objectList = objects.value;
  const selectedBucketSummary = snapshot?.buckets.find(
    (bucket) => bucket.name === selectedBucketName
  );
  const filteredBuckets =
    snapshot?.buckets.filter((bucket) =>
      matchesBucketSearch(bucket.name, bucketSearch())
    ) ?? [];

  async function handleCreateBucket(event: Event) {
    event.preventDefault();

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

    if (!window.confirm(`Delete bucket ${bucketName}?`)) {
      return;
    }

    setBucketBusy(true);
    setBucketError('');

    try {
      await deleteBucket({ bucketName });
      inventory.refresh();

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

  async function handleUploadObject(event: Event) {
    event.preventDefault();

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
      });
      setSelectedFile(null);
      setObjectKey('');
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

    if (!window.confirm(`Delete object ${objectKeyValue}?`)) {
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

  if (snapshot && snapshot.totalBuckets === 0) {
    return (
      <Section>
        <EmptyState
          icon={<AlertCircleIcon size={24} aria-hidden="true" />}
          title="No buckets yet"
          description="Create a bucket through the admin API and the workbench will populate with live storage data."
          actions={<Button onPress={() => inventory.refresh()}>Refresh</Button>}
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
            <form onSubmit={handleCreateBucket}>
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
                <Button type="submit" disabled={bucketBusy()}>
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
                  onInput={(event: Event) =>
                    setBucketSearch(
                      (event.currentTarget as HTMLInputElement).value
                    )
                  }
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
                    {filteredBuckets.map((bucket) => {
                      const isSelected = bucket.name === selectedBucketName;

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
                          <td>{bucket.objectCount}</td>
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
                              <Button
                                variant="secondary"
                                onPress={() => handleDeleteBucket(bucket.name)}
                                disabled={bucketBusy()}
                              >
                                Delete
                              </Button>
                            </Inline>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
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

                  <Button
                    variant="secondary"
                    onPress={() =>
                      handleDeleteBucket(selectedBucket.bucket.name)
                    }
                    disabled={bucketBusy()}
                  >
                    Delete bucket
                  </Button>
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
                <form onSubmit={handleUploadObject}>
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
                    {objectError() ? (
                      <p role="alert" class="form-error">
                        {objectError()}
                      </p>
                    ) : null}
                    <Button type="submit" disabled={objectBusy()}>
                      {objectBusy() ? 'Uploading...' : 'Upload object'}
                    </Button>
                  </Stack>
                </form>

                <Field>
                  <label for="object-search">Search objects</label>
                  <Input
                    id="object-search"
                    value={objectSearch()}
                    onInput={(event: Event) =>
                      setObjectSearch(
                        (event.currentTarget as HTMLInputElement).value
                      )
                    }
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
                              <Button
                                variant="secondary"
                                onPress={() => handleDownloadObject(object.key)}
                                disabled={objectBusy()}
                              >
                                Download
                              </Button>
                              <Button
                                variant="secondary"
                                onPress={() => handleDeleteObject(object.key)}
                                disabled={objectBusy()}
                              >
                                Delete
                              </Button>
                            </Inline>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {objectList?.next ? (
                  <Badge>
                    More objects are available in the next page token.
                  </Badge>
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
    </Stack>
  );
}
