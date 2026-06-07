# PEAS Emulator

PEAS is a local object and blob storage emulator for development, CI, and
compatibility testing.

It runs a shared filesystem-backed storage core behind provider-compatible API
endpoints for S3-compatible APIs, Azure Blob Storage, Google Cloud Storage, and
OCI Object Storage. Use PEAS when you want one local process for common bucket,
container, object, and blob workflows without provisioning cloud resources.

PEAS also includes a versioned admin API and a small Askr admin UI for browsing
buckets, navigating folder-like blob keys, uploading and deleting blobs, viewing
metadata, and downloading content.

## Features

- S3-compatible, Azure Blob Storage, Google Cloud Storage, and OCI Object Storage
  API endpoints
- Shared filesystem-backed storage core
- Bucket/container and object/blob CRUD workflows
- Object listing, range reads, metadata, tags, and version-oriented workflows
  where supported
- Multipart, block, resumable, and provider-compatible upload flows
- Provider-compatible request signing and auth validation for supported SDK flows
- Admin API and Askr admin UI for local inspection and basic storage operations
- Docker-ready local development and CI support

## Current Scope

- PEAS exposes native API endpoints for S3-compatible APIs, Azure Blob Storage,
  Google Cloud Storage, and OCI Object Storage on top of one local storage core.
- The checked compatibility matrix marks each operation as `certified`,
  `partial`, `unsupported`, or `deferred`.
- The SDK certification harness exercises official Python SDK clients for S3,
  Azure Blob Storage, Google Cloud Storage, and OCI Object Storage.
- Support certification details, known limitations, and issue-triage guidance
  live in `docs/support-certification.md`.

## Known Gaps

- PEAS targets object/blob storage workflows, not every surrounding cloud
  control-plane feature.
- Certification does not mean full production cloud parity. Check
  `compatibility-matrix.json` for operation-level support.
- Lifecycle execution, advanced ACL/policy behavior, copy conditionals, and some
  edge-case semantics are intentionally narrower than production cloud services.

## Building

```bash
cargo build --release
```

## Running Locally

```bash
cargo run
```

If you set `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY`, the storage endpoints
enforce auth. The admin API at `/admin/v1` will also require auth using those
same values. The browser UI exchanges them for an HttpOnly admin session cookie.

If you want to keep the admin API open for local development while still
enforcing provider auth, set `ADMIN_AUTH_DISABLED=true`.

Set `MAX_REQUEST_BYTES` to cap buffered request bodies before streaming support is
certified. Oversized uploads return provider-compatible `413 Payload Too Large`
responses.

Both the API and UI ports expose a support health endpoint:

```bash
curl http://127.0.0.1:9000/healthz
curl http://127.0.0.1:9001/healthz
```

## SDK Certification

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[sdk-tests]"
python -m pytest
```

To run against an existing PEAS process:

```bash
PEAS_API_URL=http://127.0.0.1:9000 python -m pytest
```

## Admin API Contract

The versioned OpenAPI 3.1 contract for the admin storage API lives at
`public/openapi.yml`.

The contract targets the `/admin/v1` surface for session inspection, bucket
lifecycle and versioning, object browsing, binary upload/download, metadata,
tags, and version listing. It is intentionally separate from the
protocol-compatible storage endpoints.

## Admin UI

The Askr-based UI lives in `ui/`. It uses `@fgrzl/fetch` with the client
generated from `public/openapi.yml`; `ui/src/adapters/api.g.ts` is the only
endpoint transport surface.

```bash
cd ui
npm install
npm run gen
npm run type-check
npm test
npm run lint
npm run build
```

Node 24 or newer is required. The console supports login/logout, bucket search,
bucket create/delete, folder-like bucket browsing, blob upload/delete, blob
details, and blob download.

## Docker

### Build the Docker image

```bash
docker build -t sqrzl/peas-emulator .
```

### Run the container

```bash
docker run sqrzl/peas-emulator
```

### Using Docker Compose

```bash
docker compose up --build
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
