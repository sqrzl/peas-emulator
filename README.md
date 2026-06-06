# Peas Emulator

A multi-provider blob and object storage emulator for local development and compatibility testing. With the simple admin UI, Peas becomes a valuable asset for developing cloud-native solutions without fully provisioning or locking into a cloud vendor. The companion client libraries, such as peas-go, normalize the blob storage API surface so application development stays behind one unified storage interface, making it easier to target a cloud vendor today and switch vendors later with zero friction. Peas currently exposes native front doors for S3-compatible clients, Azure Blob Storage, Google Cloud Storage, and OCI Object Storage on top of a shared filesystem-backed blob core.

## Features

- Provider adapters for:
  - S3-compatible workflows, including AWS-style clients plus MinIO/Wasabi/Backblaze-S3-oriented behavior
  - Azure Blob Storage workflows
  - Google Cloud Storage workflows
  - OCI Object Storage workflows
- Shared filesystem-backed blob core
- S3-focused versioning, multipart upload, lifecycle, tagging, ACL, policy, requester-pays, website, CORS, browser-style POST upload, SSE request-contracts, and object-lock retention/legal-hold enforcement
- Azure block blob, append blob, and page blob upload flows with Shared Key and SAS validation, lease management, snapshots, and immutability/legal-hold enforcement
- GCS XML/JSON API object workflows, signed URL, and resumable upload flow support
- OCI namespace, bucket, object, multipart, and request-signing support
- Docker deployment ready
- Local development support

## Current Scope

- Peas exposes native front doors for S3, Azure Blob Storage, GCS, and OCI on top of a shared filesystem-backed blob core.
- The checked compatibility matrix marks each operation as `certified`, `partial`, `unsupported`, or `deferred`.
- The SDK certification harness exercises official Python SDK clients for S3, Azure Blob, GCS, and OCI.
- Support certification details, known limitations, and issue-triage guidance live in `docs/support-certification.md`.

## Known Gaps

- Lifecycle configurations are stored and returned, but rule enforcement remains incomplete compared with production providers.
- ACL and policy behavior now covers common bucket/object workflows, but advanced semantics still remain simplified compared with production providers.
- Some advanced request semantics, especially around copy conditionals and edge-case parity, remain intentionally narrower than full cloud implementations.
- Peas targets object/blob storage compatibility workflows rather than every surrounding cloud control-plane feature.

## Building

```bash
cargo build --release
```

## Running Locally

```bash
cargo run
```

If you set `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY`, the storage front doors enforce auth.
The admin API at `/admin/v1` will also require auth using those same values. The
browser UI exchanges them for an HttpOnly admin session cookie.

If you want to keep the admin API open for local development while still enforcing provider
auth, set `ADMIN_AUTH_DISABLED=true`.

Set `MAX_REQUEST_BYTES` to cap buffered request bodies before streaming support is
certified. Oversized uploads return provider-shaped `413 Payload Too Large`
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
protocol-compatibility front doors.

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

Node 24 or newer is required. The console currently supports a simple admin
flow: login/logout, a bucket table with add-bucket modal, a bucket blob table
with add-blob upload modal, and a blob details page.

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
