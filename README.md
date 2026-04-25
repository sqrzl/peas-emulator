# Peas Emulator

A multi-provider blob and object storage emulator for local development and compatibility testing. Peas currently exposes native front doors for S3-compatible clients, Azure Blob Storage, Google Cloud Storage, and OCI Object Storage on top of a shared filesystem-backed blob core.

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
- The checked compatibility matrix is fully green for the in-scope operations shipped by this repo.
- The interop harness exercises official/common SDK paths for S3, Azure, GCS, and OCI.

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
The admin API at `/admin/v1` will also require HTTP Basic auth using those same values.

If you want to keep the admin API open for local development while still enforcing provider
auth, set `ADMIN_AUTH_DISABLED=true`.

## Admin API Contract

The versioned OpenAPI 3.1 contract for the admin storage API lives at
`docs/openapi/admin-v1.yaml`.

The initial contract targets the `/admin/v1` surface for local storage
administration workflows such as bucket browsing, object inspection, content
upload and download, version listing, and tag management. It is intentionally
separate from the protocol-compatibility front doors.

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
