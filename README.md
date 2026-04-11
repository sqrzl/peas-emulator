# Peas Emulator

A multi-provider blob and object storage emulator for local development and compatibility testing. Peas currently exposes native front doors for S3-compatible clients, Azure Blob Storage, Google Cloud Storage, and OCI Object Storage on top of a shared filesystem-backed blob core.

## Features

- Provider adapters for:
  - S3-compatible workflows, including AWS-style clients plus MinIO/Wasabi/Backblaze-S3-oriented behavior
  - Azure Blob Storage workflows
  - Google Cloud Storage workflows
  - OCI Object Storage workflows
- Shared filesystem-backed blob core
- S3-focused versioning, multipart upload, lifecycle, tagging, ACL, and policy support
- Azure block blob upload flow with Shared Key and SAS validation
- GCS signed URL and resumable upload flow support
- OCI namespace, bucket, object, and request-signing support
- Docker deployment ready
- Local development support

## Current Scope

- The project now has a multi-provider architecture, but SDK-grade parity is still in progress.
- S3 is the deepest implementation today and includes the most complete behavior set.
- Azure, GCS, and OCI support currently focus on core container/bucket/blob/object workflows, auth, listing, and upload paths rather than full platform coverage.

## Known Gaps

- Full SDK and CLI interoperability matrices against official external clients are not yet wired into CI.
- Advanced S3 features such as requester pays, website hosting, object lock, and the full SSE/CORS/admin surface are still deferred.
- Azure append blobs, page blobs, leases, and immutability features are deferred.
- GCS JSON API breadth is still partial; the current implementation focuses on XML-style object workflows plus resumable upload.
- OCI multipart and advanced policy/retention behavior are still partial.
- Lifecycle enforcement, ACLs, and policy behavior remain simplified compared with production cloud providers.

## Building

```bash
cargo build --release
```

## Running Locally

```bash
cargo run
```

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
