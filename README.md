# Peas Emulator

An S3-compliant emulator with Wasabi API compatibility. This emulator provides a local development environment for testing S3 applications with support for versioning, multipart uploads, lifecycle policies, and other core S3 workflows.

## Features

- S3-compliant API with Wasabi compatibility
- Object versioning and lifecycle management
- Docker deployment ready
- Local development support

## Limitations

- Lifecycle rules are stored and executed for supported transitions and expirations, but full rule enforcement is still partial.
- Advanced copy semantics such as conditional requests and full range handling are not complete.
- ACLs and bucket/object policies are simplified.
- Requester pays, CORS, server-side encryption, website hosting, and object lock are not implemented.

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
