# Peas Emulator

An S3-compliant emulator with Wasabi API compatibility. This emulator provides a local development environment for testing S3 applications with full support for versioning, multipart uploads, lifecycle policies, and more.

## Features

- S3-compliant API with Wasabi compatibility
- Object versioning and lifecycle management
- Docker deployment ready
- Local development support

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
