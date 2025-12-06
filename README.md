# Wasabi S3 Emulator

An S3-compliant emulator designed to emulate Wasabi's object storage implementation. This emulator provides a local development environment for testing S3 applications against Wasabi's specific API behavior and features.

## Features

- S3-compliant API
- Wasabi-specific implementation details
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
docker build -t sqrzl/wasabi-emulator .
```

### Run the container

```bash
docker run sqrzl/wasabi-emulator
```

### Using Docker Compose

```bash
docker compose up --build
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
