# Build UI
FROM node:22-alpine as ui-builder

WORKDIR /ui

# Copy UI package files
COPY ui/package*.json ./

# Install dependencies
RUN npm ci

# Copy UI source
COPY ui/ ./

# Build UI
RUN npm run build

# Build Rust backend
FROM rust:latest as rust-builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Final stage - use distroless (minimal with libc, ca-certs, tzdata)
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copy the Rust binary from builder
COPY --from=rust-builder /app/target/release/wasabi-emulator /app/wasabi-emulator

# Copy the built UI from ui-builder
COPY --from=ui-builder /ui/dist /app/static

# Create blobs directory for filesystem storage
RUN mkdir -p /app/blobs

# Environment variables
ENV BLOBS_PATH=/app/blobs

# Expose both S3 API and UI ports
EXPOSE 9000 9001

# Set the entrypoint
ENTRYPOINT ["/app/wasabi-emulator"]
