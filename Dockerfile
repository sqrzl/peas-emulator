# Build UI
FROM node:latest as ui-builder

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

# Create blobs directory structure
RUN mkdir -p /tmp/blobs

# Final stage - use distroless (minimal with libc, ca-certs, tzdata)
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copy the Rust binary from builder
COPY --from=rust-builder /app/target/release/peas-emulator /app/peas-emulator

# Copy the built UI from ui-builder
COPY --from=ui-builder /ui/dist /app/static

# Copy blobs directory from rust-builder (created with shell available)
COPY --from=rust-builder /tmp/blobs /app/blobs

# Environment variables
ENV BLOBS_PATH=/app/blobs
ENV ACCESS_KEY_ID=peas
ENV SECRET_ACCESS_KEY=peas

# Expose both S3 API and UI ports
EXPOSE 9000 9001

# Set the entrypoint
ENTRYPOINT ["/app/peas-emulator"]
