# Build UI
FROM node:slim AS frontend

WORKDIR /ui

# Copy UI package files
COPY ui/package*.json ./

# Install dependencies
RUN npm install

# Copy UI source
COPY ui/ ./

# Build UI
RUN npm run build

# Build Rust backend
FROM rust:latest AS backend

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
COPY --from=backend /app/target/release/peas-emulator /app/peas-emulator

# Copy the built UI from ui-builder
COPY --from=frontend /ui/dist /app/static

# Expose both S3 API and UI ports
EXPOSE 9000 9001

# Set the entrypoint
ENTRYPOINT ["/app/peas-emulator"]
