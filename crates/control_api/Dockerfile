# Build stage
FROM rust:1.85-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy Cargo files first for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Copy only the required crates directories
COPY crates/proto crates/proto
COPY crates/net crates/net
COPY crates/server crates/server
COPY crates/resolver crates/resolver
COPY crates/geodns crates/geodns
COPY crates/control_api crates/control_api
COPY crates/agent crates/agent
COPY bin bin
COPY util util

# Remove test packages from workspace
RUN sed -i 's/"tests\/integration-tests",//g' Cargo.toml && \
    sed -i 's/"tests\/test-support",//g' Cargo.toml

# Also patch all crates to remove test-support dev dependency
RUN for crate in crates/proto crates/net crates/server crates/resolver bin; do \
    if [ -f "$crate/Cargo.toml" ]; then \
        sed -i '/test-support.workspace = true/d' $crate/Cargo.toml; \
    fi \
    done

# Build the control_api
RUN cargo build --release -p control_api

# Production stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r app && useradd -r -g app app

# Copy binary from builder
COPY --from=builder /build/target/release/control_api /usr/local/bin/control_api

# Set ownership
RUN chown app:app /usr/local/bin/control_api

# Switch to non-root user
USER app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/usr/local/bin/control_api"]
