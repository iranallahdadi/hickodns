FROM rust:1.71-slim-bullseye AS builder
WORKDIR /usr/src/control_api
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bullseye-slim
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=builder /usr/src/control_api/target/release/control_api /usr/local/bin/control_api
RUN chown app:app /usr/local/bin/control_api
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control_api"]
