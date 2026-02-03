FROM rust:1-slim-bookworm AS builder
WORKDIR /usr/src
COPY . /usr/src/
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p control_api --manifest-path /usr/src/Cargo.toml

FROM debian:bookworm-slim
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=builder /usr/src/target/release/control_api /usr/local/bin/control_api
RUN chown app:app /usr/local/bin/control_api
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control_api"]
