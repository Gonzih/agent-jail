FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Build real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    iptables \
    criu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/agent-jail /app/agent-jail

ENV HOST=0.0.0.0
ENV PORT=8082
ENV DATA_DIR=/mnt/storage
ENV RUST_LOG=agent_jail=info,tower_http=info

EXPOSE 8082

CMD ["/app/agent-jail"]
