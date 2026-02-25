FROM rust:1.75 as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./ 

COPY src ./src

RUN cargo build --release


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/backend /usr/local/bin/backend

EXPOSE 3000

CMD ["backend"]
