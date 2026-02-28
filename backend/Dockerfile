FROM rust:latest as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./ 

COPY src ./src

RUN cargo build --release


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/influx-backend /usr/local/bin/influx-backend

EXPOSE 3000

CMD ["influx-backend"]
