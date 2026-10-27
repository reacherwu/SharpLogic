# Stage 1: Build Native Rust #k-SAT & WMC Core Engine (libsharplogic_core.so)
FROM rust:1.82-slim AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# Stage 2: Minimal Production Python Runtime
FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /build/target/release/libsharplogic_core.so /app/target/release/libsharplogic_core.so
COPY python ./python
COPY web ./web
COPY api ./api
COPY server.py ./server.py

ENV HOST=0.0.0.0
ENV PORT=8765
EXPOSE 8765

CMD ["python3", "server.py"]
