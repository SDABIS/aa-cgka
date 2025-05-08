FROM rust:1.67

WORKDIR /app
COPY ./ /app

ENV RUST_LOG=debug
CMD ["./mls-ds", "-p", "8080", "-m"]