FROM rust:1.67

WORKDIR /app
COPY ./ /app
RUN mkdir -p /app/logs

ENTRYPOINT ["./entrypoint.sh"]