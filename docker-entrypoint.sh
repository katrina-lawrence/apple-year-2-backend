#!/bin/sh
set -eu

APP_MODULE="${UVICORN_APP:-app.main:app}"
HOST="${UVICORN_HOST:-0.0.0.0}"
PORT="${UVICORN_PORT:-8000}"

if [ -n "${TLS_CERT_FILE:-}" ] || [ -n "${TLS_KEY_FILE:-}" ]; then
  if [ -z "${TLS_CERT_FILE:-}" ] || [ -z "${TLS_KEY_FILE:-}" ]; then
    echo "Both TLS_CERT_FILE and TLS_KEY_FILE must be set for HTTPS startup." >&2
    exit 1
  fi

  exec uvicorn "$APP_MODULE" \
    --host "$HOST" \
    --port "$PORT" \
    --ssl-certfile "$TLS_CERT_FILE" \
    --ssl-keyfile "$TLS_KEY_FILE"
fi

exec uvicorn "$APP_MODULE" --host "$HOST" --port "$PORT"
