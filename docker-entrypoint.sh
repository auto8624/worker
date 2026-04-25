#!/bin/sh
set -eu

mkdir -p /app/data
chown -R app:app /app/data
chmod 750 /app/data

run_as_app() {
  if command -v runuser >/dev/null 2>&1; then
    exec runuser -u app -- "$@"
  fi
  exec su app -s /bin/sh -c "exec \"$@\"" -- "$@"
}

run_as_app "$@"
