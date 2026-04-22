#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/../password-manager" && pwd)"
PID_FILE="/tmp/password-manager.pid"
LOG_FILE="/tmp/password-manager.log"
STAMP_FILE="/tmp/password-manager.sha"

ensure_mysql_client() {
  bash "${SCRIPT_DIR}/install-mysql-client.sh"
}

wait_for_mysql() {
  local host="${DB_HOST:-mysql}"
  local port="${DB_PORT:-3306}"
  local user="${DB_USER:-root}"
  local password="${DB_PASSWORD:-rootpassword}"
  local attempt

  for attempt in $(seq 1 30); do
    if mysqladmin ping --host="${host}" --port="${port}" --user="${user}" --password="${password}" --silent >/dev/null 2>&1; then
      return
    fi

    sleep 2
  done

  echo "MySQL did not become ready in time." >&2
  exit 1
}

app_is_running() {
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if [ -n "${pid}" ] && kill -0 "${pid}" >/dev/null 2>&1; then
      return 0
    fi
    rm -f "${PID_FILE}"
  fi

  if pgrep -f "java .* Main" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

current_app_stamp() {
  (
    cd "${APP_DIR}"
    find . -maxdepth 2 \( -name "*.java" -o -path "./web/*" -o -name "run.sh" \) -type f -print0 |
      sort -z |
      xargs -0 sha256sum |
      sha256sum |
      awk '{print $1}'
  )
}

stop_app() {
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if [ -n "${pid}" ] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
    fi
    rm -f "${PID_FILE}"
  fi

  pkill -f "java .* Main" >/dev/null 2>&1 || true
}

compile_app() {
  (
    cd "${APP_DIR}"
    javac -cp ".:lib/mysql-connector-j-9.6.0.jar" *.java
  )
}

launch_app() {
  (
    cd "${APP_DIR}"
    nohup java -cp ".:lib/mysql-connector-j-9.6.0.jar" Main >"${LOG_FILE}" 2>&1 &
    echo $! > "${PID_FILE}"
  )
}

wait_for_app() {
  local attempt

  for attempt in $(seq 1 30); do
    if (echo > /dev/tcp/127.0.0.1/8080) >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  echo "Password Manager did not start successfully." >&2
  if [ -f "${LOG_FILE}" ]; then
    echo "Last application log lines:" >&2
    tail -n 20 "${LOG_FILE}" >&2
  fi
  exit 1
}

main() {
  ensure_mysql_client
  local stamp
  stamp="$(current_app_stamp)"

  if [ "${1:-}" = "--prepare-only" ]; then
    exit 0
  fi

  if app_is_running; then
    if [ -f "${STAMP_FILE}" ] && [ "$(cat "${STAMP_FILE}")" = "${stamp}" ]; then
      echo "Password Manager is already running at http://localhost:8080"
      exit 0
    fi

    echo "Password Manager code changed; restarting app."
    stop_app
  fi

  wait_for_mysql
  compile_app
  launch_app

  if [ "${1:-}" = "--background" ]; then
    echo "${stamp}" > "${STAMP_FILE}"
    echo "Password Manager startup requested in background. Check /tmp/password-manager.log if needed."
    exit 0
  fi

  wait_for_app
  echo "${stamp}" > "${STAMP_FILE}"

  echo "Password Manager is running at http://localhost:8080"
}

main "$@"
