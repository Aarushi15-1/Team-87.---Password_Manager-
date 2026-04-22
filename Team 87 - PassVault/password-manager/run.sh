#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

JAR="lib/mysql-connector-j-9.6.0.jar"

if [ ! -f "$JAR" ]; then
  echo "Missing MySQL JDBC driver: $JAR"
  exit 1
fi

if command -v pkill >/dev/null 2>&1; then
  pkill -f "java -cp .*Main" >/dev/null 2>&1 || true
fi

javac -cp ".:$JAR" *.java
java -cp ".:$JAR" Main
