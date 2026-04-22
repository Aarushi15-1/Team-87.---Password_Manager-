#!/usr/bin/env bash
set -euo pipefail

if command -v mysql >/dev/null 2>&1 && command -v mysqladmin >/dev/null 2>&1; then
  exit 0
fi

sudo apt-get update
sudo apt-get install -y mariadb-client

if [ -x /usr/bin/mariadb ]; then
  sudo ln -sf /usr/bin/mariadb /usr/local/bin/mysql
fi
