#!/usr/bin/env bash
# Start a local DVWA instance on Kali/Linux without Docker.
# Requires: php-cli + php-mysql, mariadb, curl, unzip.
set -euo pipefail

BASE=/tmp/aimy-dvwa
SRC_DIR=$BASE/src
DB_DIR=$BASE/db
DB_SOCKET=$BASE/mysql.sock
DB_PORT=3307
WEB_PORT=8081
DVWA_ZIP=$BASE/dvwa.zip

mkdir -p "$BASE" "$SRC_DIR"

if [ ! -d "$SRC_DIR"/DVWA-* ]; then
  if [ ! -f "$DVWA_ZIP" ]; then
    curl -L -o "$DVWA_ZIP" https://codeload.github.com/digininja/DVWA/zip/refs/heads/master
  fi
  unzip -oq "$DVWA_ZIP" -d "$SRC_DIR"
fi
DVWA_ROOT=$(find "$SRC_DIR" -mindepth 1 -maxdepth 1 -type d -name 'DVWA-*' | head -1)
if [ -z "$DVWA_ROOT" ]; then
  echo "DVWA source not found" >&2
  exit 1
fi

if [ ! -d "$DB_DIR/mysql" ]; then
  mariadb-install-db --datadir="$DB_DIR" --auth-root-authentication-method=normal \
    --skip-test-db >"$BASE/db-init.log" 2>&1
fi

if ! mysqladmin --socket="$DB_SOCKET" -uroot ping >/dev/null 2>&1; then
  setsid mariadbd --datadir="$DB_DIR" --socket="$DB_SOCKET" --port="$DB_PORT" \
    --bind-address=127.0.0.1 --pid-file="$BASE/mysql.pid" \
    --log-error="$BASE/mysql.log" </dev/null >/dev/null 2>&1 &
fi

for _ in $(seq 1 30); do
  if mysqladmin --socket="$DB_SOCKET" -uroot ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! mysqladmin --socket="$DB_SOCKET" -uroot ping >/dev/null 2>&1; then
  echo "MariaDB failed to start; see $BASE/mysql.log" >&2
  exit 1
fi

mysql --socket="$DB_SOCKET" -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL ON dvwa.* TO 'dvwa'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

if [ ! -f "$DVWA_ROOT/config/config.inc.php" ]; then
  cp "$DVWA_ROOT/config/config.inc.php.dist" "$DVWA_ROOT/config/config.inc.php"
fi

if ! curl -s -m 2 "http://127.0.0.1:$WEB_PORT/login.php" >/dev/null; then
  cd "$DVWA_ROOT"
  DB_SERVER=127.0.0.1 DB_PORT="$DB_PORT" DB_DATABASE=dvwa DB_USER=dvwa DB_PASSWORD='p@ssw0rd' \
    setsid php -S "0.0.0.0:$WEB_PORT" -t "$DVWA_ROOT" </dev/null >"$BASE/php.log" 2>&1 &
  echo $! >"$BASE/php.pid"
  sleep 2
fi

printf 'DVWA: http://127.0.0.1:%s/ (admin/password)\n' "$WEB_PORT"
printf 'Logs: %s/php.log %s/mysql.log\n' "$BASE" "$BASE"
printf 'Stop: kill $(cat %s/php.pid); kill $(cat %s/mysql.pid)\n' "$BASE" "$BASE"
