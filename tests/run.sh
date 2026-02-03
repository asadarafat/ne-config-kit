#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$ROOT/requests.log"
CLI_LOG="$ROOT/cli_config.log"
NETCONF_LOG="$ROOT/netconf_config.log"

export ANSIBLE_COLLECTIONS_PATH="/tests:/usr/share/ansible/collections"
export PYTHONPATH="/tests${PYTHONPATH:+:${PYTHONPATH}}"

rm -f "$LOG_FILE" "$CLI_LOG" "$NETCONF_LOG"

# --------------------- HTTP API ---------------------
python "$ROOT/http_stub.py" \
  --port 8081 \
  --config "$ROOT/fixtures/running.conf" \
  --log "$LOG_FILE" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if curl -sSf http://127.0.0.1:8081/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

export NCK_CONFIG="$ROOT/nck-config-httpapi.yaml"

nck backup

if [[ ! -s "/backups/httpapi/testdevice/running.conf" ]]; then
  echo "HTTP API backup file missing" >&2
  exit 1
fi

diff -u "$ROOT/fixtures/running.conf" "/backups/httpapi/testdevice/running.conf"

nck audit
nck restore --check
nck restore

if [[ ! -s "$LOG_FILE" ]]; then
  echo "No HTTP requests captured" >&2
  exit 1
fi

if ! grep -q "jsonrpc" "$LOG_FILE"; then
  echo "Expected JSON-RPC payload not seen" >&2
  exit 1
fi

# ----------------------- SCP ------------------------
SSH_PORT=2222

# Ensure ansible user has a password and sshd is running with test config
if ! id ansible >/dev/null 2>&1; then
  useradd -m ansible
fi

echo "ansible:ansible" | chpasswd

cat > /tmp/sshd_test_config <<SSHD
Port ${SSH_PORT}
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
PermitRootLogin no
UsePAM no
AllowUsers ansible
Subsystem sftp /usr/lib/openssh/sftp-server
SSHD

/usr/sbin/sshd -f /tmp/sshd_test_config -E /tmp/sshd_test.log

if ! ss -ltn 2>/dev/null | grep -q ":${SSH_PORT}"; then
  echo "sshd failed to listen on ${SSH_PORT}" >&2
  cat /tmp/sshd_test.log >&2 || true
  exit 1
fi

cp "$ROOT/fixtures/running.conf" /tmp/srsim.conf
chown ansible:ansible /tmp/srsim.conf

export NCK_CONFIG="$ROOT/nck-config-scp.yaml"

nck backup

diff -u "$ROOT/fixtures/running.conf" "/backups/scp/testdevice/running.conf"

printf "%s\n" "set / system name updated" > /backups/scp/testdevice/running.conf

nck restore --check
nck restore

if ! diff -u /backups/scp/testdevice/running.conf /tmp/srsim.conf; then
  echo "SCP restore did not update remote file" >&2
  exit 1
fi

# ------------------------ CLI -----------------------
export MOCK_CLI_FILE="$ROOT/fixtures/running.conf"
export CLI_CONFIG_LOG="$CLI_LOG"
export NCK_CONFIG="$ROOT/nck-config-cli.yaml"

nck backup

diff -u "$ROOT/fixtures/running.conf" "/backups/cli/testdevice/running.conf"

nck restore --check
nck restore

if [[ ! -s "$CLI_LOG" ]]; then
  echo "CLI restore log missing" >&2
  exit 1
fi

# ---------------------- NETCONF ---------------------
export MOCK_NETCONF_FILE="$ROOT/fixtures/running.conf"
export NETCONF_CONFIG_LOG="$NETCONF_LOG"
export NCK_CONFIG="$ROOT/nck-config-netconf.yaml"

nck backup

diff -u "$ROOT/fixtures/running.conf" "/backups/netconf/testdevice/running.conf"

nck restore --check
nck restore

if [[ ! -s "$NETCONF_LOG" ]]; then
  echo "NETCONF restore log missing" >&2
  exit 1
fi

echo "Regression tests passed."
