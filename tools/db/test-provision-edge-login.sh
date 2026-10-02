#!/usr/bin/env bash
# tools/db/test-provision-edge-login.sh
#
# Proof for tools/db/provision-edge-login.sh (edge-role PR1b, gate finding M1): the script sends the server a
# SCRAM-SHA-256 VERIFIER, never the plaintext password, so a failing `ALTER ROLE` that the server logs in full
# (log_min_error_statement = error) cannot leak the secret.
#
# What this proves, against the live throwaway cluster tools/db/test.sh built:
#   1. the verifier is a VALID one: edge_gateway logs in with the plaintext over a REAL SCRAM-SHA-256 handshake
#      (a temporary pg_hba rule forces `scram-sha-256` for that role; the harness itself is otherwise `trust`),
#      a wrong password and a missing password are refused;
#   2. a FAILED provisioning (run as a role that lacks CREATEROLE) exits non-zero, the server DID log the failing
#      statement (control), and the log contains NO trace of the plaintext;
#   3. the CONTROL for (2): the old behaviour -- `ALTER ROLE ... PASSWORD '<plaintext>'` sent as text -- run by the
#      same unprivileged role leaks the plaintext into the same log. Without this, (2) could pass because the
#      statement was never logged at all.
#
# Usage (tools/db/test.sh calls it, as the postgres OS user, right after the provisioning step):
#   PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=... PGDATA=... PG_LOG=... PATH="$PG_BIN_DIR:$PATH" \
#     bash tools/db/test-provision-edge-login.sh
# PGDATA is the cluster directory (its pg_hba.conf is edited and restored); PG_LOG is the server log file.
#
# Leaves edge_gateway LOGIN with the final throwaway password (the cluster auth is `trust` again afterwards).

set -euo pipefail

: "${PGHOST:?PGHOST is required}" "${PGPORT:?PGPORT is required}" "${PGDATABASE:?PGDATABASE is required}"
: "${PGDATA:?PGDATA is required}" "${PG_LOG:?PG_LOG is required}"
PGUSER="${PGUSER:-postgres}"
export PGHOST PGPORT PGDATABASE PGUSER
export PGOPTIONS="${PGOPTIONS:-} -c client_min_messages=warning"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HBA="$PGDATA/pg_hba.conf"
HBA_BACKUP="$(mktemp "${TMPDIR:-/tmp}/pg_hba.edge-login.XXXXXX")"
SCRATCH_ROLE="zz_edge_prov_nopriv"
fail() { echo "tools/db/test-provision-edge-login.sh: FAILED -- $*" >&2; exit 1; }
rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
sql() { psql -X -q -At -v ON_ERROR_STOP=1 -c "$1"; }

cp "$HBA" "$HBA_BACKUP"
restore() {
  cp "$HBA_BACKUP" "$HBA" 2>/dev/null || true
  rm -f "$HBA_BACKUP"
  psql -X -q -At -c "SELECT pg_reload_conf()" >/dev/null 2>&1 || true
  psql -X -q -At -c "DROP ROLE IF EXISTS $SCRATCH_ROLE" >/dev/null 2>&1 || true
}
trap restore EXIT

# Make the logging assumption explicit rather than relying on the default.
sql "ALTER SYSTEM SET log_min_error_statement = 'error'" >/dev/null
sql "SELECT pg_reload_conf()" >/dev/null

# ---------------------------------------------------------------------------
# 1. The verifier is valid: a real SCRAM-SHA-256 login with the plaintext.
# ---------------------------------------------------------------------------
PW="$(rand 24)"
printf '%s\n' "$PW" | bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-stdin >/dev/null

{ echo "local all edge_gateway scram-sha-256"; cat "$HBA_BACKUP"; } > "$HBA"
sql "SELECT pg_reload_conf()" >/dev/null
sleep 0.5

login() { PGPASSWORD="$1" PGCONNECT_TIMEOUT=5 psql -X -q -At -w -U edge_gateway -c "SELECT current_user" 2>/dev/null; }
if [ "$(login "$PW")" != "edge_gateway" ]; then
  fail "edge_gateway cannot log in with the plaintext over SCRAM-SHA-256 (the client-computed verifier is not valid)"
fi
if login "${PW}x" >/dev/null; then
  fail "edge_gateway logged in with a WRONG password (the rule was not scram-sha-256, or the verifier is not the password's)"
fi
if PGCONNECT_TIMEOUT=5 psql -X -q -At -w -U edge_gateway -c "SELECT 1" >/dev/null 2>&1; then
  fail "edge_gateway logged in with NO password (the pg_hba scram rule is not in force: the proof above would be vacuous)"
fi
echo "tools/db/test-provision-edge-login.sh: OK -- a real SCRAM-SHA-256 login with the plaintext succeeds; a wrong and a missing password are refused"

# Back to trust for the rest of the harness (matrix 16 reconnects as edge_gateway without a password).
cp "$HBA_BACKUP" "$HBA"
sql "SELECT pg_reload_conf()" >/dev/null

# ---------------------------------------------------------------------------
# 2./3. A FAILED provisioning leaves no plaintext in the server log; the old plaintext form does (control).
# ---------------------------------------------------------------------------
sql "DROP ROLE IF EXISTS $SCRATCH_ROLE" >/dev/null
sql "CREATE ROLE $SCRATCH_ROLE LOGIN NOCREATEROLE NOSUPERUSER" >/dev/null
CANARY="edge-canary-$(rand 12)"
CANARY_OLD="edge-canary-old-$(rand 12)"

set +e
printf '%s\n' "$CANARY" | PGUSER="$SCRATCH_ROLE" bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-stdin >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -ne 0 ] || fail "provisioning as a role WITHOUT CREATEROLE succeeded; the failure-path proof needs it to fail"

# The old behaviour (plaintext in the statement), same role: it fails identically -- and the server logs it in full.
PGUSER="$SCRATCH_ROLE" psql -X -q -At -c "ALTER ROLE edge_gateway LOGIN PASSWORD '$CANARY_OLD'" >/dev/null 2>&1 && fail "the control ALTER ROLE unexpectedly succeeded"

# Wait for the server to flush both failing statements to the log (it logs after the client has the error).
for _ in $(seq 1 40); do
  if grep -q "$CANARY_OLD" "$PG_LOG" 2>/dev/null; then break; fi
  sleep 0.25
done

grep -q "$CANARY_OLD" "$PG_LOG" || fail "control: the plaintext form was NOT found in the server log, so this test cannot tell whether the log would leak (is log_min_error_statement honoured, is PG_LOG the right file?)"
if grep -q "$CANARY" "$PG_LOG"; then
  fail "the FAILED provisioning leaked its plaintext password into the server log"
fi
# The failing provisioning statement was logged too (so its absence of the plaintext is a real result), with a verifier.
grep -q "ALTER ROLE edge_gateway LOGIN PASSWORD 'SCRAM-SHA-256\$4096:" "$PG_LOG" \
  || fail "the failing provisioning statement was not logged with a SCRAM verifier (log capture or statement shape is not what this test assumes)"
echo "tools/db/test-provision-edge-login.sh: OK -- a failed provisioning logs a SCRAM verifier and NO plaintext; the control (plaintext form) does leak"
