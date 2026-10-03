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

# ---------------------------------------------------------------------------
# 4. `--password-env`: the variable is unset before any child process exists (PR1b gate NIT).
# ---------------------------------------------------------------------------
# A psql stand-in records the environment it was started with; the variable (and so the secret) must not be in it.
ENV_PROBE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/edge-login-envprobe.XXXXXX")"
REAL_PSQL="$(command -v psql)"
cat > "$ENV_PROBE_DIR/psql-probe" <<PROBE
#!/usr/bin/env bash
env >> "$ENV_PROBE_DIR/children-env.txt"
exec "$REAL_PSQL" "\$@"
PROBE
chmod +x "$ENV_PROBE_DIR/psql-probe"
PW_ENV="$(rand 24)"
EDGE_PROBE_SECRET_VAR="$PW_ENV" PSQL_BIN="$ENV_PROBE_DIR/psql-probe" bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-env EDGE_PROBE_SECRET_VAR >/dev/null
[ -s "$ENV_PROBE_DIR/children-env.txt" ] || fail "the psql probe recorded nothing (the probe is not in the provisioning path, so the --password-env proof would be vacuous)"
if grep -q "EDGE_PROBE_SECRET_VAR\|$PW_ENV" "$ENV_PROBE_DIR/children-env.txt"; then
  fail "--password-env: the password variable (or its value) was still in the environment of a child process"
fi
rm -rf "$ENV_PROBE_DIR"
# And the password it carried is the role's real one (the script did its job with the unset variable).
{ echo "local all edge_gateway scram-sha-256"; cat "$HBA_BACKUP"; } > "$HBA"
sql "SELECT pg_reload_conf()" >/dev/null
sleep 0.5
[ "$(login "$PW_ENV")" = "edge_gateway" ] || fail "--password-env: the role cannot log in with the password the variable carried"
cp "$HBA_BACKUP" "$HBA"
sql "SELECT pg_reload_conf()" >/dev/null
echo "tools/db/test-provision-edge-login.sh: OK -- with --password-env the variable is gone from every child's environment, and the password still took effect"

# ---------------------------------------------------------------------------
# 5. The minting role (migration 0041): provisioning accepts the correctly configured role and REFUSES a misconfigured one.
# ---------------------------------------------------------------------------
# (the harness cluster has 0041 applied, so the happy path ran above: every provisioning in this file passed the minter post-condition.)
# The misconfigurations below are made by the bootstrap superuser and undone straight after, so the cluster is left as it was.
PW_M="$(rand 24)"
mutate_minter() { sql "$1" >/dev/null; }
expect_refused() { # $1 = label
  set +e
  printf '%s\n' "$PW_M" | bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-stdin >/dev/null 2>"$ENV_PROBE_ERR"
  local rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "provisioning blessed a misconfigured minter ($1)"
  grep -q "edge_signin_minter is not in the expected state" "$ENV_PROBE_ERR" || fail "provisioning refused ($1) but not for the minter's state: $(cat "$ENV_PROBE_ERR")"
}
ENV_PROBE_ERR="$(mktemp "${TMPDIR:-/tmp}/edge-login-minter.XXXXXX")"
printf '%s\n' "$PW_M" | bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-stdin >/dev/null 2>"$ENV_PROBE_ERR" || fail "provisioning refused a correctly configured minter: $(cat "$ENV_PROBE_ERR")"
mutate_minter "ALTER ROLE edge_signin_minter LOGIN"
expect_refused "LOGIN"
mutate_minter "ALTER ROLE edge_signin_minter NOLOGIN"
mutate_minter "GRANT edge_actor TO edge_signin_minter"
expect_refused "a member of edge_actor"
mutate_minter "REVOKE edge_actor FROM edge_signin_minter"
mutate_minter "GRANT edge_signin_minter TO edge_actor"
expect_refused "edge_actor a member of it"
mutate_minter "REVOKE edge_signin_minter FROM edge_actor"
# The membership is re-granted by the role that GRANTED it (the migrating role: postgres in superuser mode, migration_owner in restricted mode), so the
# fixtures replace that one grant row and leave the cluster with exactly the row it started with (a REVOKE by another grantor would leave the original behind).
GRANTOR="$(sql "SELECT g.rolname FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member JOIN pg_roles g ON g.oid = am.grantor WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway'" | tr -d '[:space:]')"
[ -n "$GRANTOR" ] || fail "edge_gateway has no membership of edge_signin_minter in the harness cluster (is 0041 applied?)"
regrant() { # $1 = options
  mutate_minter "REVOKE edge_signin_minter FROM edge_gateway GRANTED BY $GRANTOR"
  mutate_minter "GRANT edge_signin_minter TO edge_gateway WITH $1 GRANTED BY $GRANTOR"
}
regrant "INHERIT TRUE, SET TRUE"
expect_refused "edge_gateway holds it WITH INHERIT"
regrant "INHERIT FALSE, SET FALSE"
expect_refused "edge_gateway holds it without SET"
regrant "INHERIT FALSE, SET TRUE"
printf '%s\n' "$PW_M" | bash "$ROOT_DIR/tools/db/provision-edge-login.sh" --password-stdin >/dev/null 2>"$ENV_PROBE_ERR" || fail "provisioning refused the minter after every fixture was undone: $(cat "$ENV_PROBE_ERR")"
rm -f "$ENV_PROBE_ERR"
echo "tools/db/test-provision-edge-login.sh: OK -- provisioning accepts the correctly configured edge_signin_minter and refuses it with LOGIN, a membership of another role, edge_actor as a member, edge_gateway with INHERIT, and edge_gateway without SET"
