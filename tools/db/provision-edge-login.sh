#!/usr/bin/env bash
# tools/db/provision-edge-login.sh
#
# Gives the `edge_gateway` role (created NOLOGIN by supabase/migrations/0030_edge_role_core.sql) its LOGIN
# attribute and a password. This is the ONLY place a credential for that role is ever set: a migration
# must not carry one (the repo is public), so the migration creates the role NOLOGIN and this script
# turns it into a login role, once per environment, from a secret the operator already holds.
#
# Idempotent: re-running it just sets the same (or a new) password again. `ALTER ROLE` needs the
# caller to hold CREATEROLE (and ADMIN on the role, which the migrating role has) or be a superuser.
#
# THE PASSWORD IS NEVER A LITERAL ARGUMENT. It is read from, in this order:
#   1. `--password-stdin`            the first line of standard input (preferred; wins over the variable)
#   2. the environment variable named by `--password-env NAME`  (default name: EDGE_GATEWAY_PASSWORD)
# There is deliberately no `--password VALUE` option, so it never appears in a process list or a shell history
# of this script's own command line.
#
# THE PLAINTEXT NEVER REACHES THE SERVER (0032, gate finding M1). The script computes the SCRAM-SHA-256 verifier
# itself (PBKDF2-HMAC-SHA256, 4096 iterations, a fresh 16-byte salt -- the format PostgreSQL stores and its own
# `PQencryptPasswordConn` produces) and sends `ALTER ROLE edge_gateway LOGIN PASSWORD 'SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>'`.
# The old form sent `PASSWORD '<plaintext>'`, and a FAILING ALTER ROLE is logged in full when
# log_min_error_statement is `error` (the default): a plaintext secret in the server log. A verifier in a log is
# useless for anything but an offline guess against a 4096-round PBKDF2, and the client's own handshake never
# needs the plaintext on the server. Requires python3 (stdlib only). The password must be printable ASCII
# (0x20-0x7e): SASLprep normalisation is not implemented here, and for ASCII it is the identity; a generated
# password (`openssl rand -base64 24`, `head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'`) always qualifies.
# The verifier is computed from the password read from stdin of a python3 child; it is never an argument.
#
# Connection: the standard libpq environment only (PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD, ...), exactly
# as tools/db/verify-function-inventory.mjs and the test harness do; there is no connection-URL argument.
# Run it as the migrating role or a superuser. Note `[unverified]`: the statement carries the password, so on a
# server with log_statement = 'ddl' or 'all' it can reach the server log; run it with that off.
#
# Proof: tools/db/test-provision-edge-login.sh (run by tools/db/test.sh) logs in with the plaintext over a real
# SCRAM handshake, shows a wrong password is refused, and shows a FAILED provisioning (as a role without CREATEROLE)
# leaves no plaintext in the server log -- with a control that the old plaintext form DID leak.
#
# Usage:
#   EDGE_GATEWAY_PASSWORD=... tools/db/provision-edge-login.sh
#   printf '%s\n' "$SECRET" | tools/db/provision-edge-login.sh --password-stdin
#   tools/db/provision-edge-login.sh --password-env MY_VAR
#   tools/db/provision-edge-login.sh --connection-limit 20     (optional: cap concurrent sessions)
#
# Exit 0 on success; non-zero (with a message on stderr, never echoing the password) otherwise.

set -euo pipefail

PSQL_BIN="${PSQL_BIN:-psql}"
PASSWORD_ENV="EDGE_GATEWAY_PASSWORD"
FROM_STDIN=0
CONN_LIMIT=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --password-stdin) FROM_STDIN=1; shift ;;
    --password-env)
      [ "$#" -ge 2 ] || { echo "provision-edge-login.sh: --password-env needs a variable NAME" >&2; exit 2; }
      PASSWORD_ENV="$2"; shift 2 ;;
    --connection-limit)
      [ "$#" -ge 2 ] || { echo "provision-edge-login.sh: --connection-limit needs a number" >&2; exit 2; }
      CONN_LIMIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "provision-edge-login.sh: unknown argument '$1' (there is deliberately no way to pass the password as an argument)" >&2; exit 2 ;;
  esac
done

if [ -n "$CONN_LIMIT" ] && ! [[ "$CONN_LIMIT" =~ ^[0-9]+$ ]]; then
  echo "provision-edge-login.sh: --connection-limit must be a non-negative integer" >&2
  exit 2
fi

if [ "$FROM_STDIN" -eq 1 ]; then
  IFS= read -r PASSWORD || true
else
  if ! [[ "$PASSWORD_ENV" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "provision-edge-login.sh: '$PASSWORD_ENV' is not a valid environment variable name" >&2
    exit 2
  fi
  PASSWORD="${!PASSWORD_ENV:-}"
  # The variable is not needed any more, and every child this script starts (psql, python3) would inherit it if it were
  # exported (PR1b gate NIT): unset it now, before any child exists. (`--password-stdin` never had the secret in the environment.)
  unset "$PASSWORD_ENV"
fi

if [ -z "${PASSWORD:-}" ]; then
  echo "provision-edge-login.sh: no password supplied (set \$$PASSWORD_ENV or use --password-stdin); refusing to set an empty one" >&2
  exit 2
fi
case "$PASSWORD" in
  *$'\n'*|*$'\r'*) echo "provision-edge-login.sh: the password must be a single line" >&2; exit 2 ;;
esac
# Printable ASCII only (see the header: no SASLprep here). LC_ALL=C so the range is bytes, not a locale collation.
if ! printf '%s' "$PASSWORD" | LC_ALL=C grep -qE '^[ -~]+$'; then
  echo "provision-edge-login.sh: the password must be printable ASCII (generate one: openssl rand -base64 24)" >&2
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "provision-edge-login.sh: python3 is required (it computes the SCRAM-SHA-256 verifier)" >&2; exit 2; }

# The SCRAM-SHA-256 verifier, computed here, so the server only ever sees the verifier. The password goes to the
# python3 child on STDIN (printf is a shell builtin: no argv, no process-list entry).
VERIFIER="$(printf '%s' "$PASSWORD" | python3 -c '
import base64, hashlib, hmac, os, sys
pw = sys.stdin.buffer.read()
iterations = 4096
salt = os.urandom(16)
salted = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations)
client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
stored_key = hashlib.sha256(client_key).digest()
server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
b64 = lambda b: base64.b64encode(b).decode("ascii")
sys.stdout.write("SCRAM-SHA-256$%d:%s$%s:%s" % (iterations, b64(salt), b64(stored_key), b64(server_key)))
')"
case "$VERIFIER" in
  'SCRAM-SHA-256$4096:'*) ;;
  *) echo "provision-edge-login.sh: could not compute the SCRAM-SHA-256 verifier" >&2; exit 1 ;;
esac
unset PASSWORD

# The role must already exist (the migration creates it); fail loudly rather than creating a second,
# differently-configured one here.
EXISTS="$(printf '%s\n' "SELECT 1 FROM pg_roles WHERE rolname = 'edge_gateway'" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1)"
if [ "$EXISTS" != "1" ]; then
  echo "provision-edge-login.sh: role edge_gateway does not exist; apply supabase/migrations/0030_edge_role_core.sql first" >&2
  exit 1
fi

# Base64 and '$', ':' contain no quote, so the verifier needs no escaping inside '...'.
SQL="ALTER ROLE edge_gateway LOGIN PASSWORD '${VERIFIER}'"
if [ -n "$CONN_LIMIT" ]; then
  SQL="${SQL} CONNECTION LIMIT ${CONN_LIMIT}"
fi

# Statement on STDIN: not on the command line, so not in `ps` (and it carries a verifier, not the password).
printf '%s;\n' "$SQL" | "$PSQL_BIN" -X -q -v ON_ERROR_STOP=1 >/dev/null

# Post-condition: still not a superuser / bypassrls, and can log in. (The migration's own checks
# enforce the first two; this guards against the script ever being pointed at the wrong role.)
CHECK="$(printf '%s\n' "SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname = 'edge_gateway'" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1)"
if [ "$CHECK" != "t" ]; then
  echo "provision-edge-login.sh: edge_gateway is not in the expected state after provisioning (LOGIN, NOSUPERUSER, NOBYPASSRLS)" >&2
  exit 1
fi
# The minting role (migration 0041): edge_gateway reaches `private.signin_record_email_proof` only through `SET ROLE edge_signin_minter`. This script gives
# the login nothing and creates no role, but a login provisioned next to a MISCONFIGURED minter (a role that can log in, holds SUPERUSER / BYPASSRLS /
# INHERIT, is a member of another role, or that edge_gateway holds with INHERIT, without SET, or with ADMIN) is not a state to bless: refuse. Before
# 0041 is applied the role does not exist yet: that is a note, not an error (the proof mint refuses until the migration is applied; nothing else needs it).
MINTER="$(printf '%s\n' "SELECT CASE
  WHEN NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edge_signin_minter') THEN 'absent'
  WHEN (SELECT r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication FROM pg_roles r WHERE r.rolname = 'edge_signin_minter')
    OR EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE m.rolname = 'edge_signin_minter')
    OR NOT EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
                   WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option AND NOT am.admin_option)
    OR EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
               WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway' AND (NOT am.set_option OR am.inherit_option OR am.admin_option))
    OR EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
               WHERE r.rolname = 'edge_signin_minter' AND m.rolname NOT IN ('edge_gateway') AND (am.set_option OR am.inherit_option OR NOT (m.rolsuper OR m.rolcreaterole)))
  THEN 'bad' ELSE 'ok' END" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1)"
case "$MINTER" in
  ok) ;;
  absent) echo "provision-edge-login.sh: note: role edge_signin_minter does not exist (supabase/migrations/0041_signin_proof_hardening.sql is not applied): the cross-account email-proof link will refuse until it is" >&2 ;;
  *) echo "provision-edge-login.sh: edge_signin_minter is not in the expected state (NOLOGIN, no SUPERUSER / BYPASSRLS / INHERIT, a member of nothing, edge_gateway its only SET TRUE / INHERIT FALSE / non-admin member): refusing to bless this login" >&2; exit 1 ;;
esac
echo "provision-edge-login.sh: edge_gateway can now log in (SCRAM-SHA-256 verifier set; the password was never sent to the server)"
