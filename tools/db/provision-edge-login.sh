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
# and it is sent to psql on STANDARD INPUT, so it never appears in a process list or a shell history of
# this script's own command line. There is deliberately no `--password VALUE` option.
#
# Connection: the standard libpq environment only (PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD, ...), exactly
# as tools/db/verify-function-inventory.mjs and the test harness do; there is no connection-URL argument.
# Run it as the migrating role or a superuser. Note `[unverified]`: the statement carries the password, so on a
# server with log_statement = 'ddl' or 'all' it can reach the server log; run it with that off.
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
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
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
fi

if [ -z "${PASSWORD:-}" ]; then
  echo "provision-edge-login.sh: no password supplied (set \$$PASSWORD_ENV or use --password-stdin); refusing to set an empty one" >&2
  exit 2
fi
case "$PASSWORD" in
  *$'\n'*|*$'\r'*) echo "provision-edge-login.sh: the password must be a single line" >&2; exit 2 ;;
esac

# The literal for the ALTER ROLE statement. standard_conforming_strings is on, so the only character to
# escape inside '...' is the single quote itself.
ESCAPED="${PASSWORD//\'/\'\'}"

# The role must already exist (the migration creates it); fail loudly rather than creating a second,
# differently-configured one here.
EXISTS="$(printf '%s\n' "SELECT 1 FROM pg_roles WHERE rolname = 'edge_gateway'" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1)"
if [ "$EXISTS" != "1" ]; then
  echo "provision-edge-login.sh: role edge_gateway does not exist; apply supabase/migrations/0030_edge_role_core.sql first" >&2
  exit 1
fi

SQL="ALTER ROLE edge_gateway LOGIN PASSWORD '${ESCAPED}'"
if [ -n "$CONN_LIMIT" ]; then
  SQL="${SQL} CONNECTION LIMIT ${CONN_LIMIT}"
fi

# Statement on STDIN: not on the command line, so not in `ps`.
printf '%s;\n' "$SQL" | "$PSQL_BIN" -X -q -v ON_ERROR_STOP=1 >/dev/null

# Post-condition: still not a superuser / bypassrls, and can log in. (The migration's own checks
# enforce the first two; this guards against the script ever being pointed at the wrong role.)
CHECK="$(printf '%s\n' "SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname = 'edge_gateway'" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1)"
if [ "$CHECK" != "t" ]; then
  echo "provision-edge-login.sh: edge_gateway is not in the expected state after provisioning (LOGIN, NOSUPERUSER, NOBYPASSRLS)" >&2
  exit 1
fi
echo "provision-edge-login.sh: edge_gateway can now log in (password set; not echoed)"
