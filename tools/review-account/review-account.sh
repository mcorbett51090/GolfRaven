#!/usr/bin/env bash
# tools/review-account/review-account.sh
#
# Owner tool for the App Store review account (Apple guideline 2.1; build plan "FM-16.1"; migration 0051). One account, enabled ONLY inside a submission window.
# docs/security/review-account-design.md is the design; docs/owner/review-account-procedure.md is the step-by-step.
#
#   provision        create the Auth user if there is none (born BANNED), mark it the review account (app.app_review_demo_account), keep it banned until a window opens
#   open --hours N   open a window [now, now + N hours) (N = 1..1440, the database refuses more than 60 days) and clear the Auth ban        [--note TEXT]
#   close            end every open window NOW (the database refuses the account from that instant) and ban the Auth user
#   sync             make the Auth ban agree with the windows right now (idempotent; the scheduled step that closes a window that simply ran out)
#   status           what the database says (accounts, whether a window is open, windows); prints no address and no key
#
# WHAT LIVES WHERE (never in git: this repository is public):
#   the address        REVIEW_ACCOUNT_EMAIL, or the first line of standard input. Never an argument (no process list, no shell history). Read once, then unset.
#   the database       the standard libpq environment (PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD ...) exactly like tools/db/provision-edge-login.sh: a login that may SET ROLE service_role
#                      (REVIEW_ACCOUNT_DB_ROLE names another role, or is empty if the login already is the right one). There is no connection-URL argument.
#   the Auth admin API SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (environment only). The key goes to curl on STDIN (`-K -`), never on its command line.
#   GOLFRAVEN_REVIEW_AUTH=skip   database only: no Auth call is made (the proof in tools/db/test-review-account-tool.sh; also what you want if you ban by hand in the dashboard)
#
# THE ORDER IS THE SAFETY: `open` writes the window and THEN unbans (a failed unban leaves the account closed); `close` ends the window FIRST (the database refuses at once) and THEN bans
# (a failed ban leaves GoTrue willing to issue a token that the database still refuses). Every Auth call is `[unverified — training knowledge of the GoTrue admin API: POST
# /auth/v1/admin/users, PUT /auth/v1/admin/users/{id} with ban_duration "none" | "<hours>h"]`: it could not be exercised here (no hosted project); the database side is proven by matrix 29a-29f.
#
# Exit 0 on success; non-zero with a message on stderr (never the address, never a key).

set -euo pipefail

PSQL_BIN="${PSQL_BIN:-psql}"
CURL_BIN="${CURL_BIN:-curl}"
BAN_DURATION="876000h" # ~100 years: "banned until further notice" (GoTrue takes a duration, not a flag) [unverified]

die() { printf 'review-account.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

CMD="${1:-}"
[ -n "$CMD" ] || usage
shift || true
HOURS=""
NOTE="submission window"
while [ $# -gt 0 ]; do
  case "$1" in
    --hours) [ $# -ge 2 ] || die "--hours needs a value"; HOURS="$2"; shift 2 ;;
    --note) [ $# -ge 2 ] || die "--note needs a value"; NOTE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Every statement runs as service_role (the role that administers app.app_review_*; FORCE RLS has no policy for any other login). REVIEW_ACCOUNT_DB_ROLE overrides the name; empty means
# "the connecting role already is the right one".
DB_ROLE="${REVIEW_ACCOUNT_DB_ROLE-service_role}"
sql() {
  { [ -z "$DB_ROLE" ] || printf 'SET ROLE %s;\n' "$DB_ROLE"; cat; } | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1 "$@"
}

# ---------------------------------------------------------------------------------------------------------------------
# the address: environment or first line of stdin (provision only needs it; the other commands act on the review accounts the database lists)
# ---------------------------------------------------------------------------------------------------------------------
read_email() {
  local e="${REVIEW_ACCOUNT_EMAIL:-}"
  unset REVIEW_ACCOUNT_EMAIL
  if [ -z "$e" ]; then
    [ ! -t 0 ] || die "give the address on standard input (one line) or in REVIEW_ACCOUNT_EMAIL"
    IFS= read -r e || true
  fi
  e="${e%$'\r'}"
  [ -n "$e" ] || die "no address given"
  [ "${#e}" -le 254 ] || die "the address is too long"
  case "$e" in *[![:print:]]*|*" "*) die "the address must be printable ASCII with no spaces" ;; esac
  printf '%s' "$e" | grep -Eq '^[^@]+@[^@]+\.[^@]+$' || die "that does not look like an email address"
  EMAIL="$e"
}

# ---------------------------------------------------------------------------------------------------------------------
# GoTrue admin calls: URL and key from the environment, the key handed to curl on stdin only. `skip` mode makes no call.
# ---------------------------------------------------------------------------------------------------------------------
auth_call() { # METHOD PATH JSON  -> prints the HTTP status, leaves the body in $AUTH_BODY
  local method="$1" path="$2" body="$3"
  AUTH_BODY=""
  if [ "${GOLFRAVEN_REVIEW_AUTH:-api}" = "skip" ]; then printf 'skipped'; return 0; fi
  [ -n "${SUPABASE_URL:-}" ] || die "SUPABASE_URL is not set (or set GOLFRAVEN_REVIEW_AUTH=skip to act on the database only)"
  [ -n "${SUPABASE_SERVICE_ROLE_KEY:-}" ] || die "SUPABASE_SERVICE_ROLE_KEY is not set (or set GOLFRAVEN_REVIEW_AUTH=skip)"
  case "$SUPABASE_URL" in https://*|http://127.0.0.1*|http://localhost*) ;; *) die "SUPABASE_URL must be https:// (or a local http:// address)" ;; esac
  local out status
  out="$(mktemp)"; chmod 600 "$out"
  # printf is a shell builtin: the key is never an argument of a process. `data-binary` carries the JSON, so the address is not on a command line either.
  status="$(printf 'url = %s\nrequest = %s\nheader = "Authorization: Bearer %s"\nheader = "apikey: %s"\nheader = "Content-Type: application/json"\ndata-binary = %s\n' \
      "$(jq -Rn --arg u "${SUPABASE_URL%/}$path" '$u|@json')" "$method" "$SUPABASE_SERVICE_ROLE_KEY" "$SUPABASE_SERVICE_ROLE_KEY" "$(jq -Rn --arg b "$body" '$b|@json')" \
    | "$CURL_BIN" -sS -K - --max-time 20 -o "$out" -w '%{http_code}')" || { rm -f "$out"; die "the Auth admin call could not be made"; }
  AUTH_BODY="$(cat "$out")"; rm -f "$out"
  printf '%s' "$status"
}

ban_user() { # UID banned|clear
  local uid="$1" want="$2" body st
  if [ "$want" = "banned" ]; then body="$(jq -nc --arg d "$BAN_DURATION" '{ban_duration:$d}')"; else body='{"ban_duration":"none"}'; fi
  st="$(auth_call PUT "/auth/v1/admin/users/$uid" "$body")"
  case "$st" in 200|skipped) ;; *) die "the Auth admin call to set the ban failed (HTTP $st); the database side is unaffected" ;; esac
}

short() { printf '%s' "${1:0:8}"; }

review_uids() { printf '%s\n' "SELECT user_id FROM app.app_review_demo_account ORDER BY user_id" | sql; }
window_open() { printf '%s\n' "SELECT private.review_window_open_at(clock_timestamp())" | sql; }

do_sync() {
  local open uid n=0
  open="$(window_open)"
  while IFS= read -r uid; do
    [ -n "$uid" ] || continue
    if [ "$open" = "t" ]; then ban_user "$uid" clear; else ban_user "$uid" banned; fi
    n=$((n + 1))
  done < <(review_uids)
  printf 'review-account.sh: window %s; %s review account(s) %s\n' "$([ "$open" = t ] && echo OPEN || echo closed)" "$n" "$([ "$open" = t ] && echo 'cleared of the Auth ban' || echo 'banned in Auth')"
}

case "$CMD" in
  provision)
    read_email
    uid="$(printf '%s\n' "SELECT id FROM auth.users WHERE lower(email) = lower(:'email') ORDER BY created_at LIMIT 1" | sql -v email="$EMAIL")"
    if [ -z "$uid" ]; then
      st="$(auth_call POST /auth/v1/admin/users "$(jq -nc --arg e "$EMAIL" --arg d "$BAN_DURATION" '{email:$e,email_confirm:true,ban_duration:$d}')")"
      case "$st" in 200|201) ;; skipped) die "no Auth user has that address and GOLFRAVEN_REVIEW_AUTH=skip: create it first" ;; *) die "creating the Auth user failed (HTTP $st)" ;; esac
      uid="$(printf '%s\n' "SELECT id FROM auth.users WHERE lower(email) = lower(:'email') ORDER BY created_at LIMIT 1" | sql -v email="$EMAIL")"
      [ -n "$uid" ] || die "the Auth user was created but is not visible in auth.users"
    fi
    unset EMAIL
    # the review account holds NO partner scope: refuse an account that is a partner member or an admin (the database refuses it a partner route anyway; this stops a misconfiguration at the source)
    bad="$(printf '%s\n' "SELECT (EXISTS (SELECT 1 FROM app.partner_member WHERE user_id = :'uid') OR EXISTS (SELECT 1 FROM app.admin_user WHERE user_id = :'uid'))" | sql -v uid="$uid")"
    [ "$bad" = "f" ] || die "that account holds a partner role or is an admin: the review account must have no partner scope; use a different address"
    printf '%s\n' "INSERT INTO app.app_review_demo_account (user_id) VALUES (:'uid') ON CONFLICT DO NOTHING" | sql -v uid="$uid" >/dev/null
    printf 'review-account.sh: review account %s... is provisioned (closed until a window opens)\n' "$(short "$uid")"
    do_sync
    ;;
  open)
    printf '%s' "$HOURS" | grep -Eq '^[0-9]+$' || die "open needs --hours N (a whole number of hours, 1 to 1440)"
    [ "$HOURS" -ge 1 ] && [ "$HOURS" -le 1440 ] || die "--hours must be between 1 and 1440 (60 days is the longest window the database accepts)"
    [ "${#NOTE}" -le 200 ] || die "--note is limited to 200 characters"
    case "$NOTE" in *@*) die "--note must not contain an email address" ;; esac
    [ -n "$(review_uids)" ] || die "no review account is provisioned: run provision first"
    printf '%s\n' "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now(), now() + make_interval(hours => :hours), :'note')" | sql -v hours="$HOURS" -v note="$NOTE" >/dev/null
    printf 'review-account.sh: window opened for %s hour(s)\n' "$HOURS"
    do_sync
    ;;
  close)
    n="$(printf '%s\n' "WITH c AS (UPDATE app.app_review_window SET ends_at = now() WHERE starts_at < now() AND ends_at > now() RETURNING 1) SELECT count(*) FROM c" | sql)"
    printf 'review-account.sh: %s open window(s) ended now\n' "$n"
    do_sync
    ;;
  sync)
    do_sync
    ;;
  status)
    printf '%s\n' "SELECT 'review accounts: ' || (SELECT count(*) FROM app.app_review_demo_account) || E'\nwindow open now: ' || private.review_window_open_at(clock_timestamp()) || E'\nopen windows: ' || (SELECT count(*) FROM app.app_review_window WHERE starts_at <= now() AND ends_at > now()) || E'\nfuture windows: ' || (SELECT count(*) FROM app.app_review_window WHERE starts_at > now()) || E'\npast windows: ' || (SELECT count(*) FROM app.app_review_window WHERE ends_at <= now())" | sql
    ;;
  *) usage ;;
esac
