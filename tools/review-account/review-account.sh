#!/usr/bin/env bash
# tools/review-account/review-account.sh
#
# Owner tool for the App Store review account (Apple guideline 2.1; build plan "FM-16.1"; migration 0051). One account, enabled ONLY inside a submission window.
# docs/security/review-account-design.md is the design; docs/owner/review-account-procedure.md is the step-by-step.
#
#   provision [--adopt]  create the Auth user (born BANNED), mark it the review account (app.app_review_demo_account), keep it banned until a window opens.
#                        An address that ALREADY has an Auth user is refused (a typo must not turn a real player into the review account), unless it is already the review
#                        account (idempotent) or you pass --adopt AND the account has never been used (no evidence, play, reward, offer code, marker credit or purchase, no
#                        device, no partner role, not an admin). At most ONE review account exists (a unique index): a different one is refused until you delete the old row.
#   open --hours N       open a window [now, now + N hours) (N = 1..1440, the database refuses more than 60 days) and clear the Auth ban        [--note TEXT]
#   close                end every OPEN window NOW (the database refuses the account from that instant) and ban the Auth user. Future windows are left in place: the database
#                        would enable the account when one starts, while GoTrue stays banned until the next `sync` or `open`, which fails closed.
#   sync                 make the Auth ban agree with the windows right now (idempotent; the scheduled step that closes a window that simply ran out)
#   status               what the database says (accounts, whether a window is open, windows); prints no address and no key
#
# WHAT LIVES WHERE (never in git: this repository is public):
#   the address        REVIEW_ACCOUNT_EMAIL, or the first line of standard input. Never an argument (no process list, no shell history), and it reaches psql and jq on STANDARD INPUT only,
#                      never on a command line. Read once, then unset, so no child process inherits it.
#   the database       the standard libpq environment (PGHOST, PGPORT, PGUSER, PGDATABASE, PGPASSWORD ...) exactly like tools/db/provision-edge-login.sh: a login that may SET ROLE service_role
#                      (REVIEW_ACCOUNT_DB_ROLE names another role, or is empty if the login already is the right one). There is no connection-URL argument.
#   the Auth admin API SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (environment only; the key is moved into a shell variable and unset at once, so no child inherits it). The key goes to
#                      curl on STDIN (`-K -`, built by the printf BUILTIN), never on a command line; the response (which names the address) lives in a variable, never in a file.
#                      SUPABASE_URL must be exactly `https://<host>[:port]`. `http://localhost` and `http://127.0.0.1` (optional port) are accepted ONLY with GOLFRAVEN_REVIEW_ALLOW_LOCAL=1 (the proof in
#                      tools/db/test-review-account-tool.sh); userinfo, a path, and look-alike hosts (`localhost.evil`, `127.0.0.1.nip.io`) are refused.
#   GOLFRAVEN_REVIEW_AUTH=skip   database only: no Auth call is made (also what you want if you ban by hand in the dashboard)
#
# THE ORDER IS THE SAFETY: `open` writes the window and THEN unbans (a failed unban leaves the account closed); `close` ends the window FIRST (the database refuses at once) and THEN bans
# (a failed ban leaves GoTrue willing to issue a token that the database still refuses). Every Auth call is `[unverified — training knowledge of the GoTrue admin API: POST
# /auth/v1/admin/users, PUT /auth/v1/admin/users/{id} with ban_duration "none" | "<hours>h"]`: it could not be exercised against a hosted project; the CALLS (method, path, headers, JSON body, order
# against the database) are proven against a real curl and a local listener in tools/db/test-review-account-tool.sh, and the database side by matrix 29a-29f.
#
# Exit 0 on success; non-zero with a message on stderr (never the address, never a key).

set -euo pipefail

PSQL_BIN="${PSQL_BIN:-psql}"
CURL_BIN="${CURL_BIN:-curl}"
BAN_DURATION="876000h" # ~100 years: "banned until further notice" (GoTrue takes a duration, not a flag) [unverified]

die() { printf 'review-account.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

# The service key and the URL leave the environment NOW: every child process (psql, jq, curl) is started without them.
AUTH_URL="${SUPABASE_URL:-}"
AUTH_KEY="${SUPABASE_SERVICE_ROLE_KEY:-}"
unset SUPABASE_URL SUPABASE_SERVICE_ROLE_KEY

CMD="${1:-}"
[ -n "$CMD" ] || usage
shift || true
HOURS=""
NOTE="submission window"
ADOPT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --hours) [ $# -ge 2 ] || die "--hours needs a value"; HOURS="$2"; shift 2 ;;
    --note) [ $# -ge 2 ] || die "--note needs a value"; NOTE="$2"; shift 2 ;;
    --adopt) ADOPT=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Every statement runs as service_role (the role that administers app.app_review_*; FORCE RLS has no policy for any other login). REVIEW_ACCOUNT_DB_ROLE overrides the name; empty means
# "the connecting role already is the right one". The SQL arrives on STDIN: nothing sensitive is ever an argument of psql.
DB_ROLE="${REVIEW_ACCOUNT_DB_ROLE-service_role}"
sql() {
  { [ -z "$DB_ROLE" ] || printf 'SET ROLE %s;\n' "$DB_ROLE"; cat; } | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1 "$@"
}
# a SQL string literal for a value that is validated printable ASCII: standard_conforming_strings is on (PostgreSQL's default since 9.1), so doubling the quote is the whole escape
lit() { printf "'%s'" "${1//\'/\'\'}"; }
# JSON-encode stdin as ONE string (jq's own output, no second encoding, no argument)
jstr() { jq -Rs .; }

# ---------------------------------------------------------------------------------------------------------------------
# the address: environment or first line of stdin (only provision needs it)
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
# GoTrue admin calls
# ---------------------------------------------------------------------------------------------------------------------
check_url() {
  local u="${AUTH_URL%/}"
  if printf '%s' "$u" | grep -Eq '^https://[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[0-9]{1,5})?$'; then return 0; fi
  if [ "${GOLFRAVEN_REVIEW_ALLOW_LOCAL:-}" = "1" ] && printf '%s' "$u" | grep -Eq '^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$'; then return 0; fi
  die "SUPABASE_URL must be exactly https://<host>[:port] (no userinfo, no path; plain http only to localhost or 127.0.0.1 for the tool's own test, with GOLFRAVEN_REVIEW_ALLOW_LOCAL=1)"
}

# auth_call METHOD PATH BODY -> prints the HTTP status. The response body (it names the address) is held in a local variable and dropped: it never touches a file and is never printed.
auth_call() {
  local method="$1" path="$2" body="$3" resp
  if [ "${GOLFRAVEN_REVIEW_AUTH:-api}" = "skip" ]; then printf 'skipped'; return 0; fi
  [ -n "$AUTH_URL" ] || die "SUPABASE_URL is not set (or set GOLFRAVEN_REVIEW_AUTH=skip to act on the database only)"
  [ -n "$AUTH_KEY" ] || die "SUPABASE_SERVICE_ROLE_KEY is not set (or set GOLFRAVEN_REVIEW_AUTH=skip)"
  check_url
  # The config is built by the printf BUILTIN (its arguments are never exec'd, so the key is on no command line) and piped to curl's stdin. The URL and the body are JSON-encoded ONCE
  # (a JSON string is a valid curl-config quoted string for the printable ASCII used here).
  resp="$(printf 'url = %s\nrequest = %s\nheader = "Authorization: Bearer %s"\nheader = "apikey: %s"\nheader = "Content-Type: application/json"\ndata-binary = %s\n' \
      "$(printf '%s' "${AUTH_URL%/}$path" | jstr)" "$method" "$AUTH_KEY" "$AUTH_KEY" "$(printf '%s' "$body" | jstr)" \
    | "$CURL_BIN" -sS -K - --max-time 20 -w '\n%{http_code}')" || die "the Auth admin call could not be made"
  printf '%s' "${resp##*$'\n'}"
}

ban_user() { # UID banned|clear
  local uid="$1" want="$2" body st
  if [ "$want" = "banned" ]; then body="$(jq -nc --arg d "$BAN_DURATION" '{ban_duration:$d}')"; else body='{"ban_duration":"none"}'; fi
  st="$(auth_call PUT "/auth/v1/admin/users/$uid" "$body")"
  case "$st" in 200|skipped) ;; *) die "the Auth admin call to set the ban failed (HTTP $st); the database side is unaffected" ;; esac
}

short() { printf '%s' "${1:0:8}"; }

# ---------------------------------------------------------------------------------------------------------------------
# database reads. A failed read is FATAL (no process substitution, no swallowed status): a sync that cannot read the accounts must not look like "nothing to do".
# ---------------------------------------------------------------------------------------------------------------------
review_uids() { printf '%s\n' "SELECT user_id FROM app.app_review_demo_account ORDER BY user_id" | sql; }
window_open() { printf '%s\n' "SELECT private.review_window_open_at(clock_timestamp())" | sql; }

do_sync() {
  local open uids uid n=0
  open="$(window_open)" || die "could not read the window state from the database"
  case "$open" in t|f) ;; *) die "the database answered '$open' to 'is a window open'" ;; esac
  uids="$(review_uids)" || die "could not list the review accounts from the database"
  while IFS= read -r uid; do
    [ -n "$uid" ] || continue
    if [ "$open" = "t" ]; then ban_user "$uid" clear; else ban_user "$uid" banned; fi
    n=$((n + 1))
  done <<< "$uids"
  printf 'review-account.sh: window %s; %s review account(s) %s\n' "$([ "$open" = t ] && echo OPEN || echo closed)" "$n" "$([ "$open" = t ] && echo 'cleared of the Auth ban' || echo 'banned in Auth')"
}

case "$CMD" in
  provision)
    read_email
    L="$(lit "$EMAIL")"
    # (1) is that address already THE review account?
    same="$(printf '%s\n' "SELECT EXISTS (SELECT 1 FROM app.app_review_demo_account d JOIN auth.users u ON u.id = d.user_id WHERE lower(u.email) = lower($L))" | sql)" || die "database read failed"
    if [ "$same" = "t" ]; then
      printf 'review-account.sh: that address is already the review account (nothing to create)\n'
    else
      # (2) at most ONE review account
      other="$(printf '%s\n' "SELECT count(*) FROM app.app_review_demo_account" | sql)" || die "database read failed"
      [ "$other" = "0" ] || die "a different review account already exists (at most one is allowed): delete its row from app.app_review_demo_account first if you mean to replace it"
      # (3) an address that already has an Auth user is never converted by accident
      uid="$(printf '%s\n' "SELECT id FROM auth.users WHERE lower(email) = lower($L) ORDER BY created_at LIMIT 1" | sql)" || die "database read failed"
      if [ -n "$uid" ]; then
        [ "$ADOPT" = "1" ] || die "an Auth user with that address already exists. Refusing to turn an existing account into the review account (a typo would convert a real player). Pass --adopt only if it was created for this purpose and has never been used"
        used="$(printf '%s\n' "SELECT (EXISTS (SELECT 1 FROM app.evidence WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.play WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.offer_code WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.entitlement WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.marker_credit WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.purchase_evidence WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.device WHERE user_id = :'u'))" | sql -v u="$uid")" || die "database read failed"
        [ "$used" = "f" ] || die "--adopt refused: that account has been used (evidence, plays, rewards, credits, purchases or devices exist). Use a fresh address"
      else
        body="$(printf '%s' "$EMAIL" | jq -Rsc --arg d "$BAN_DURATION" '{email: ., email_confirm: true, ban_duration: $d}')" || die "could not build the request"
        st="$(auth_call POST /auth/v1/admin/users "$body")" || die "creating the Auth user failed"
        unset body
        case "$st" in
          200|201) ;;
          skipped) die "no Auth user has that address and GOLFRAVEN_REVIEW_AUTH=skip: create it first" ;;
          *) die "creating the Auth user failed (HTTP $st)" ;;
        esac
        uid="$(printf '%s\n' "SELECT id FROM auth.users WHERE lower(email) = lower($L) ORDER BY created_at LIMIT 1" | sql)" || die "database read failed"
        [ -n "$uid" ] || die "the Auth user was created but is not visible in auth.users"
      fi
      # (4) the review account holds NO partner scope: refuse an account that is a partner member or an admin (the database refuses it a partner route anyway; this stops a
      # misconfiguration at the source)
      bad="$(printf '%s\n' "SELECT (EXISTS (SELECT 1 FROM app.partner_member WHERE user_id = :'u') OR EXISTS (SELECT 1 FROM app.admin_user WHERE user_id = :'u'))" | sql -v u="$uid")" || die "database read failed"
      [ "$bad" = "f" ] || die "that account holds a partner role or is an admin: the review account must have no partner scope; use a different address"
      printf '%s\n' "INSERT INTO app.app_review_demo_account (user_id) VALUES (:'u')" | sql -v u="$uid" >/dev/null
      printf 'review-account.sh: review account %s... is provisioned (closed until a window opens)\n' "$(short "$uid")"
    fi
    unset EMAIL L
    do_sync
    ;;
  open)
    printf '%s' "$HOURS" | grep -Eq '^[0-9]+$' || die "open needs --hours N (a whole number of hours, 1 to 1440)"
    [ "$HOURS" -ge 1 ] && [ "$HOURS" -le 1440 ] || die "--hours must be between 1 and 1440 (60 days is the longest window the database accepts)"
    [ "${#NOTE}" -le 200 ] || die "--note is limited to 200 characters"
    case "$NOTE" in *@*) die "--note must not contain an email address" ;; esac
    uids="$(review_uids)" || die "could not list the review accounts from the database"
    [ -n "$uids" ] || die "no review account is provisioned: run provision first"
    printf '%s\n' "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now(), now() + make_interval(hours => :hours), :'note')" | sql -v hours="$HOURS" -v note="$NOTE" >/dev/null
    printf 'review-account.sh: window opened for %s hour(s)\n' "$HOURS"
    do_sync
    ;;
  close)
    n="$(printf '%s\n' "WITH c AS (UPDATE app.app_review_window SET ends_at = now() WHERE starts_at < now() AND ends_at > now() RETURNING 1) SELECT count(*) FROM c" | sql)" || die "could not end the open windows"
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
