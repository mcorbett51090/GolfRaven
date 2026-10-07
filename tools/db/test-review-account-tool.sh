#!/usr/bin/env bash
# tools/db/test-review-account-tool.sh
#
# Proof of tools/review-account/review-account.sh (0051) against the harness cluster: provision, open, close, sync and status; what each writes; that the address and the key never
# appear in its output or on a command line; and the shape of the Auth admin calls through a recording curl stand-in (GoTrue itself is `[unverified]`: no hosted project here).
#
#   1. provision (address on STDIN): marks the existing Auth user the review account, idempotently; the output names no address
#   2. provision refuses an admin (a review account holds no partner scope)
#   3. open: rejects 0, 1441, a non-number and an address-bearing note; opens a window (the DATABASE predicate flips to true)
#   4. close: ends the window at once (the predicate flips to false)
#   5. the Auth calls (a recording curl): sync while closed PUTs ban_duration 876000h, sync while open PUTs "none"; the key is on curl's STDIN, never in its arguments; the tool prints no key
#   6. status prints counts only
#   everything this seeds is removed by the EXIT trap.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-review-account-tool.sh   (tools/db/test.sh calls it after the matrix, against the same cluster)
# No secret: the address is synthetic (example.test), the "service-role key" handed to the stub is random per run and the stub is local.

set -euo pipefail

: "${PGHOST:?tools/db/test-review-account-tool.sh: PGHOST must be set}"
: "${PGPORT:?PGPORT must be set}"
: "${PGUSER:?PGUSER must be set}"
: "${PGDATABASE:?PGDATABASE must be set}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT_DIR/tools/review-account/review-account.sh"
PSQL_BIN="${PSQL_BIN:-psql}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rev-tool-test.XXXXXX")"
UID1="29520000-0000-0000-0000-0000000000a1"
UID2="29520000-0000-0000-0000-0000000000a2"
EMAIL="rev-tool-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')@example.test"
KEY="k$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"

psql_q() { printf '%s\n' "SET ROLE service_role; $1" | "$PSQL_BIN" -X -q -A -t -v ON_ERROR_STOP=1; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

cleanup() {
  psql_q "DELETE FROM app.app_review_window WHERE note LIKE 'rev-tool-test%'; DELETE FROM app.app_review_demo_account WHERE user_id IN ('$UID1', '$UID2'); DELETE FROM app.admin_user WHERE user_id = '$UID2'; DELETE FROM auth.users WHERE id IN ('$UID1', '$UID2');" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_trap_ready=1

psql_q "DELETE FROM app.app_review_window WHERE note LIKE 'rev-tool-test%'; DELETE FROM app.app_review_demo_account WHERE user_id IN ('$UID1', '$UID2'); DELETE FROM app.admin_user WHERE user_id = '$UID2'; DELETE FROM auth.users WHERE id IN ('$UID1', '$UID2');" >/dev/null
psql_q "INSERT INTO auth.users (id, email) VALUES ('$UID1', '$EMAIL'), ('$UID2', 'rev-tool-admin-$UID2@example.test'); INSERT INTO app.admin_user (user_id) VALUES ('$UID2');" >/dev/null
# no window may be open when the proof starts (it asserts the predicate flips)
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "a window is open before the proof starts"

export GOLFRAVEN_REVIEW_AUTH=skip

# 1. provision, address on stdin
OUT="$(printf '%s\n' "$EMAIL" | bash "$TOOL" provision 2>&1)" || fail "provision failed: $OUT"
case "$OUT" in *"$EMAIL"*) fail "provision printed the address" ;; esac
[ "$(psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '$UID1'")" = "1" ] || fail "provision did not mark the review account"
printf '%s\n' "$EMAIL" | bash "$TOOL" provision >/dev/null 2>&1 || fail "provision is not idempotent"
[ "$(psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '$UID1'")" = "1" ] || fail "provision twice made two rows"
ok "provision (stdin): marks the account once, idempotently, prints no address"

# the address also works through the environment, and a missing one is refused
REVIEW_ACCOUNT_EMAIL="$EMAIL" bash "$TOOL" provision >/dev/null 2>&1 || fail "provision via REVIEW_ACCOUNT_EMAIL failed"
if bash "$TOOL" provision </dev/null >/dev/null 2>&1; then fail "provision with no address succeeded"; fi
if printf 'not-an-address\n' | bash "$TOOL" provision >/dev/null 2>&1; then fail "provision accepted a malformed address"; fi
ok "provision: environment variable works; no address and a malformed address are refused"

# 2. an admin cannot be the review account
if printf '%s\n' "rev-tool-admin-$UID2@example.test" | bash "$TOOL" provision >/dev/null 2>&1; then fail "provision accepted an admin"; fi
[ "$(psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '$UID2'")" = "0" ] || fail "an admin was marked the review account"
ok "provision refuses an admin (no partner scope)"

# 3. open
for bad in 0 1441 abc "" "-3"; do
  if bash "$TOOL" open --hours "$bad" >/dev/null 2>&1; then fail "open accepted --hours '$bad'"; fi
done
if bash "$TOOL" open --hours 2 --note "rev-tool-test x@y.test" >/dev/null 2>&1; then fail "open accepted an address in the note"; fi
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "a refused open still opened a window"
bash "$TOOL" open --hours 2 --note "rev-tool-test open" >/dev/null 2>&1 || fail "open --hours 2 failed"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp() + interval '1 minute')")" = "t" ] || fail "open did not make the predicate true"
[ "$(psql_q "SELECT count(*) FROM app.app_review_window WHERE note = 'rev-tool-test open' AND ends_at - starts_at = interval '2 hours'")" = "1" ] || fail "open wrote the wrong window"
ok "open: rejects 0 / 1441 / non-numbers / an address in the note; a 2-hour window makes the database predicate true"

# 4. close
bash "$TOOL" close >/dev/null 2>&1 || fail "close failed"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "close left the window open"
ok "close: the database predicate is false at once"

# 5. the Auth calls through a recording curl stand-in
STUB="$WORK/curl-stub"
cat > "$STUB" <<'STUBEOF'
#!/usr/bin/env bash
# records its arguments and its stdin config; answers 200 {} like the admin API would
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) printf '%s\n' "$1" >> "$STUB_ARGS"; shift ;; esac; done
cat >> "$STUB_STDIN"
printf '\n---\n' >> "$STUB_STDIN"
[ -z "$out" ] || printf '{}' > "$out"
printf '200'
STUBEOF
chmod +x "$STUB"
export STUB_ARGS="$WORK/args.log" STUB_STDIN="$WORK/stdin.log"
: > "$STUB_ARGS"; : > "$STUB_STDIN"
unset GOLFRAVEN_REVIEW_AUTH
OUT="$(CURL_BIN="$STUB" SUPABASE_URL="https://example.test" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" sync 2>&1)" || fail "sync failed: $OUT"
case "$OUT" in *"$KEY"*|*"$EMAIL"*) fail "sync printed the key or the address" ;; esac
grep -q "/auth/v1/admin/users/$UID1" "$STUB_STDIN" || fail "sync (closed) made no PUT for the review account"
grep -q 'request = PUT' "$STUB_STDIN" || fail "sync did not use PUT"
grep -q '876000h' "$STUB_STDIN" || fail "sync (closed) did not ban"
! grep -q "$KEY" "$STUB_ARGS" || fail "the key appeared in curl's ARGUMENTS"
grep -q "$KEY" "$STUB_STDIN" || fail "the key did not reach curl on stdin (the stub would see no auth)"
: > "$STUB_STDIN"
CURL_BIN="$STUB" SUPABASE_URL="https://example.test" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" open --hours 1 --note "rev-tool-test open2" >/dev/null 2>&1 || fail "open with the Auth call failed"
grep -q '"ban_duration":"none"' "$STUB_STDIN" || fail "open did not clear the ban"
CURL_BIN="$STUB" SUPABASE_URL="https://example.test" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" close >/dev/null 2>&1 || fail "close with the Auth call failed"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "close left the window open (Auth mode)"
if SUPABASE_URL="http://example.test" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" sync >/dev/null 2>&1; then fail "sync accepted a plain-http remote URL"; fi
if SUPABASE_URL="https://example.test" bash "$TOOL" sync >/dev/null 2>&1; then fail "sync ran with no service key"; fi
ok "Auth calls: closed sync bans (876000h), open clears (none), PUT per account; the key is on curl's stdin only and never printed; remote http and a missing key are refused"

# 6. status
OUT="$(bash "$TOOL" status 2>&1)" || fail "status failed"
case "$OUT" in *"$EMAIL"*|*"$KEY"*) fail "status printed the address or key" ;; esac
printf '%s' "$OUT" | grep -q 'window open now: f' || fail "status did not report closed"
ok "status: counts only"

echo "tools/db/test-review-account-tool.sh: all review-account tool checks passed"
