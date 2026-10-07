#!/usr/bin/env bash
# tools/db/test-review-account-tool.sh
#
# Proof of tools/review-account/review-account.sh (0051) against the harness cluster, with the REAL curl, jq and psql: nothing in the tool is stubbed. GoTrue's admin API is stood in for by
# tools/db/review-account-listener.py, a local listener that RECORDS every request it gets and, on every PUT, what the database says at that instant. (GoTrue's own behaviour is
# `[unverified]`: no hosted project here; what is proven is the CALL: method, path, headers, parsed JSON body, and its ORDER against the database.)
#
#   1. provision of a NEW address: one POST /auth/v1/admin/users (Authorization and apikey carry the key, JSON content type, body parsed as {email, email_confirm, ban_duration}) then one
#      PUT /auth/v1/admin/users/<id> {ban_duration} while the window is closed; the database row exists; nothing printed names the address or the key; idempotent on the same address
#   2. at most ONE review account (a different address is refused, no Auth call); an existing Auth user is NEVER converted without --adopt; --adopt refuses an account that has been used, one
#      that is a partner member and one that is an admin; --adopt of a fresh account makes no POST
#   3. open: the PUT {"ban_duration":"none"} arrives AFTER the window is written (the listener saw the database predicate true); bad --hours and a note with an address are refused by the tool's
#      OWN check with no Auth call
#   4. close: the PUT ban arrives AFTER the window ended (predicate false); a FUTURE window is left in place; sync bans while closed and unbans while open
#   5. a database read that fails is FATAL (sync with an unreachable database: non-zero, no Auth call); an Auth failure is reported and exits non-zero without printing the key
#   6. SUPABASE_URL: exactly https://<host>[:port]; look-alike hosts, userinfo, a path, plain http to a remote host and local http without the test switch are refused BEFORE curl is started
#   7. wrappers around psql, jq and curl log every argument and the secret-bearing environment of every invocation: the address and the key appear in NONE of them, no temp file is created,
#      and a positive control proves the logger would have caught them
#   everything this seeds is removed by the EXIT trap (auth.users rows cannot be deleted by service_role; the harness leaves them, with random addresses).
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-review-account-tool.sh   (tools/db/test.sh calls it after the matrix, against the same cluster)
# Needs python3 (stdlib), jq, curl, psql. No secret: every address is synthetic (example.test, random per run) and the "service-role key" is random per run.

set -euo pipefail

: "${PGHOST:?tools/db/test-review-account-tool.sh: PGHOST must be set}"
: "${PGPORT:?PGPORT must be set}"
: "${PGUSER:?PGUSER must be set}"
: "${PGDATABASE:?PGDATABASE must be set}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT_DIR/tools/review-account/review-account.sh"
LISTENER="$ROOT_DIR/tools/db/review-account-listener.py"
REAL_PSQL="$(command -v "${PSQL_BIN:-psql}")"
REAL_JQ="$(command -v jq)"
REAL_CURL="$(command -v curl)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rev-tool-test.XXXXXX")"
mkdir -p "$WORK/tmp" "$WORK/wrap"
LOG="$WORK/listener.jsonl"; : > "$LOG"
ARGV_LOG="$WORK/argv.log"; : > "$ARGV_LOG"
ENV_LOG="$WORK/env.log"; : > "$ENV_LOG"
RND="$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
KEY="k$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NEW_EMAIL="rev-tool-new-$RND@example.test"
PLAYER_EMAIL="rev-tool-player-$RND@example.test"
ADOPT_EMAIL="rev-tool-adopt-$RND@example.test"
PM_EMAIL="rev-tool-pm-$RND@example.test"
AD_EMAIL="rev-tool-admin-$RND@example.test"
ALL_ADDRESSES=("$NEW_EMAIL" "$PLAYER_EMAIL" "$ADOPT_EMAIL" "$PM_EMAIL" "$AD_EMAIL")

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }
psql_q() { printf '%s\n' "SET ROLE service_role; $1" | "$REAL_PSQL" -X -q -A -t -v ON_ERROR_STOP=1; }
# the cleanup role: the table owner / harness role itself (service_role holds no DELETE on partner_member's authority trail in every mode)
psql_o() { printf '%s\n' "$1" | "$REAL_PSQL" -X -q -A -t -v ON_ERROR_STOP=1; }

ORIG_DEMO="$(psql_q "SELECT string_agg(user_id::text, ',') FROM app.app_review_demo_account" || true)"
LISTENER_PID=""
cleanup() {
  [ -z "$LISTENER_PID" ] || kill "$LISTENER_PID" 2>/dev/null || true
  psql_o "GRANT SELECT, INSERT, UPDATE, DELETE ON app.app_review_demo_account TO service_role" >/dev/null 2>&1 || true
  psql_o "ALTER TABLE app.app_review_demo_account DISABLE TRIGGER review_account_retire_guard_trg" >/dev/null 2>&1 || true   # a retired row is kept while its Auth user exists; this harness cannot delete auth.users
  psql_q "DELETE FROM app.app_review_window WHERE note LIKE 'rev-tool-test%'; DELETE FROM app.app_review_demo_account; DELETE FROM app.partner_member WHERE user_id IN (SELECT id FROM auth.users WHERE email LIKE 'rev-tool-%@example.test'); DELETE FROM app.admin_user WHERE user_id IN (SELECT id FROM auth.users WHERE email LIKE 'rev-tool-%@example.test'); DELETE FROM app.push_token WHERE user_id IN (SELECT id FROM auth.users WHERE email LIKE 'rev-tool-%@example.test'); DELETE FROM app.device WHERE user_id IN (SELECT id FROM auth.users WHERE email LIKE 'rev-tool-%@example.test');" >/dev/null 2>&1 || true
  psql_o "ALTER TABLE app.app_review_demo_account ENABLE TRIGGER review_account_retire_guard_trg" >/dev/null 2>&1 || true
  if [ -n "${ORIG_DEMO:-}" ]; then
    IFS=',' read -ra OU <<< "$ORIG_DEMO"
    for u in "${OU[@]}"; do psql_q "INSERT INTO app.app_review_demo_account (user_id) VALUES ('$u') ON CONFLICT DO NOTHING" >/dev/null 2>&1 || true; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- the wrappers: log every argument and the secret-bearing environment, then run the REAL program
for pair in "psql:$REAL_PSQL" "jq:$REAL_JQ" "curl:$REAL_CURL"; do
  name="${pair%%:*}"; real="${pair#*:}"
  cat > "$WORK/wrap/$name" <<EOF
#!/usr/bin/env bash
{ printf '%s' '$name'; printf ' %q' "\$@"; printf '\n'; } >> "$ARGV_LOG"
env | grep -E '^(REVIEW_ACCOUNT_EMAIL|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_URL)=' >> "$ENV_LOG" || true
exec '$real' "\$@"
EOF
  chmod +x "$WORK/wrap/$name"
done

psql_o "ALTER TABLE app.app_review_demo_account DISABLE TRIGGER review_account_retire_guard_trg"
psql_q "DELETE FROM app.app_review_window WHERE note LIKE 'rev-tool-test%'; DELETE FROM app.app_review_demo_account;" >/dev/null
psql_o "ALTER TABLE app.app_review_demo_account ENABLE TRIGGER review_account_retire_guard_trg"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "a window is open before the proof starts"

# ---- the listener (a real HTTP server), started before PATH is changed so its own psql is the real one
python3 "$LISTENER" --portfile "$WORK/port" --log "$LOG" --fail-file "$WORK/fail" &
LISTENER_PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
PORT="$(cat "$WORK/port")"
[ -n "$PORT" ] || fail "the listener did not start"

# no proxy for the local listener (and none for anything else: the tool is exercised against 127.0.0.1 only, bar the one well-formed-https case below, which is pointed at a dead local proxy)
run_tool() { env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy PATH="$WORK/wrap:$PATH" TMPDIR="$WORK/tmp" GOLFRAVEN_REVIEW_ALLOW_LOCAL=1 SUPABASE_URL="${TOOL_URL:-http://127.0.0.1:$PORT}" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" "$@"; }
reqs_since() { tail -n +"$(($1 + 1))" "$LOG"; }
nlog() { wc -l < "$LOG" | tr -d ' '; }
nth() { reqs_since "$1" | sed -n "${2}p"; }
jqe() { local json="$1" expr="$2"; shift 2; printf '%s' "$json" | "$REAL_JQ" -e "$expr" "$@" >/dev/null; }
no_secrets() { # TEXT label
  local a
  case "$1" in *"$KEY"*) fail "$2 printed the service key" ;; esac
  for a in "${ALL_ADDRESSES[@]}"; do case "$1" in *"$a"*) fail "$2 printed an address" ;; esac; done
}
demo_count() { psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE retired_at IS NULL"; }   # ACTIVE accounts
retired_count() { psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE retired_at IS NOT NULL"; }
mkuser() { psql_q "INSERT INTO auth.users (id, email) VALUES (gen_random_uuid(), '$1') RETURNING id" | head -1; }

# ============================================================================ 1. provision a NEW address
N0="$(nlog)"
OUT="$(printf '%s\n' "$NEW_EMAIL" | run_tool provision 2>&1)" || fail "provision failed: $OUT"
no_secrets "$OUT" provision
[ "$(demo_count)" = "1" ] || fail "provision did not mark the review account"
UID1="$(psql_q "SELECT user_id FROM app.app_review_demo_account WHERE retired_at IS NULL")"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "2" ] || fail "provision made $(reqs_since "$N0" | wc -l) Auth calls, expected 2 (create, ban)"
R1="$(nth "$N0" 1)"; R2="$(nth "$N0" 2)"
jqe "$R1" '.method == "POST" and .path == "/auth/v1/admin/users" and .authorization == ("Bearer " + $k) and .apikey == $k and .content_type == "application/json"' --arg k "$KEY" || fail "the create call has the wrong method, path or headers: $R1"
jqe "$R1" '(.body_raw | fromjson) == {email: $e, email_confirm: true, ban_duration: "876000h"}' --arg e "$NEW_EMAIL" || fail "the create call's PARSED body is not {email, email_confirm: true, ban_duration: 876000h}"
jqe "$R2" '.method == "PUT" and .path == ("/auth/v1/admin/users/" + $u) and .authorization == ("Bearer " + $k) and .apikey == $k and (.body_raw | fromjson) == {ban_duration: "876000h"} and .window_open_at_call == "f"' --arg u "$UID1" --arg k "$KEY" || fail "the ban call is wrong: $R2"
ok "provision (new address): POST create with the right headers and parsed body, then PUT ban {876000h} while closed; the review row exists; nothing printed names the address or the key"

N0="$(nlog)"
OUT="$(printf '%s\n' "$NEW_EMAIL" | run_tool provision 2>&1)" || fail "second provision failed: $OUT"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] || fail "re-provision made more than the one ban call"
jqe "$(nth "$N0" 1)" '.method == "PUT"' || fail "re-provision did not just ban"
[ "$(demo_count)" = "1" ] || fail "re-provision made a second row"
ok "provision is idempotent on the same address (no second create)"

# a non-ASCII address is refused even under a UTF-8 locale (where [:print:] would accept an accented letter): the check runs under LC_ALL=C
N0="$(nlog)"
if OUT="$(printf 'ren\303\251-%s@example.test\n' "$RND" | LC_ALL=C.utf8 run_tool provision 2>&1)"; then fail "a non-ASCII address was accepted under a UTF-8 locale"; fi
case "$OUT" in *"printable ASCII"*) ;; *) fail "the non-ASCII refusal was not the ASCII check: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "an Auth call was made for a refused non-ASCII address"
ok "a non-ASCII address is refused under a UTF-8 locale (the printable check runs under LC_ALL=C)"

# ============================================================================ 2. one account; never convert an existing user; --adopt guards
PLAYER_UID="$(mkuser "$PLAYER_EMAIL")"
N0="$(nlog)"
if OUT="$(printf '%s\n' "$PLAYER_EMAIL" | run_tool provision 2>&1)"; then fail "a SECOND review account was provisioned"; fi
case "$OUT" in *"at most one"*) ;; *) fail "the second-account refusal was not the one-account check: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "an Auth call was made for a refused second account"
ok "at most ONE review account: a different address is refused with the tool's own message and no Auth call"

psql_q "DELETE FROM app.app_review_demo_account" >/dev/null
if OUT="$(printf '%s\n' "$PLAYER_EMAIL" | run_tool provision 2>&1)"; then fail "an existing player was converted without --adopt"; fi
case "$OUT" in *"Refusing to turn an existing account"*) ;; *) fail "refusal was not the existing-account check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] && [ "$(nlog)" = "$N0" ] || fail "a refused conversion still wrote or called something"
ok "an address that already has an Auth user is refused without --adopt (a typo cannot convert a real player)"

psql_q "INSERT INTO app.device (id, user_id, platform) VALUES (gen_random_uuid(), '$PLAYER_UID', 'android')" >/dev/null
if OUT="$(printf '%s\n' "$PLAYER_EMAIL" | run_tool provision --adopt 2>&1)"; then fail "--adopt converted a USED account"; fi
case "$OUT" in *"has been used"*) ;; *) fail "the --adopt refusal was not the used-account check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] && [ "$(nlog)" = "$N0" ] || fail "a refused adopt still wrote or called something"
ok "--adopt refuses an account that has been used"

# a never-used-looking account that HAS signed in (auth.users.last_sign_in_at) is refused too: no table row of ours is needed to tell it is a real person
SI_EMAIL="rev-tool-signedin-$RND@example.test"; ALL_ADDRESSES+=("$SI_EMAIL")
SI_UID="$(mkuser "$SI_EMAIL")"
psql_q "UPDATE auth.users SET last_sign_in_at = now() WHERE id = '$SI_UID'" >/dev/null
if OUT="$(printf '%s\n' "$SI_EMAIL" | run_tool provision --adopt 2>&1)"; then fail "--adopt converted an account that has SIGNED IN"; fi
case "$OUT" in *"has been used"*) ;; *) fail "the refusal was not the used-account check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] && [ "$(nlog)" = "$N0" ] || fail "a refused adopt of a signed-in account still wrote or called something"
ok "--adopt refuses an account whose auth.users.last_sign_in_at is set"

# a push token with NO device of the account's own (app.push_token's device FK only needs SOME device: here the player's, above): the push_token clause alone must refuse it
PT_EMAIL="rev-tool-push-$RND@example.test"; ALL_ADDRESSES+=("$PT_EMAIL")
PT_UID="$(mkuser "$PT_EMAIL")"
psql_q "INSERT INTO app.push_token (user_id, device_id, expo_token) SELECT '$PT_UID', id, 'ExponentPushToken[rev-tool-test]' FROM app.device WHERE user_id = '$PLAYER_UID' LIMIT 1" >/dev/null
[ "$(psql_q "SELECT count(*) FROM app.push_token WHERE user_id = '$PT_UID'")" = "1" ] && [ "$(psql_q "SELECT count(*) FROM app.device WHERE user_id = '$PT_UID'")" = "0" ] || fail "the push-token fixture is wrong (it must have a token and no device of its own)"
if OUT="$(printf '%s\n' "$PT_EMAIL" | run_tool provision --adopt 2>&1)"; then fail "--adopt converted an account that holds a PUSH TOKEN"; fi
case "$OUT" in *"has been used"*) ;; *) fail "the refusal was not the used-account check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] && [ "$(nlog)" = "$N0" ] || fail "a refused adopt of a push-token account still wrote or called something"
ok "--adopt refuses an account that holds a push token (its own check, no device of its own needed)"

PM_UID="$(mkuser "$PM_EMAIL")"
psql_q "INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('$PM_UID', '10000000-0000-0000-0000-000000000001', 'staff')" >/dev/null
if OUT="$(printf '%s\n' "$PM_EMAIL" | run_tool provision --adopt 2>&1)"; then fail "--adopt converted a PARTNER MEMBER"; fi
case "$OUT" in *"partner role or is an admin"*) ;; *) fail "the refusal was not the partner check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] || fail "a partner member was marked the review account"
AD_UID="$(mkuser "$AD_EMAIL")"
psql_q "INSERT INTO app.admin_user (user_id) VALUES ('$AD_UID')" >/dev/null
if OUT="$(printf '%s\n' "$AD_EMAIL" | run_tool provision --adopt 2>&1)"; then fail "--adopt converted an ADMIN"; fi
case "$OUT" in *"partner role or is an admin"*) ;; *) fail "the refusal was not the admin check: $OUT" ;; esac
[ "$(demo_count)" = "0" ] && [ "$(nlog)" = "$N0" ] || fail "a refused adopt still wrote or called something"
ok "--adopt refuses a partner member and an admin (no partner scope), with no Auth call"

# a fresh, unused account IS adopted (address through the ENVIRONMENT this time): no create, one ban
ADOPT_UID="$(mkuser "$ADOPT_EMAIL")"
OUT="$(REVIEW_ACCOUNT_EMAIL="$ADOPT_EMAIL" run_tool provision --adopt </dev/null 2>&1)" || fail "--adopt of a fresh account failed: $OUT"
no_secrets "$OUT" "provision --adopt"
[ "$(psql_q "SELECT user_id FROM app.app_review_demo_account WHERE retired_at IS NULL")" = "$ADOPT_UID" ] || fail "the fresh account was not marked"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] && jqe "$(nth "$N0" 1)" '.method == "PUT" and (.body_raw | fromjson) == {ban_duration: "876000h"}' || fail "--adopt of a fresh account must make exactly one ban call and no create"
ok "--adopt of a fresh, unused account marks it and bans it (no create), address given through REVIEW_ACCOUNT_EMAIL"
UID1="$ADOPT_UID"

# ============================================================================ 3. open: the unban comes AFTER the window is written
N0="$(nlog)"
for bad in 0 1441 abc "" "-3"; do
  if OUT="$(run_tool open --hours "$bad" 2>&1)"; then fail "open accepted --hours '$bad'"; fi
  case "$OUT" in *"--hours"*) ;; *) fail "open --hours '$bad' was not refused by the tool's own check: $OUT" ;; esac
done
if OUT="$(run_tool open --hours 2 --note "rev-tool-test x@y.test" 2>&1)"; then fail "open accepted an address in the note"; fi
case "$OUT" in *"must not contain an email"*) ;; *) fail "the note refusal was not the tool's own: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] && [ "$(psql_q "SELECT count(*) FROM app.app_review_window WHERE note LIKE 'rev-tool-test%'")" = "0" ] || fail "a refused open wrote a window or called Auth"
OUT="$(run_tool open --hours 2 --note "rev-tool-test open" 2>&1)" || fail "open failed: $OUT"
no_secrets "$OUT" open
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] || fail "open made $(reqs_since "$N0" | wc -l) Auth calls, expected 1 (unban)"
R="$(nth "$N0" 1)"
jqe "$R" '.method == "PUT" and .path == ("/auth/v1/admin/users/" + $u) and (.body_raw | fromjson) == {ban_duration: "none"}' --arg u "$UID1" || fail "the unban call is wrong: $R"
jqe "$R" '.window_open_at_call == "t"' || fail "ORDER: the unban arrived before the window was written (the database said closed at that instant)"
[ "$(psql_q "SELECT count(*) FROM app.app_review_window WHERE note = 'rev-tool-test open' AND ends_at - starts_at = interval '2 hours'")" = "1" ] || fail "open wrote the wrong window"
ok "open: refused inputs make no call and no window; PUT {ban_duration: none} arrives AFTER the window is written (database predicate true at that instant)"

# ============================================================================ 4. close and sync
N0="$(nlog)"
psql_q "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now() + interval '3 days', now() + interval '4 days', 'rev-tool-test future')" >/dev/null
OUT="$(run_tool close 2>&1)" || fail "close failed: $OUT"
no_secrets "$OUT" close
R="$(nth "$N0" 1)"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] && jqe "$R" '.method == "PUT" and (.body_raw | fromjson) == {ban_duration: "876000h"}' || fail "close must make exactly one ban call"
jqe "$R" '.window_open_at_call == "f"' || fail "ORDER: the ban arrived while the window was still open (close must end the window FIRST)"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "close left the window open"
[ "$(psql_q "SELECT count(*) FROM app.app_review_window WHERE note = 'rev-tool-test future'")" = "1" ] || fail "close removed a FUTURE window"
ok "close: the window ends BEFORE the ban call (predicate false at that instant), one ban, and a future window is left in place"

N0="$(nlog)"
run_tool sync >/dev/null 2>&1 || fail "sync (closed) failed"
jqe "$(nth "$N0" 1)" '(.body_raw | fromjson) == {ban_duration: "876000h"}' || fail "sync while closed must ban"
psql_q "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now() - interval '1 minute', now() + interval '1 hour', 'rev-tool-test live')" >/dev/null
N0="$(nlog)"
run_tool sync >/dev/null 2>&1 || fail "sync (open) failed"
jqe "$(nth "$N0" 1)" '(.body_raw | fromjson) == {ban_duration: "none"}' || fail "sync while open must clear the ban"
psql_q "DELETE FROM app.app_review_window WHERE note = 'rev-tool-test live'" >/dev/null
ok "sync: bans while closed, clears the ban while open"

# ============================================================================ 5. a failing database read is FATAL; an Auth failure is loud
N0="$(nlog)"
if OUT="$(PGPORT=1 run_tool sync 2>&1)"; then fail "sync with an unreachable database SUCCEEDED"; fi
case "$OUT" in *"could not read the window state"*) ;; *) fail "sync with an unreachable database did not say so: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "sync with an unreachable database still made an Auth call"
if OUT="$(PGPORT=1 run_tool close 2>&1)"; then fail "close with an unreachable database SUCCEEDED"; fi
# the window read works but the ACCOUNT LIST fails (the login lost SELECT on the table): still fatal, never "no accounts, nothing to do"
psql_o "REVOKE SELECT ON app.app_review_demo_account FROM service_role"
if OUT="$(run_tool sync 2>&1)"; then psql_o "GRANT SELECT, INSERT, UPDATE, DELETE ON app.app_review_demo_account TO service_role"; fail "sync SUCCEEDED although the review accounts could not be listed"; fi
psql_o "GRANT SELECT, INSERT, UPDATE, DELETE ON app.app_review_demo_account TO service_role"
case "$OUT" in *"could not list the review accounts"*) ;; *) fail "a failed account listing was not reported as such: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "sync with a failed account listing still made an Auth call"
ok "a failing database read is fatal: sync and close exit non-zero, say so, and make no Auth call (window read failing, and account listing failing)"

: > "$WORK/fail"
N0="$(nlog)"
if OUT="$(run_tool open --hours 1 --note "rev-tool-test authfail" 2>&1)"; then fail "open SUCCEEDED while the Auth call failed"; fi
no_secrets "$OUT" "a failing open"
case "$OUT" in *"HTTP 500"*) ;; *) fail "the Auth failure was not reported: $OUT" ;; esac
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "t" ] || fail "the window was not written before the Auth call (the order)"
rm -f "$WORK/fail"
run_tool close >/dev/null 2>&1 || fail "close after the failure failed"
ok "an Auth failure exits non-zero and is reported (HTTP status only, no key); the window had been written first, so the failure leaves GoTrue banned: the safe direction"

# ============================================================================ 5b. retire = close, ban, mark retired: the row is NEVER deleted
[ "$(demo_count)" = "1" ] || fail "no active review account to retire in the test"
psql_q "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now() - interval '1 minute', now() + interval '1 hour', 'rev-tool-test retire-open')" >/dev/null
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "t" ] || fail "the retire proof needs an open window"
N0="$(nlog)"
OUT="$(run_tool retire 2>&1)" || fail "retire failed: $OUT"
no_secrets "$OUT" retire
case "$OUT" in *"is banned"*"KEPT"*) ;; *) fail "retire (api mode) did not report ban + kept row: $OUT" ;; esac
R="$(nth "$N0" 1)"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] && jqe "$R" '.method == "PUT" and .path == ("/auth/v1/admin/users/" + $u) and (.body_raw | fromjson) == {ban_duration: "876000h"}' --arg u "$UID1" || fail "retire must make exactly one ban call for the old account"
jqe "$R" '.window_open_at_call == "f"' || fail "ORDER: the ban arrived while a window was still open (retire must CLOSE first)"
jqe "$R" '.demo_rows_at_call == "1" and .retired_rows_at_call == "0"' || fail "ORDER: at the ban the row must exist and not yet be retired (close, THEN ban, THEN mark retired)"
[ "$(demo_count)" = "0" ] && [ "$(retired_count)" = "1" ] || fail "retire must leave the row, marked retired (and no active account)"
[ "$(psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '$UID1' AND retired_at IS NOT NULL")" = "1" ] || fail "the retired row is not the old account's"
[ "$(psql_q "SELECT private.is_demo_account('$UID1')")" = "t" ] || fail "a retired account must STAY a review account (is_demo_account)"
[ "$(psql_q "SELECT private.review_window_open_at(clock_timestamp())")" = "f" ] || fail "retire left a window open"
if OUT="$(run_tool retire 2>&1)"; then fail "retire with no active review account succeeded"; fi
case "$OUT" in *"no active review account to retire"*) ;; *) fail "retire with nothing to retire did not say so: $OUT" ;; esac
# a window OPEN and the retired account stays banned: sync never clears a retired account's ban
psql_q "INSERT INTO app.app_review_window (starts_at, ends_at, note) VALUES (now() - interval '1 minute', now() + interval '1 hour', 'rev-tool-test retired-sync')" >/dev/null
N0="$(nlog)"
run_tool sync >/dev/null 2>&1 || fail "sync with a retired account failed"
[ "$(reqs_since "$N0" | wc -l | tr -d ' ')" = "1" ] && jqe "$(nth "$N0" 1)" '(.body_raw | fromjson) == {ban_duration: "876000h"}' || fail "sync with a window OPEN must keep a retired account banned (one ban call, never 'none')"
psql_q "DELETE FROM app.app_review_window WHERE note = 'rev-tool-test retired-sync'" >/dev/null
# a retired address is never re-activated
for flag in "" "--adopt"; do
  if OUT="$(printf '%s\n' "$ADOPT_EMAIL" | run_tool provision $flag 2>&1)"; then fail "a RETIRED account was provisioned again ($flag)"; fi
  case "$OUT" in *"RETIRED review account"*) ;; *) fail "the refusal of a retired address was not the retired check ($flag): $OUT" ;; esac
done
[ "$(demo_count)" = "0" ] || fail "a refused re-provision still made an active account"
ok "retire: closes the open window, then bans the Auth user, then marks the row retired; the row is KEPT (is_demo_account true); sync keeps it banned while a window is open; a retired address cannot be provisioned again"

# retire in skip mode: no Auth call is made, so it must NOT claim a ban, must say what to do by hand, and exits 3 with the database side done
SKIP_EMAIL="rev-tool-skip-$RND@example.test"; ALL_ADDRESSES+=("$SKIP_EMAIL")
SKIP_UID="$(mkuser "$SKIP_EMAIL")"
printf '%s\n' "$SKIP_EMAIL" | run_tool provision --adopt >/dev/null 2>&1 || fail "could not provision the skip-mode account"
N0="$(nlog)"
set +e; OUT="$(GOLFRAVEN_REVIEW_AUTH=skip run_tool retire 2>&1)"; RC=$?; set -e
[ "$RC" = "3" ] || fail "retire in skip mode must exit 3 (database done, Auth ban still to do by hand), got $RC: $OUT"
case "$OUT" in *"ACTION REQUIRED"*"dashboard"*) ;; *) fail "retire in skip mode did not say what to do by hand: $OUT" ;; esac
case "$OUT" in *"RETIRED IN THE DATABASE"*) ;; *) fail "retire in skip mode did not say the account is retired in the database: $OUT" ;; esac
case "$(printf '%s' "$OUT" | tr 'A-Z' 'a-z')" in *banned*) fail "retire in skip mode printed the word banned: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "retire in skip mode made an Auth call"
[ "$(psql_q "SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '$SKIP_UID' AND retired_at IS NOT NULL")" = "1" ] || fail "retire in skip mode did not retire the row in the database"
ok "retire in skip mode: retired in the database (row kept), says ACTION REQUIRED: ban in the dashboard, never claims a ban, makes no Auth call, exits 3"
# sync in skip mode (gate NIT): no Auth call, so its summary must never claim a ban or a clear
N0="$(nlog)"
set +e; OUT="$(GOLFRAVEN_REVIEW_AUTH=skip run_tool sync 2>&1)"; RC=$?; set -e
[ "$RC" = "0" ] || fail "sync in skip mode must still exit 0, got $RC: $OUT"
case "$(printf '%s' "$OUT" | tr 'A-Z' 'a-z')" in *"banned in auth"*|*"cleared of the auth ban"*) fail "sync in skip mode claimed an Auth change: $OUT" ;; esac
case "$OUT" in *"Auth NOT changed"*"dashboard"*) ;; *) fail "sync in skip mode did not say Auth was not changed: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] || fail "sync in skip mode made an Auth call"
ok "sync in skip mode: no Auth call, exit 0, and the summary says Auth was NOT changed instead of claiming a ban"

# an active account again for the sections below, through the api
N0="$(nlog)"
NEW2_EMAIL="rev-tool-new2-$RND@example.test"; ALL_ADDRESSES+=("$NEW2_EMAIL")
OUT="$(printf '%s\n' "$NEW2_EMAIL" | run_tool provision 2>&1)" || fail "provision after retire failed: $OUT"
UID1="$(psql_q "SELECT user_id FROM app.app_review_demo_account WHERE retired_at IS NULL")"
[ "$(demo_count)" = "1" ] && [ "$(retired_count)" = "2" ] || fail "expected one active and two retired accounts"
if OUT="$(printf '%s\n' "$PLAYER_EMAIL" | run_tool provision 2>&1)"; then fail "a second ACTIVE review account was provisioned"; fi
case "$OUT" in *"run the retire command"*) ;; *) fail "the one-account refusal does not point at retire: $OUT" ;; esac
ok "retired accounts do not count as the active one (a new account provisions); a second ACTIVE one is still refused and the refusal points at retire"

# ============================================================================ 6. the URL, exactly
BAD_URLS=("http://example.test" "https://user:pw@example.test" "https://example.test/path" "https://example.test:99999x" "https://" "https://exa mple.test" "ftp://example.test"
          "http://localhost.evil:$PORT" "http://127.0.0.1.nip.io:$PORT" "http://127.0.0.1@evil.test:$PORT" "http://127.0.0.1:$PORT/evil" "http://localhost@127.0.0.1:$PORT" "https://example.test?x=1" "https://example.test#frag")
N0="$(nlog)"; C0="$(grep -c '^curl ' "$ARGV_LOG" || true)"
for u in "${BAD_URLS[@]}"; do
  if OUT="$(TOOL_URL="$u" run_tool sync 2>&1)"; then fail "sync accepted the URL '$u'"; fi
  case "$OUT" in *"must be exactly https"*) ;; *) fail "the URL '$u' was not refused by the URL check: $OUT" ;; esac
done
# local http without the test switch
if OUT="$(env PATH="$WORK/wrap:$PATH" SUPABASE_URL="http://127.0.0.1:$PORT" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" sync 2>&1)"; then fail "local http was accepted without GOLFRAVEN_REVIEW_ALLOW_LOCAL"; fi
case "$OUT" in *"must be exactly https"*) ;; *) fail "local http without the switch was not refused by the URL check: $OUT" ;; esac
[ "$(nlog)" = "$N0" ] && [ "$(grep -c '^curl ' "$ARGV_LOG" || true)" = "$C0" ] || fail "curl was STARTED for a refused URL"
OUT="$(env HTTPS_PROXY="http://127.0.0.1:1" https_proxy="http://127.0.0.1:1" PATH="$WORK/wrap:$PATH" SUPABASE_URL="https://example.invalid" SUPABASE_SERVICE_ROLE_KEY="$KEY" bash "$TOOL" sync 2>&1)" && fail "an unreachable https host succeeded" || true
case "$OUT" in *"must be exactly https"*) fail "a well-formed https URL was refused by the URL check: $OUT" ;; esac
ok "SUPABASE_URL: ${#BAD_URLS[@]} look-alike / userinfo / path / plain-http / bare-local URLs are refused before curl starts; a well-formed https URL passes the check"

# ============================================================================ 7. no address, no key on any command line or in any child's environment; no temp file
for name in psql jq curl; do grep -q "^$name " "$ARGV_LOG" || fail "the $name wrapper logged nothing: the check below would be vacuous"; done
for a in "${ALL_ADDRESSES[@]}"; do
  ! grep -qF "$a" "$ARGV_LOG" || fail "an address appeared on a psql / jq / curl COMMAND LINE"
  ! grep -qF "$a" "$ENV_LOG" || fail "an address was inherited by a child process (REVIEW_ACCOUNT_EMAIL was not unset)"
done
! grep -qF "$KEY" "$ARGV_LOG" || fail "the service key appeared on a command line"
! grep -qF "$KEY" "$ENV_LOG" || fail "the service key was inherited by a child process"
[ -z "$(ls -A "$WORK/tmp")" ] || fail "the tool left a temp file (the response body names the address)"
# positive control: the logger WOULD have caught them
CTL="ctl-$RND"
env PATH="$WORK/wrap:$PATH" REVIEW_ACCOUNT_EMAIL="$CTL" SUPABASE_SERVICE_ROLE_KEY="$CTL-key" jq -n 1 >/dev/null
grep -qF "$CTL" "$ENV_LOG" && grep -qF "$CTL-key" "$ENV_LOG" || fail "the environment logger is blind (control)"
env PATH="$WORK/wrap:$PATH" jq -n --arg a "$CTL" '$a' >/dev/null
grep -qF "$CTL" "$ARGV_LOG" || fail "the argv logger is blind (control)"
ok "no address or key on any psql / jq / curl command line or in any child environment; no temp file; the loggers are proven live by a control"

echo "tools/db/test-review-account-tool.sh: all review-account tool checks passed"
