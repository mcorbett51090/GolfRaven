// supabase/functions/_shared/privileged.ts
// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1183-1205): "Every
// write runs as service_role, which bypasses RLS. The authorization
// boundary on writes is therefore each Edge Function's own ownership and
// scope check... Writes and privileged reads go only through
// supabase/functions/_shared/privileged.ts -> withOwnership(actor, op)."
//
// THIS FILE is the SOLE allow-listed construction site for a service-role
// client (tools/service-role-lint rule (a)) and the sole allow-listed
// place a raw `.from()`/`.rpc()`/Storage call, a Postgres driver import,
// or `SUPABASE_DB_URL`/`SUPABASE_SERVICE_ROLE_KEY` may appear (rules (b),
// (c)) — `tools/service-role-lint/src/lint.ts`'s `isAllowedFile` exempts
// this EXACT path (`supabase/functions/_shared/privileged.ts`) from every
// one of its checks; see that file's own header comment.
//
// WHY A DIRECT POSTGRES CONNECTION, NOT supabase-js `.from()`/`.rpc()`:
// `supabase/config.toml` sets `db.schemas = ["api"]` — PostgREST (which
// `supabase-js` talks to) exposes ONLY the `api` schema. Every table this
// round's endpoints read or write (`app.evidence`, `app.play`,
// `app.checkin_challenge`, `app.catalog_id_ledger`, ...) lives in `app`,
// and the rate-limit helper this round calls (`private.hit_rate_limit`)
// lives in `private` — NEITHER is PostgREST-exposed, at any role, so
// there is no `supabase-js` call shape that could ever reach them. A
// direct Postgres connection is the only way to reach them at all, which
// is exactly what the lint's rule (c) anticipates by naming
// `SUPABASE_DB_URL`/a Postgres driver import as a legitimate,
// privileged.ts-only shape.
//
// ⛔ P3c gate round 2 ("Conditions on the BYPASSRLS design", required):
// the connection string's own role is `[unverified]` to be `service_role`
// itself on the REAL hosted project — it may well be `postgres` (or
// another admin-ish role), per the gate's own note. This file no longer
// assumes it: `withOwnership` runs `SET LOCAL ROLE service_role` as the
// FIRST statement of every transaction and asserts `current_user` came
// back as `service_role` before building a `Repo` at all — see
// `withOwnership`'s own body. If the connecting role can't assume
// `service_role` (no membership, wrong grant), every request fails
// closed with a clear error instead of silently running as whatever role
// actually connected. No per-request GUC is used anywhere in this file —
// every query parameterizes `actor.uid`/ids directly as bound values, so
// there is nothing here for `SET LOCAL` + `nullif(current_setting(...))`
// to apply to; noted because the gate asked for this to be stated
// explicitly, not left implicit.
//
// [unverified — this session confirmed `deno eval`/`deno check`/`deno
// test` can import and resolve `postgres` (now via
// supabase/functions/deno.json's import map — see the should-fix note
// below) and `@supabase/supabase-js` (still a direct pinned URL — see
// that same note for why) over this session's network proxy, and
// separately confirmed Deno 2.5.2's `crypto.subtle` supports Ed25519
// (catalog/signature.ts) — neither confirms this exact driver version
// behaves identically inside the REAL hosted Supabase Edge Runtime,
// which this session has no access to. Flagged per this repo's own
// accuracy discipline, alongside the pre-existing "pin --config at
// deploy time" unverified flag in
// docs/security/p3-money-path-requirements.md.]
//
// ⛔ FIX, PARTIAL (P3c gate round 2, should-fix "supply chain"): both of
// these used to be raw `https://` string-literal imports, invisible to
// tools/service-role-lint's own pinned-target discipline in a way no
// OTHER third-party dependency in this codebase is (zod/@noble/hashes/
// tz-lookup all resolve through the reviewed
// supabase/functions/deno.json import map + pinned-import-targets.json
// allow-list — see generate-bundle.sh's own header for why). `postgres`
// is now a bare specifier through that SAME reviewed map — privileged.ts
// itself stays exempt from the lint's AST content scan (rule (a)/(b)/(c)
// — it legitimately needs the raw env access / client construction every
// other file is banned from), but this ONE import's GRAPH is no longer a
// special case: config.ts's own model validates every deno.json's
// import-map target against pinned-import-targets.json regardless of
// which file resolves through it, so bumping this pin now means touching
// the SAME two reviewed, diffable files every other dependency bump
// already requires.
// `@supabase/supabase-js` could NOT be moved the same way — confirmed
// this round: tools/service-role-lint/src/config.ts unconditionally bans
// ANY import-map entry whose value contains "@supabase/" or
// "supabase-js", regardless of pinning (`upper.includes("@SUPABASE/") ||
// upper.includes("SUPABASE-JS")`, checked before the pinned-allow-list
// lookup even runs) — a deliberate, pre-existing hardened rule closing
// exactly the evasion this move would otherwise open: routing a
// service-role-shaped client through the import map from a file OTHER
// than privileged.ts, invisible to the AST's own specifier-text ban.
// `@supabase/supabase-js` therefore stays a direct pinned URL, same as
// before this round — the exemption for THIS ONE import is inherent to
// the lint's own design, not an oversight to "remove".
import postgres from "postgres";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
import { Errors, HttpError } from "./http.ts";

import type { OwnReward, RewardsRepo } from "./rewards/types.ts";
import type { RewardsAttestationConfig } from "./rewards/production-ports.ts";
import type {
  Actor,
  CatalogVersionRow,
  ChallengeRow,
  ConsumedCheckinToken,
  ExistingEvidenceRow,
  ImporterCurrentVersionRow,
  ImporterLedgerRow,
  ImporterRepo,
  ImporterSigningKeyRow,
  ImportVersionInput,
  ImportVersionResult,
  InsertEvidenceResult,
  LedgerBaseRow,
  LedgerRow,
  LedgerStateRow,
  MatchResult,
  NewEvidenceRow,
  QueuedEvidenceRow,
  RateLimitResult,
  Repo,
  RepickRefusal,
  SigningKeyRow,
  StoredEvidenceRow,
  StoredPlayRow,
  UpsertPlayInput,
  UpsertPlayResult,
  CatalogImportEnvConfig,
  RescoreBacklogRow,
  RescoreCursor,
  RescorePlayRef,
  RosterVersionInput,
} from "./types.ts";
// Type-only: erased at runtime, so this does NOT make ABSOLUTE_ROW_CAP a
// second source of truth — it re-reads the SAME constant score-play.ts
// exports, from the SAME vendored file evidence/handler.ts imports (see
// generate-bundle.sh's own doc on why this vendor tree exists at all).
// @deno-types="./scoring/scoring-types.d.ts"
import { ABSOLUTE_ROW_CAP as ABSOLUTE_ROW_CAP_RUNTIME } from "./scoring/vendor/parse-evidence.js";

const ABSOLUTE_ROW_CAP: number = ABSOLUTE_ROW_CAP_RUNTIME as unknown as number;

export type { Actor, Repo } from "./types.ts";

export interface Op<T> {
  (repo: Repo): Promise<T>;
}

/** A single Postgres connection (the pool `postgres()` itself manages) —
 * `TxSql` is what every Repo method actually queries with: the
 * transaction-scoped tagged-template `sql.begin()` hands its callback,
 * NEVER the top-level pool (see `withOwnership`'s own doc, P3c gate
 * round 2 item 2: "every statement autocommits... run each withOwnership
 * callback in ONE sql.begin()"). Typed as `postgres.TransactionSql`
 * (the namespace member `postgres`'s own `.d.ts` merges onto the default
 * export, per `deno.land/x/postgresjs`'s own types) rather than the
 * looser `ReturnType<typeof postgres>` (P3c gate round 3, blocking
 * MEDIUM 4) — `TransactionSql` is the one that actually declares
 * `.savepoint(...)`, which `withOwnershipBatch` below needs typed, not
 * cast through `any`. */
type TxSql = postgres.TransactionSql;

let _sql: ReturnType<typeof postgres> | null = null;

// ============================================================================
// EDGE ROLE (follow-up 6, PR2): the TEMPORARY `EDGE_DB_MODE` switch.
// ============================================================================
// docs/security/edge-role-design.md. `legacy` (the default) is today's path: one
// pool from SUPABASE_DB_URL, `SET LOCAL ROLE service_role` (BYPASSRLS) per
// transaction, ownership enforced only by each Repo method's own `user_id = ${uid}`
// filter. `edge` runs the user-facing paths as `edge_actor` through a pool opened
// from GOLFRAVEN_EDGE_DB_URL (connecting as the NOBYPASSRLS login `edge_gateway`):
// FORCE RLS then backs every Repo method, and the identity is the database-side
// binding `private.bind_actor(uid)` (a forgotten bind fails closed).
//
// Both variables are read ONLY in this file (the lint's allow-listed site). The
// switch is temporary: PR4 flips the default, deletes the legacy path and adds the
// lint pass. Until then every behaviour below is written to be observably the same
// in both modes; the few differences are listed in docs/security/edge-role-design.md
// §9 ("Behaviour differences between the two modes").
//
// PR3 BOUNDARY: the catalog-import system path (`withSystemCatalogImport`, and with
// it `import-catalog`'s importer / drain-read repositories) stays on the LEGACY
// pool in `edge` mode, so `edge` mode with `import-catalog` needs BOTH URLs. The
// per-row user transactions the drains open (`withOwnership`) DO run as edge_actor
// (they bind the row owner with `bind_actor`, not through a delegate binder: PR3
// replaces that with `bind_delegate_*` once the importer repo runs as edge_system).
export type DbMode = "legacy" | "edge";

/** Reads `EDGE_DB_MODE` on every call (cheap; lets a test flip it). Anything but
 * `legacy`/`edge` (or unset = `legacy`) is a configuration error, never a silent default. */
export function getDbMode(): DbMode {
  const raw = Deno.env.get("EDGE_DB_MODE");
  if (raw === undefined || raw === "" || raw === "legacy") return "legacy";
  if (raw === "edge") return "edge";
  throw new Error(`privileged.ts: EDGE_DB_MODE must be 'legacy' or 'edge' (got '${raw}')`);
}

function openPool(dbUrl: string): ReturnType<typeof postgres> {
  return postgres(dbUrl, {
    max: 5,
    prepare: true,
    // ⛔ FIX (P3c gate round 4, blocking HIGH's own fix list, items 3-4):
    // "Set a connect/acquire timeout... Set idle_in_transaction_session_
    // timeout." Neither of these is the ROOT fix (see `hitRateLimitForActor`'s
    // own doc for that) — postgres.js has no acquire-timeout at all (a
    // request queued waiting for a free pooled connection waits forever;
    // `connect_timeout` below bounds only the TCP+auth handshake for a
    // NEW physical connection, not a wait for a pool SLOT), so neither
    // setting can, by itself, prevent the deadlock this round's own
    // reviewer reproduced. They are defense in depth: `connect_timeout`
    // fails fast if the DATABASE itself is unreachable/slow, rather than
    // hanging silently forever the same way an exhausted pool did;
    // `idle_in_transaction_session_timeout` bounds how long ANY
    // connection (this pool's or a future one) can sit idle inside an
    // open transaction before Postgres itself kills it, a backstop
    // against a DIFFERENT future bug of the same shape (something else
    // holding a transaction open indefinitely), not a fix for THIS one.
    connect_timeout: 10, // seconds
    connection: {
      idle_in_transaction_session_timeout: 30_000, // ms
    },
  });
}

function sql(): ReturnType<typeof postgres> {
  if (_sql) return _sql;
  const dbUrl = Deno.env.get("SUPABASE_DB_URL");
  if (!dbUrl) {
    throw new Error("privileged.ts: SUPABASE_DB_URL is not set in this environment");
  }
  _sql = openPool(dbUrl);
  return _sql;
}

let _edgeSql: ReturnType<typeof postgres> | null = null;
let _edgeChecked: Promise<void> | null = null;

function edgeSql(): ReturnType<typeof postgres> {
  if (_edgeSql) return _edgeSql;
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  if (!dbUrl) {
    throw new Error("privileged.ts: EDGE_DB_MODE=edge needs GOLFRAVEN_EDGE_DB_URL (the edge_gateway connection string)");
  }
  _edgeSql = openPool(dbUrl);
  return _edgeSql;
}

/** Roles the edge connection must never reach: the privileged ones PR1's check 9 keeps out of the closure. */
const EDGE_FORBIDDEN_MEMBERSHIPS = ["service_role", "authenticated", "anon", "authenticator", "private_definer", "supabase_admin", "postgres"];

/**
 * The startup self-check (edge mode), run once per pool on its first connection: the
 * session user is `edge_gateway`; nothing in its membership closure (itself included)
 * is a superuser or BYPASSRLS; and it is not a member of `service_role`, `authenticated`
 * (or the other privileged roles above). Any failure rejects with a plain Error — a 500
 * from every handler, i.e. FAILS CLOSED — and is not cached, so the next request
 * re-checks (a misconfiguration is never "remembered as fine", a transient error is retried).
 */
export async function assertEdgeConnectionSafe(db: ReturnType<typeof postgres>): Promise<void> {
  const rows = await db`
    with recursive clo(oid) as (
      select oid from pg_catalog.pg_roles where rolname = session_user
      union
      select m.roleid from pg_catalog.pg_auth_members m join clo c on m.member = c.oid
    )
    select session_user::text as su,
           coalesce(bool_or(r.rolsuper or r.rolbypassrls), false) as privileged,
           coalesce(array_agg(r.rolname::text order by r.rolname::text), '{}'::text[]) as closure
    from clo join pg_catalog.pg_roles r on r.oid = clo.oid`;
  const r = rows[0];
  const closure: string[] = Array.isArray(r?.closure) ? (r.closure as string[]) : [];
  const problems: string[] = [];
  if (r?.su !== "edge_gateway") problems.push(`session_user is '${r?.su}', not 'edge_gateway'`);
  if (r?.privileged) problems.push("a role in its membership closure is SUPERUSER or BYPASSRLS");
  const forbidden = closure.filter((n) => EDGE_FORBIDDEN_MEMBERSHIPS.includes(n));
  if (forbidden.length > 0) problems.push(`it is a member of ${forbidden.join(", ")}`);
  if (problems.length > 0) {
    throw new Error(`privileged.ts: the edge database connection is not acceptable (${problems.join("; ")}) — refusing to run (fail closed)`);
  }
}

function edgeChecked(): Promise<void> {
  if (_edgeChecked) return _edgeChecked;
  const p = assertEdgeConnectionSafe(edgeSql());
  _edgeChecked = p;
  p.catch(() => {
    if (_edgeChecked === p) _edgeChecked = null; // never cache a failure
  });
  return p;
}

/** Tests only: closes both pools and forgets the self-check, so a test can point
 * `GOLFRAVEN_EDGE_DB_URL` / `SUPABASE_DB_URL` somewhere else and start clean. */
export async function resetPrivilegedConnectionsForTests(): Promise<void> {
  const a = _sql;
  const b = _edgeSql;
  _sql = null;
  _edgeSql = null;
  _edgeChecked = null;
  _supportsTransactionTimeout = null;
  await Promise.allSettled([a?.end({ timeout: 1 }), b?.end({ timeout: 1 })]);
}

/** What `openScopedTx` binds. `expectedUid` is the identity the transaction must END UP
 * bound to (null: no actor, the `edge_system` kind); `run` performs the bind. Splitting
 * the two is what makes the post-bind assertion meaningful: it compares the database's own
 * answer (`private.actor_uid()`) with what the CALLER meant, so a bind that bound somebody
 * else fails closed. */
export interface ScopedBind {
  expectedUid: string | null;
  run?: (trx: TxSql) => Promise<unknown>;
}

/** The ordinary user binding: `private.bind_actor(uid)`. */
export function userBind(uid: string): ScopedBind {
  return { expectedUid: uid, run: (trx) => trx`select private.bind_actor(${uid}::uuid)` };
}

/**
 * THE one way an edge-mode transaction is opened (design §6): in order,
 *   1. `SET LOCAL ROLE edge_actor | edge_system` (the session user, `edge_gateway`, may SET into both);
 *   2. the three timeouts (`statement`, `lock`, and `transaction` where PG17+ has it);
 *   3. the bind (`private.bind_actor(uid)`; the system kind binds nothing);
 *   4. an assertion that `current_user` is the expected role, that role is neither SUPERUSER nor
 *      BYPASSRLS, and (actor kind) `private.actor_uid()` equals the expected uid.
 * Any failure throws before `op` runs. The startup self-check has already passed on this pool.
 */
export async function openScopedTx<T>(kind: "actor" | "system", bind: ScopedBind, op: (trx: TxSql) => Promise<T>): Promise<T> {
  await edgeChecked();
  const db = edgeSql();
  const txTimeoutSupported = await supportsTransactionTimeout(db);
  const role = kind === "actor" ? "edge_actor" : "edge_system";
  return await (db.begin(async (trx: TxSql) => {
    // Literal SQL text (no `${...}`): SET LOCAL takes no bind parameter — see the note above STATEMENT_TIMEOUT.
    if (kind === "actor") await trx`set local role edge_actor`;
    else await trx`set local role edge_system`;
    await trx`set local statement_timeout = '10s'`;
    await trx`set local lock_timeout = '5s'`;
    if (txTimeoutSupported) await trx`set local transaction_timeout = '12s'`;
    if (bind.run) await bind.run(trx);
    if (kind === "actor") {
      const check = await trx`
        select current_user::text as u,
               (select r.rolsuper or r.rolbypassrls from pg_catalog.pg_roles r where r.rolname = current_user) as privileged,
               private.actor_uid()::text as actor`;
      const c = check[0];
      if (c?.u !== role) throw new Error(`openScopedTx: expected current_user = '${role}' after SET LOCAL ROLE, got '${c?.u}'`);
      if (c?.privileged !== false) throw new Error(`openScopedTx: role '${role}' is SUPERUSER or BYPASSRLS — refusing to run`);
      if (bind.expectedUid === null || typeof c?.actor !== "string" || c.actor.toLowerCase() !== bind.expectedUid.toLowerCase()) {
        throw new Error(`openScopedTx: the bound actor is '${c?.actor ?? null}', expected '${bind.expectedUid}' — refusing to run`);
      }
    } else {
      const check = await trx`
        select current_user::text as u,
               (select r.rolsuper or r.rolbypassrls from pg_catalog.pg_roles r where r.rolname = current_user) as privileged`;
      const c = check[0];
      if (c?.u !== role) throw new Error(`openScopedTx: expected current_user = '${role}' after SET LOCAL ROLE, got '${c?.u}'`);
      if (c?.privileged !== false) throw new Error(`openScopedTx: role '${role}' is SUPERUSER or BYPASSRLS — refusing to run`);
    }
    return op(trx);
  }) as Promise<T>);
}

/**
 * P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock the
 * pool"): the reviewer's own repro and diagnosis — `Repo#rateLimit.hit`
 * (round 3's own fix) opened its own `db.begin()` (a SECOND pooled
 * connection) from INSIDE a `buildRepo` callback that only ever exists
 * while `withOwnership`/`withOwnershipBatch` ALREADY holds one pooled
 * connection open for the request's own transaction. With `max: 5`, once
 * 5 concurrent requests each hold their own outer-transaction connection
 * and then EACH ALSO calls `repo.rateLimit.hit`, every one of them blocks
 * forever waiting for a 6th connection that will never free up (nothing
 * releases a connection until ITS OWN rate-limit hit completes, which
 * never happens) — a real deadlock, reproduced by the reviewer at 12
 * concurrent requests (5 sessions stuck `idle in transaction` forever;
 * postgres.js queues a blocked `db.begin()` with no acquire timeout at
 * all).
 *
 * The fix is ORDERING, not a bigger pool: this function is the ONE
 * place a rate-limit hit opens its own connection, and it is designed to
 * be called BEFORE any `withOwnership`/`withOwnershipBatch` call for the
 * SAME request even STARTS — never from inside a `Repo` method, so no
 * request can ever hold two connections from this pool at once. `Repo`
 * itself no longer has a `rateLimit` member at all (removed, not merely
 * deprecated) — the removal is deliberate and structural: keeping a
 * `Repo`-level rate-limit method around, even unused, is exactly the
 * footgun that let a future change re-introduce a call to it from inside
 * an open transaction. Every current caller (evidence/handler.ts's
 * `planEvidenceRateLimitChecks`, checkin/challenge-handler.ts, checkin/
 * token-handler.ts) computes its bucket key(s) from data available
 * BEFORE any DB access at all (`actor.uid`, plus a client-supplied
 * `deviceId` — always present, request-shape.ts's `CommonFields` — never
 * a value that requires resolving something inside the transaction
 * first), so none of them have a genuine need to rate-limit from inside
 * a transaction in the first place.
 */
export async function hitRateLimitForActor(actor: Actor, bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult> {
  if (getDbMode() === "edge") {
    // Edge mode: its own short transaction, as edge_actor, through `private.hit_actor_rate_limit`,
    // which builds the `<uid>:<key>` bucket IN THE DATABASE from the bound actor (so the Edge code
    // cannot reach another user's bucket, nor the global one) — the exact key format legacy builds
    // here, so a bucket counts the same in both modes. The database bounds the key (<= 128 chars),
    // the window (1 s .. 1 day) and the max (1 .. 1,000,000); a violation raises 22023.
    const count = await openScopedTx("actor", userBind(actor.uid), async (rateTrx) => {
      const rows = await rateTrx`select private.hit_actor_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}::int) as count`;
      return Number(rows[0]?.count ?? 0);
    });
    if (count > max) return { ok: false, count, retryAfterSeconds: windowSeconds };
    return { ok: true, count };
  }
  const db = sql();
  const scopedBucketKey = `${actor.uid}:${bucketKey}`;
  // Same reasoning as the round-3 fix this replaces (blocking MEDIUM 3,
  // "rate-limit hits roll back on 4xx"): its own short transaction, on
  // the top-level pool, so it commits independently of whatever the
  // request's own (not-yet-open, with this fix) transaction later does.
  // `private.hit_rate_limit` itself never raises (0020_rate_limit_no_
  // raise.sql) — the increment always commits; this code decides
  // ok/not-ok from the returned count.
  return db.begin(async (rateTrx: TxSql) => {
    await rateTrx`set local role service_role`;
    const check = await rateTrx`select current_user as u`;
    if (check[0]?.u !== "service_role") {
      throw new Error(`hitRateLimitForActor: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
    }
    const rows = await rateTrx`select private.hit_rate_limit(${scopedBucketKey}, ${windowSeconds + " seconds"}::interval, ${max}) as count`;
    const count = Number(rows[0]?.count ?? 0);
    if (count > max) {
      return { ok: false, count, retryAfterSeconds: windowSeconds };
    }
    return { ok: true, count };
  }) as Promise<RateLimitResult>;
}

/**
 * Verifies the caller's own JWT against Supabase Auth (`auth.getUser`) —
 * NEVER a client-sent user id (build plan §4.7: "Roles and facilities
 * never come from user_metadata"). Uses the ANON key + the caller's own
 * forwarded `Authorization` header, exactly the "JWT-forwarded client"
 * §4.7.1a describes for reads — routed through this file only because
 * `supabase-js` itself may only ever be imported here (rule (a)/(b)).
 * Returns `null` on any failure (missing header, invalid/expired token,
 * GoTrue error) — the caller (every Edge Function entrypoint) maps that
 * to 401, never assumes a role beyond "authenticated".
 */
export async function getActorFromRequest(req: Request): Promise<Actor | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) return null;
  const token = authHeader.slice(authHeader.indexOf(" ") + 1).trim();
  if (!token) return null;

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) return null;

  const client = createClient(url, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data, error } = await client.auth.getUser(token);
  if (error || !data?.user) return null;
  return { uid: data.user.id, role: "authenticated" };
}

let _adminClient: ReturnType<typeof createClient> | null = null;
function adminClient(): ReturnType<typeof createClient> {
  if (_adminClient) return _adminClient;
  const url = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceRoleKey) {
    throw new Error("privileged.ts: SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY are not set in this environment");
  }
  _adminClient = createClient(url, serviceRoleKey, { auth: { autoRefreshToken: false, persistSession: false } });
  return _adminClient;
}

/**
 * P3d, `DELETE /v1/me`: deletes the caller's own Supabase Auth user (task
 * instruction: "Delete the Supabase Auth user: use the Auth admin API
 * from the allow-listed privileged module only"). Uses the SAME
 * privileged-module exemption `getActorFromRequest`/`sql()` already rely
 * on (`tools/service-role-lint/src/lint.ts`'s `isAllowedFile` — this
 * whole file is the one construction site for a service-role-privileged
 * client of ANY kind, Postgres or Supabase Auth Admin) — routed through
 * `@supabase/supabase-js`'s Admin API (`auth.admin.deleteUser`), never a
 * direct `auth.users` DELETE from SQL: `private.delete_my_data` (0015)
 * deliberately never touches `auth.users` itself (only reads `email`
 * from it) — Supabase Auth owns that table's own lifecycle (identities,
 * sessions, refresh tokens) in ways a raw DELETE would not correctly
 * unwind `[unverified — training knowledge that a direct DELETE FROM
 * auth.users bypasses GoTrue's own cleanup; this environment has no live
 * Supabase Auth to confirm the admin API's exact behaviour against
 * either]`.
 *
 * Deliberately called by `me-delete/index.ts` AFTER `withOwnership`'s own
 * transaction (running `private.delete_my_data`) has COMMITTED, never
 * from inside it — the Admin API is an HTTP call to GoTrue, not a
 * Postgres statement, so it cannot participate in that transaction, and
 * ordering the DB deletion first means a failure here still leaves the
 * caller's personal ROWS gone (the privacy-bearing half of AT 6) even if
 * the Auth identity itself has to be retried.
 *
 * Idempotent by construction: a SECOND call (the caller retries after a
 * first call's Auth deletion failed, or the account was already deleted)
 * is treated as success — Supabase Auth Admin's own error for an
 * already-deleted/nonexistent user id is read as "already gone", not a
 * failure, so a retry never surfaces a spurious error for work that is
 * already done `[unverified — training knowledge on the admin API's
 * exact error shape for a missing user (a 404 body, a specific error
 * code) — this environment cannot exercise a real GoTrue instance; the
 * check below is written broadly (status 404, or a message mentioning
 * "not found"/"not_found") rather than pinned to one exact shape, on
 * purpose, so it fails closed to "report the error" rather than silently
 * swallowing something else if the exact shape differs]`.
 */
export async function deleteAuthUser(uid: string): Promise<{ deleted: boolean; alreadyGone: boolean }> {
  const client = adminClient();
  const { error } = await client.auth.admin.deleteUser(uid);
  if (!error) return { deleted: true, alreadyGone: false };
  const status = (error as { status?: number } | null)?.status;
  const message = String((error as { message?: unknown } | null)?.message ?? "").toLowerCase();
  if (status === 404 || message.includes("not found") || message.includes("not_found") || message.includes("user not found")) {
    return { deleted: true, alreadyGone: true };
  }
  throw new Error(`deleteAuthUser: Supabase Auth admin.deleteUser failed for this account: ${message || String(error)}`);
}

/** Deterministic 64-bit advisory-lock key from a namespace + a string id
 * (P3c gate round 2, item 8: "count-then-insert races... use
 * pg_advisory_xact_lock inside the transaction"). Namespacing (a small
 * integer prefix) keeps the prefetch-cap lock, the queued-catalog-cap
 * lock and the play-rescore lock from ever colliding with each other on
 * the SAME underlying id even though `hashtext` alone could. */
function advisoryLockKeys(namespace: number, id: string): [number, number] {
  // `hashtext` (used by 0017's own dedupe_receipt_fingerprint) needs a
  // real SQL call; this file computes the SAME kind of 32-bit hash in JS
  // (FNV-1a) so the lock key can be passed as a literal two-int pair to
  // `pg_advisory_xact_lock(int, int)` without a round trip just to hash
  // the string first. Collision-safety requirement here is "extremely
  // unlikely to serialize two UNRELATED requests together", not
  // cryptographic — a false-positive collision only costs a little
  // throughput, never correctness (the lock is advisory, not a
  // uniqueness constraint).
  let h = 0x811c9dc5;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  // ⛔ FIX (found via the P3c gate round 2 Deno integration suite):
  // `pg_advisory_xact_lock(int, int)` takes two SIGNED 32-bit integers
  // (Postgres `int4`, range -2147483648..2147483647). `h >>> 0` (unsigned
  // right shift) always produces a NON-NEGATIVE value up to 4294967295 —
  // roughly HALF of all possible hash outputs exceed int4's max positive
  // value and fail with "value ... is out of range for type integer" the
  // instant a real query actually binds it. `h | 0` (bitwise OR with 0)
  // reinterprets the SAME 32 bits as SIGNED instead — every bit pattern
  // is preserved (the lock key's own uniqueness/collision behaviour is
  // identical either way), it just now fits the column type it's
  // actually bound against. Caught only by running this against a real
  // Postgres — every unit/fake-repo test exercises the TS-level function
  // alone and never binds its output to an `int4` SQL parameter.
  return [namespace, h | 0];
}

// ⛔ FIX (P3c gate PASS follow-up 14, nit): `db` used to be an unused
// second parameter here (three args: connection, transaction, actor) —
// every Repo method
// queries through `trx` only; nothing in this function ever read `db`.
// Removed rather than left as dead weight (the same discipline
// `challenge.insert`'s dead `staffUserId` parameter already got in P3c
// gate round 4). `withOwnership`/`withOwnershipBatch` below updated to
// match (`buildRepo(trx, actor)`/`buildRepo(sp, actor)`); their OWN `db`
// locals stay (that one IS used, to open `sql.begin()`/`sql.savepoint()`
// in the first place).
function buildRepo(trx: TxSql, actor: Actor, mode: DbMode): Repo {
  const uid = actor.uid;
  return {
    now(): Date {
      return new Date();
    },

    // ⛔ REMOVED (P3c gate round 4, blocking HIGH: "5 concurrent requests
    // deadlock the pool"). `Repo` no longer has a `rateLimit` member at
    // all — see `hitRateLimitForActor`'s own doc, above `sql()`, for the
    // full reasoning and its replacement. A rate-limit hit is now always
    // made via `hitRateLimitForActor(actor, ...)`, called BEFORE
    // `withOwnership`/`withOwnershipBatch` even opens, never through a
    // `Repo` method reachable only from inside an already-open
    // transaction.

    catalog: {
      // ⛔ FIX (P3e round 2 gate, LOW: "don't let rollback move the
      // current version: importing an older valid version records it but
      // never becomes the drain's currentVersion"). `version int` is
      // assigned `max(version)+1` on FIRST SIGHT of a `site_version`
      // (privileged.ts's own `ImporterRepo#catalog.importVersion`) — so a
      // previously-unseen but chronologically OLDER `site_version`
      // (a rollback republish) would still get the numerically HIGHEST
      // `version` int, and `order by version desc` would wrongly report
      // it as current. `site_version` is `yyyymmdd-gitsha7` — fixed-width
      // digits then fixed-width lowercase hex — so plain text ordering
      // already matches `compareCatalogVersions`'s own date-primary/
      // sha-tiebreak semantics; `nulls last` falls back to the old
      // `version`-int ordering ONLY when every row is a pre-import-catalog
      // fixture with `site_version IS NULL` (0023's own migration note),
      // so `supabase/tests/helpers.sql`'s seed row and every existing
      // skew-window test fixture (`insertCatalogVersion`) keep behaving
      // exactly as before.
      async currentVersion(): Promise<CatalogVersionRow | null> {
        const rows = await trx`
          select version, site_version, contract_version, sha256, kid, published_at
          from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, siteVersion: r.site_version, contractVersion: r.contract_version, sha256: r.sha256, kid: r.kid, publishedAt: r.published_at.toISOString() };
      },

      async versionRow(version: number): Promise<CatalogVersionRow | null> {
        const rows = await trx`
          select version, site_version, contract_version, sha256, kid, published_at
          from app.catalog_version where version = ${version}`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, siteVersion: r.site_version, contractVersion: r.contract_version, sha256: r.sha256, kid: r.kid, publishedAt: r.published_at.toISOString() };
      },

      // ⛔ NEW (P3e round 2 gate, H1): evidence intake now resolves the
      // client's own submitted SITE version string, not an internal int.
      async versionRowBySiteVersion(siteVersion: string): Promise<CatalogVersionRow | null> {
        const rows = await trx`
          select version, site_version, contract_version, sha256, kid, published_at
          from app.catalog_version where site_version = ${siteVersion}`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, siteVersion: r.site_version, contractVersion: r.contract_version, sha256: r.sha256, kid: r.kid, publishedAt: r.published_at.toISOString() };
      },

      async repickEligible(courseId: string): Promise<boolean> {
        const rows = await trx`
          select exists (
            select 1 from app.catalog_id_ledger l
            where l.id = ${courseId}
              and (l.status = 'stub'
                   or l.split_from is not null
                   or exists (select 1 from app.catalog_id_ledger s where s.split_from = l.id)
                   or exists (select 1 from app.catalog_rescore_backlog b where b.course_id = l.id and b.done_at is null))
          ) as e`;
        return Boolean(rows[0]?.e);
      },

      async releaseRank(siteVersion: string): Promise<number | null> {
        const rows = await trx`select count(*)::int as n from app.catalog_version where site_version is not null and site_version <= ${siteVersion}`;
        const n = Number(rows[0]?.n ?? 0);
        return n > 0 ? n : null;
      },

      async resolveLedgerId(id: string): Promise<LedgerRow | null> {
        let currentId = id;
        // Ninth-gate-style bounded closure walk (mirrors packages/catalog's
        // own resolveMergedId — reimplemented here in SQL since this file
        // cannot import that package; see the P3c report's bundling note):
        // at most 10 hops, matching the tombstoned-id-chain being a single
        // hop in every seeded fixture, with headroom against a cycle.
        for (let hop = 0; hop < 10; hop++) {
          const rows = await trx`
            select id, kind, status, verified_in_version, split_from, tombstoned_at, merged_into, first_catalog_version
            from app.catalog_id_ledger where id = ${currentId}`;
          const r = rows[0];
          if (!r) return null;
          if (r.merged_into && r.merged_into !== currentId) {
            currentId = r.merged_into;
            continue;
          }
          return {
            id: r.id,
            kind: r.kind,
            status: r.status,
            verifiedInVersion: r.verified_in_version,
            splitFrom: r.split_from,
            tombstonedAt: r.tombstoned_at ? r.tombstoned_at.toISOString() : null,
            mergedInto: r.merged_into,
            firstCatalogVersion: r.first_catalog_version,
          };
        }
        return null;
      },

      async facilityTz(facilityId: string): Promise<string | null> {
        const rows = await trx`select tz from app.catalog_facility where id = ${facilityId}`;
        return rows[0]?.tz ?? null;
      },

      async courseFacilityId(courseId: string): Promise<string | null> {
        const rows = await trx`select facility_id from app.catalog_course where id = ${courseId}`;
        return rows[0]?.facility_id ?? null;
      },

      async courseHoleCount(courseId: string): Promise<number> {
        // R3: catalog_hole rows (Course.holesDetail) when present, else the
        // course's DECLARED count (Course.holes), else 0 = unknown — and the
        // handler treats anything but exactly 9 as 18 (the stricter dwell bar).
        const rows = await trx`
          select coalesce(
            nullif((select count(*) from app.catalog_hole where course_id = ${courseId}), 0),
            (select holes from app.catalog_course where id = ${courseId}),
            0)::int as n`;
        return rows[0]?.n ?? 0;
      },

      async matchFix(courseId: string, lat: number, lng: number): Promise<MatchResult | null> {
        const rows = await trx`
          select
            verification_status,
            geometry_kind,
            case
              when geometry_kind = 'polygon' and boundary is not null then
                ST_DWithin(boundary::geography, ST_SetSRID(ST_MakePoint(${lng}, ${lat}), 4326)::geography, 50)
              when geometry_kind = 'radius' and radius_center is not null then
                ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(${lng}, ${lat}), 4326)::geography, coalesce(radius_m, 0) + 50)
              else false
            end as inside_buffer
          from app.catalog_course where id = ${courseId}`;
        const r = rows[0];
        if (!r) return null;
        return {
          verificationTier: r.verification_status as "unverified" | "listed-verified" | "play-verified",
          geometryKind: (r.geometry_kind ?? "radius") as "polygon" | "radius",
          insideBuffer: Boolean(r.inside_buffer),
        };
      },

      async signingKey(kid: string): Promise<SigningKeyRow | null> {
        const rows = await trx`select k.kid, k.public_key_b64url,
            coalesce(k.revoked_at, (select r.recorded_at from app.catalog_kid_revocation r where r.kid = k.kid)) as revoked_at
          from app.catalog_signing_key k where k.kid = ${kid}`;
        const r = rows[0];
        if (!r) return null;
        return { kid: r.kid, publicKeyB64Url: r.public_key_b64url, revokedAt: r.revoked_at ? r.revoked_at.toISOString() : null };
      },
    },

    evidence: {
      async countOpenQueued(): Promise<number> {
        // ⛔ FIX (P3c gate round 2, item 8): "count-then-insert races...
        // use pg_advisory_xact_lock inside the transaction." Locked by
        // user (namespace 2) — held until COMMIT, so the INSERT that
        // follows this count (in the SAME transaction, per
        // withOwnership's own wrapping) is serialized against any other
        // concurrent request for the SAME user.
        const [k1, k2] = advisoryLockKeys(2, uid);
        await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
        const rows = await trx`select count(*)::int as n from app.evidence where user_id = ${uid} and status = 'queued_catalog'`;
        return rows[0]?.n ?? 0;
      },

      async insertIdempotent(row: NewEvidenceRow): Promise<InsertEvidenceResult> {
        // ⛔ FIX (P3e round 2 gate, B3): two structurally distinct INSERT
        // shapes now, matching the discriminated `NewEvidenceRow` union
        // and `app.evidence`'s own `evidence_queued_claim_shape` CHECK —
        // a `queued` row writes claimed_*/queued_input and leaves
        // facility_id/course_id/catalog_version NULL (never a value that
        // could trip their FKs on an id the server doesn't have yet); a
        // `resolved` row is the original, unchanged shape.
        const inserted =
          row.kind === "queued"
            ? await trx`
                insert into app.evidence (
                  user_id, device_id, source, source_ref, input_hash, local_date, status,
                  claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input
                ) values (
                  ${uid}, ${row.deviceId}, ${row.source}::app.evidence_source, ${row.sourceRef}, ${row.inputHash}, ${row.localDate}, ${row.status}::app.evidence_status,
                  ${row.claimedFacilityId}, ${row.claimedCourseId}, ${row.claimedCatalogVersion}, ${trx.json(row.queuedInput as never)}
                )
                on conflict (user_id, source, source_ref) do nothing
                returning id, status, input_hash`
            : await trx`
                insert into app.evidence (
                  user_id, device_id, source, source_ref, input_hash, course_id, facility_id,
                  started_at, ended_at, local_date, summary, integrity, cosignal,
                  attestation_grade, matcher_version, catalog_version, status
                ) values (
                  ${uid}, ${row.deviceId}, ${row.source}::app.evidence_source, ${row.sourceRef}, ${row.inputHash}, ${row.courseId}, ${row.facilityId},
                  ${row.startedAt}, ${row.endedAt}, ${row.localDate}, ${trx.json(row.summary as never)}, ${trx.json(row.integrity as never)}, ${trx.json(row.cosignal as never)},
                  ${row.attestationGrade}::app.attestation_grade, ${row.matcherVersion}, ${row.catalogVersion}, ${row.status}::app.evidence_status
                )
                on conflict (user_id, source, source_ref) do nothing
                returning id, status, input_hash`;
        if (inserted[0]) {
          return { id: inserted[0].id, wasNew: true, status: inserted[0].status, inputHash: inserted[0].input_hash };
        }
        // ⛔ P3c gate round 3, blocking HIGH 1+2's own post-insert
        // race-safety note: `handler.ts` already calls
        // `evidence.findExisting` BEFORE this insert is ever attempted, so
        // reaching the ON CONFLICT branch here means a concurrent request
        // for the SAME (user, source, source_ref) won the race between
        // that lookup and this insert — the SAME kind of narrow window
        // `device.ensureOwn`'s own ON CONFLICT fallback already closes.
        // handler.ts re-checks `input_hash` against what IT computed
        // before treating this as its own row.
        const existing = await trx`select id, status, input_hash from app.evidence where user_id = ${uid} and source = ${row.source}::app.evidence_source and source_ref = ${row.sourceRef}`;
        if (!existing[0]) throw new Error("insertIdempotent: conflict reported but no existing row found");
        return { id: existing[0].id, wasNew: false, status: existing[0].status, inputHash: existing[0].input_hash };
      },

      async refreshFixTiers(courseId: string, localDate: string): Promise<number> {
        const rows = await trx`
          update app.evidence e set summary = (
            select coalesce(jsonb_object_agg(t.k,
              case when t.k in ('fix', 'checkinFix', 'checkoutFix') and jsonb_typeof(t.v) = 'object'
                   then jsonb_set(t.v, '{verificationTier}', to_jsonb(c.verification_status::text))
                   else t.v end), '{}'::jsonb)
            from jsonb_each(e.summary) as t(k, v))
          from app.catalog_course c
          where c.id = e.course_id and e.user_id = ${uid} and e.course_id = ${courseId}
            and e.local_date = ${localDate} and e.status = 'accepted'
          returning e.id`;
        return rows.length;
      },

      async findExisting(source: string, sourceRef: string): Promise<ExistingEvidenceRow | null> {
        // ⛔ P3c gate round 3, blocking HIGH 1+2 ("replay handling"):
        // called by handler.ts BEFORE any side effect (token consumption,
        // a fraud signal, a rate-limit hit, a device row) — the whole
        // point of this method existing at all. A `null` result is the
        // ONLY signal that lets handler.ts proceed into the side-effecting
        // pipeline; any row here means either an idempotent replay (exact
        // `input_hash` match) or a rejected conflict (mismatch), decided
        // entirely by handler.ts from the row this returns.
        const rows = await trx`
          select id, status, input_hash, facility_id, course_id, local_date
          from app.evidence
          where user_id = ${uid} and source = ${source}::app.evidence_source and source_ref = ${sourceRef}`;
        const r = rows[0];
        if (!r) return null;
        // ⛔ FIX (found via the P3c gate round 3 Deno integration suite):
        // `local_date` is a Postgres `date` column — postgres.js parses
        // it back as a JS `Date` object, NOT a string, unlike every OTHER
        // column this repo already returns as a bare string. `buildReplayResult`
        // (handler.ts) feeds this straight into `scorePlay`'s own strict
        // `ctx.playLocalDate` (a zod-validated STRING field, unlike a
        // per-row Evidence's own `localDate`, which scorePlay accepts
        // more leniently) — a raw `Date` object fails that validation
        // outright ("expected string, received Date"), reachable only by
        // actually running this against a real Postgres column of this
        // type; no fake/unit test's plain-string fixture data could ever
        // produce a real `Date` instance to catch it. Normalized to
        // `YYYY-MM-DD` here, at the repo boundary, same as every other
        // method's own local_date already IS everywhere else it's read.
        const localDate = r.local_date instanceof Date ? r.local_date.toISOString().slice(0, 10) : r.local_date;
        return { id: r.id, status: r.status, inputHash: r.input_hash, facilityId: r.facility_id, courseId: r.course_id, localDate };
      },

      // ⛔ NEW (P3e round 2 gate, B2/B3): promotes a queued_catalog row IN
      // PLACE — see types.ts's own doc for the full contract. Guarded
      // `WHERE status = 'queued_catalog'` so a row already resolved by a
      // concurrent drain (or moved on some other way) is left untouched.
      async resolveQueuedRow(
        id: string,
        resolved: { facilityId: string; courseId: string | null; summary: Record<string, unknown>; integrity: Record<string, unknown>; attestationGrade: "attested" | "unattestable" | "failed"; catalogVersion: number | null },
      ): Promise<void> {
        await trx`
          update app.evidence set
            status = 'accepted',
            facility_id = ${resolved.facilityId},
            course_id = ${resolved.courseId},
            summary = ${trx.json(resolved.summary as never)},
            integrity = ${trx.json(resolved.integrity as never)},
            attestation_grade = ${resolved.attestationGrade}::app.attestation_grade,
            catalog_version = ${resolved.catalogVersion},
            claimed_facility_id = null,
            claimed_course_id = null,
            claimed_catalog_version = null,
            queued_input = null
          where id = ${id} and user_id = ${uid} and status = 'queued_catalog'`;
      },

      async markQueuedTerminal(id: string, status: "needs_attention" | "unknown_id"): Promise<void> {
        // A terminal row keeps NO queued submission: `queued_input` (raw
        // coordinates and all) and the claimed_* columns are cleared with the
        // status change, exactly as the column comments in 0024 say. A replay
        // of such a row needs only its status + input_hash.
        await trx`
          update app.evidence set
            status = ${status}::app.evidence_status,
            claimed_facility_id = null,
            claimed_course_id = null,
            claimed_catalog_version = null,
            queued_input = null
          where id = ${id} and user_id = ${uid} and status = 'queued_catalog'`;
      },

      async deviceIdFor(id: string): Promise<string | null> {
        const rows = await trx`select device_id from app.evidence where id = ${id} and user_id = ${uid}`;
        return rows[0]?.device_id ?? null;
      },

      async listForPlay(facilityId: string, courseId: string, localDate: string): Promise<StoredEvidenceRow[]> {
        // ⛔ FIX (P3c gate round 2, item 1): filters on the REAL
        // `local_date` column (0019's own ALTER — see that migration's
        // own note) instead of a jsonb `summary->>'localDate'` read, and
        // the old `coalesce(..., $localDate)` fail-open is gone
        // entirely — a row with no local_date can no longer exist (the
        // column is NOT NULL), and a row from a DIFFERENT date no longer
        // silently matches every query. Capped at ABSOLUTE_ROW_CAP
        // (packages/rules' own raw-query DoS bound, re-read from the
        // SAME vendored constant evidence/handler.ts uses).
        const rows = await trx`
          select id, source, facility_id, course_id, local_date, summary, integrity, cosignal, attestation_grade
          from app.evidence
          where user_id = ${uid} and facility_id = ${facilityId}
            and (course_id = ${courseId} or course_id is null)
            and local_date = ${localDate}
            and status = 'accepted'
          order by created_at asc
          limit ${ABSOLUTE_ROW_CAP}`;
        return rows.map((r) => ({
          id: r.id,
          source: r.source,
          facilityId: r.facility_id,
          courseId: r.course_id,
          localDate: r.local_date,
          attestationGrade: r.attestation_grade,
          summary: r.summary ?? {},
          integrity: r.integrity ?? {},
          cosignal: r.cosignal ?? {},
        }));
      },
    },

    play: {
      async upsertFromScore(input: UpsertPlayInput): Promise<UpsertPlayResult> {
        // ⛔ should-fix (P3c gate round 2): "concurrent re-score — hold an
        // advisory lock on (user, course, date) inside the transaction."
        // Serializes two concurrent scorers of the SAME play (e.g. two
        // evidence submissions racing) so the ON CONFLICT DO UPDATE below
        // can never lose an update to a concurrent one under READ
        // COMMITTED.
        const [k1, k2] = advisoryLockKeys(1, `${uid}:${input.courseId}:${input.playDate}`);
        await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;

        const rows = await trx`
          insert into app.play (
            user_id, course_id, facility_id, play_date, course_disambiguated_by,
            score_badge, score_monetary, hard_signal, presence_signal,
            money, held_review, policy_version, input_digest, status
          ) values (
            ${uid}, ${input.courseId}, ${input.facilityId}, ${input.playDate}, ${input.courseDisambiguatedBy},
            ${input.scoreBadge}, ${input.scoreMonetary}, ${input.hardSignal}, ${input.presenceSignal},
            ${input.money}, ${input.heldReview}, ${input.policyVersion}, ${input.inputDigest},
            -- should-fix (P3c gate round 2): "provisional below the
            -- threshold instead of always confirmed."
            -- FIX (found via the Deno integration suite, NOT the
            -- coordinator's list): a bare CASE expression's own result
            -- type resolves to plain text, not app.play_status -- unlike
            -- a plain string literal in a VALUES list (which Postgres
            -- up-casts to the target column's type automatically via its
            -- "unknown"-literal coercion), a CASE expression's branches
            -- resolve to a concrete text type once evaluated, and
            -- assigning text into an enum column with no explicit cast
            -- is a hard error ("column is of type app.play_status but
            -- expression is of type text") -- this INSERT would have
            -- failed on every real Postgres, always, the very first time
            -- a fresh play row was ever created; no unit/fake-repo test
            -- could ever catch it, since the fake Repo never runs real
            -- SQL at all. (No backticks in this comment block on
            -- purpose: this whole statement is one JS template literal --
            -- see this function's own opening line -- and a literal
            -- backtick character here would terminate it early.)
            (case when ${input.scoreBadge} >= 0.50 then 'confirmed' else 'provisional' end)::app.play_status
          )
          on conflict (user_id, course_id, play_date) do update set
            score_badge = excluded.score_badge,
            score_monetary = excluded.score_monetary,
            hard_signal = excluded.hard_signal,
            presence_signal = excluded.presence_signal,
            money = excluded.money,
            held_review = excluded.held_review,
            policy_version = excluded.policy_version,
            input_digest = excluded.input_digest,
            status = (case when app.play.status = 'disputed' then app.play.status::text
                          when excluded.score_badge >= 0.50 then 'confirmed' else 'provisional' end)::app.play_status
          returning id, (xmax = 0) as inserted`;
        const r = rows[0];
        const playId = r.id as string;
        for (const evidenceId of input.evidenceIds) {
          // FIX (found via the Deno integration suite, item 1's own
          // "cover the facility-level row with a second course on the
          // same day" scenario): app.play_evidence carries TWO unique
          // constraints — its own composite PK (play_id, evidence_id)
          // AND a NARROWER play_evidence_evidence_id_key UNIQUE
          // (evidence_id) (0017_money_path_hardening.sql's own M1: "one
          // evidence row backs at most one play"). The ON CONFLICT target
          // below used to name only the composite PK — a conflict on the
          // NARROWER evidence_id-only constraint (a facility-level
          // residual row that ALREADY backs a DIFFERENT play, from an
          // earlier evidence intake the same day) is a DIFFERENT arbiter
          // Postgres will not match against that clause at all, and
          // raised as a raw, uncaught exception (500) instead of the
          // graceful no-op this case actually calls for: a row that
          // already backs one play correctly CANNOT also back a second
          // one, and this play's own scoring/insert should still
          // succeed regardless — it just doesn't gain this particular
          // link. Targeting the narrower, subsuming constraint
          // (evidence_id alone) covers BOTH cases: an exact replay of an
          // already-linked (SAME play_id, SAME evidence_id) row, and a
          // row that now belongs to a DIFFERENT play — both a real
          // Postgres cluster, never the in-memory fake Repo.
          await trx`
            insert into app.play_evidence (play_id, evidence_id, user_id)
            values (${playId}, ${evidenceId}, ${uid})
            on conflict (evidence_id) do nothing`;
        }
        return { id: playId, created: Boolean(r.inserted) };
      },

      async getForDate(courseId: string, playDate: string): Promise<StoredPlayRow | null> {
        // ⛔ ADDED (P3c gate round 4, blocking MEDIUM: "replays skip
        // every rate limit" — fix item "make the replay path read-only:
        // return the stored evidence and play outcome without
        // re-scoring or upserting"). A plain SELECT of the ALREADY
        // -PERSISTED play row — no scoring, no advisory lock, no write
        // of any kind. `evidence/handler.ts#buildReplayResult` uses this
        // instead of re-running `scorePlay` + `upsertFromScore` against
        // the SAME already-stored rows: the original, genuinely-new
        // submission that created this evidence row already scored and
        // upserted its play row, atomically, in the SAME transaction
        // (P3c gate round 2, item 2) — a later replay of that SAME
        // content has nothing new to contribute, so reading the
        // existing row back is not merely cheaper, it's the CORRECT
        // "no re-score beyond what's idempotent" behaviour, made
        // literal (no re-score AT ALL) rather than "re-score and get
        // the same answer."
        const rows = await trx`
          select id, score_badge, score_monetary, presence_signal, money, held_review
          from app.play
          where user_id = ${uid} and course_id = ${courseId} and play_date = ${playDate}`;
        const r = rows[0];
        if (!r) return null;
        return {
          id: r.id,
          scoreBadge: Number(r.score_badge),
          scoreMonetary: Number(r.score_monetary),
          presenceSignal: Boolean(r.presence_signal),
          money: Boolean(r.money),
          heldReview: Boolean(r.held_review),
        };
      },

      // AT 18 — server-side `uniqueCourses` (see types.ts's own doc).
      async uniqueCourseCount(): Promise<number> {
        // A2-01 / §4.2: plays that are USER PICKS (labelled `user`, or unlabelled
        // at a split-family course) count at most ONCE per (facility, date) —
        // the labelled one wins, then the lowest course id — however many
        // split-ambiguous plays that facility-date holds. Geometry/staff
        // resolved plays are unaffected.
        const rows = await trx`
          with recursive cand as (
            select p.id, p.course_id, p.facility_id, p.play_date,
                   (coalesce(p.course_disambiguated_by = 'user', false)
                    or (p.course_disambiguated_by is null and exists (
                         select 1 from app.catalog_id_ledger l
                         where l.id = p.course_id
                           and (l.split_from is not null or exists (select 1 from app.catalog_id_ledger s where s.split_from = l.id))))) as user_pick,
                   coalesce(p.course_disambiguated_by = 'user', false) as labelled
            from app.play p
            join app.catalog_id_ledger l on l.id = p.course_id and l.status = 'verified'
            where p.user_id = ${uid}
              and p.status not in ('void', 'disputed')
              and (p.score_badge >= 0.50 or p.money)
          ), q as (
            select course_id as start_id from (
              select c.*, row_number() over (partition by c.facility_id, c.play_date, c.user_pick order by c.labelled desc, c.course_id) as rn from cand c
            ) r
            where not r.user_pick or r.rn = 1
          ), walk(start_id, cur_id, depth) as (
            select start_id, start_id, 0 from q
            union all
            select w.start_id, l.merged_into, w.depth + 1
            from walk w join app.catalog_id_ledger l on l.id = w.cur_id
            where l.merged_into is not null and l.merged_into <> w.cur_id and w.depth < 10
          )
          select count(distinct w.cur_id)::int as n
          from walk w
          where not exists (select 1 from app.catalog_id_ledger l where l.id = w.cur_id and l.merged_into is not null and l.merged_into <> w.cur_id)`;
        return Number(rows[0]?.n ?? 0);
      },

      async markUserPick(playId: string): Promise<boolean> {
        const rows = await trx`
          update app.play p set course_disambiguated_by = 'user'
          where p.id = ${playId} and p.user_id = ${uid} and p.course_disambiguated_by is null
            and not exists (
              select 1 from app.play o
              where o.user_id = p.user_id and o.facility_id = p.facility_id and o.play_date = p.play_date
                and o.course_disambiguated_by = 'user' and o.id <> p.id)
          returning p.id`;
        return rows.length > 0;
      },

      async lockForScoring(courseId: string, playDate: string): Promise<void> {
        const [k1, k2] = advisoryLockKeys(1, `${uid}:${courseId}:${playDate}`);
        await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
      },

      async disambiguation(courseId: string, playDate: string): Promise<{ stored: "geometry" | "staff" | "user" | null; effective: "geometry" | "staff" | "user" | null }> {
        const rows = await trx`
          select
            (select course_disambiguated_by::text from app.play where user_id = ${uid} and course_id = ${courseId} and play_date = ${playDate}) as stored,
            exists (
              select 1 from app.catalog_id_ledger l
              where l.id = ${courseId}
                and (l.split_from is not null or exists (select 1 from app.catalog_id_ledger s where s.split_from = l.id))
            ) as split_family`;
        const d = rows[0]?.stored;
        const stored = d === "geometry" || d === "staff" || d === "user" ? d : null;
        // §4.2: a play at a split-family course with no geometry/staff
        // resolution IS a user pick, whether or not the one-per-facility-date
        // label could be written.
        return { stored, effective: stored ?? (rows[0]?.split_family ? "user" : null) };
      },

      async repickPrepare(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string }): Promise<{ ok: true; playId: string } | { ok: false; reason: RepickRefusal }> {
        // Serialize against any concurrent scorer of EITHER play — same
        // advisory key family as upsertFromScore, taken in a stable order
        // so two re-picks (or a re-pick and a live submission) cannot
        // deadlock.
        const keys = [`${uid}:${args.fromCourseId}:${args.playDate}`, `${uid}:${args.toCourseId}:${args.playDate}`].map((k) => advisoryLockKeys(1, k)).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
        for (const [k1, k2] of keys) await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;

        const family = await trx`
          select 1
          from app.catalog_id_ledger a
          join app.catalog_id_ledger b on b.id = ${args.toCourseId}
          join app.catalog_course ca on ca.id = a.id and ca.facility_id = ${args.facilityId}
          join app.catalog_course cb on cb.id = b.id and cb.facility_id = ${args.facilityId}
          where a.id = ${args.fromCourseId}
            and a.id <> b.id
            and (b.split_from = a.id or a.split_from = b.id or (a.split_from is not null and a.split_from = b.split_from))`;
        if (family.length === 0) return { ok: false, reason: "not_same_split_family" };

        const existing = await trx`
          select id, course_disambiguated_by as d from app.play
          where user_id = ${uid} and course_id = ${args.fromCourseId} and play_date = ${args.playDate} and facility_id = ${args.facilityId}`;
        if (existing.length === 0) return { ok: false, reason: "no_such_play" };
        const playId = existing[0]!.id as string;
        // ONLY a player's own pick may be re-picked; a geometry/staff
        // resolution is not the player's to move.
        if (existing[0]!.d !== "user") return { ok: false, reason: "not_user_pick" };
        // Exactly ONE re-pick per play (audit-backed: app.audit_log is
        // insert-only, so the count cannot be rewritten).
        const prior = await trx`
          select 1 from app.audit_log
          where actor_user_id = ${uid} and action = 'play.repick' and subject_table = 'play' and subject_id = ${playId}
          limit 1`;
        if (prior.length > 0) return { ok: false, reason: "already_repicked" };
        const clash = await trx`
          select id from app.play
          where user_id = ${uid} and facility_id = ${args.facilityId} and play_date = ${args.playDate} and id <> ${playId}
            and (course_id = ${args.toCourseId} or course_disambiguated_by = 'user')`;
        if (clash.length > 0) return { ok: false, reason: "target_play_exists" };
        return { ok: true, playId };
      },

      async repickApply(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string; playId: string; rederived: { evidenceId: string; summary: Record<string, unknown> }[] }): Promise<void> {
        for (const r of args.rederived) {
          await trx`update app.evidence set summary = ${trx.json(r.summary as never)} where id = ${r.evidenceId} and user_id = ${uid}`;
        }
        await trx`update app.evidence set course_id = ${args.toCourseId} where user_id = ${uid} and course_id = ${args.fromCourseId} and local_date = ${args.playDate} and facility_id = ${args.facilityId}`;
        await trx`update app.play set course_id = ${args.toCourseId}, course_disambiguated_by = 'user' where id = ${args.playId} and user_id = ${uid}`;
        // §8.6: the single re-pick is now used — the raw coordinates have
        // nothing left to do, so they go with it.
        await trx`update app.evidence set integrity = integrity - 'fixCoords' where user_id = ${uid} and course_id = ${args.toCourseId} and local_date = ${args.playDate} and facility_id = ${args.facilityId} and integrity ? 'fixCoords'`;
        await trx`
          insert into app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
          values (${uid}, 'play.repick', 'play', ${args.playId},
                  ${trx.json({ facilityId: args.facilityId, playDate: args.playDate, fromCourseId: args.fromCourseId, toCourseId: args.toCourseId } as never)})`;
      },
    },

    fraudSignal: {
      // ⛔ FIX (P3d gate round 3, S2, MEDIUM): "make repeated finalize
      // idempotent for fraud signals: no duplicate quarantined_evidence_row
      // signal on each retry." `finalizeScoringForKey` (evidence/
      // handler.ts) can now genuinely run twice for the SAME play — once
      // from a batch's own phase 2b, once more from `buildReplayResult`'s
      // live-retry path — and both passes independently decide whether a
      // quarantine signal is warranted from the SAME underlying evidence
      // rows, so a naive unconditional INSERT would raise it twice.
      //
      // ⛔ FIX (P3d gate round 4, F1, BLOCKING): the round-3 version above
      // deduped on `(kind, detail->>'playId')` ALONE — found this round to
      // silently drop a SECOND, genuinely DIFFERENT quarantine signal on
      // the SAME play (a q2 malformed row found alongside/after an
      // earlier q1), violating security doc §3's own "every on-play
      // quarantine... naming the row and its reasons" requirement, and
      // (independently) `INSERT ... SELECT ... WHERE NOT EXISTS` is not
      // safe under real concurrency without a backing unique constraint —
      // two simultaneous finalizes could both pass the NOT EXISTS check
      // before either commits.
      //
      // FIX: dedupe key widened to `(playId, quarantineDigest)` — a
      // canonical digest over the FULL quarantined-row SET a single
      // scoring pass found (`evidence/handler.ts#computeQuarantineDigest`,
      // the ONLY place that knows enough domain shape to compute it — not
      // duplicated here). Enforced by a REAL partial unique index on
      // `app.fraud_signal` (0022, `WHERE kind = 'quarantined_evidence_row'`),
      // via `INSERT ... ON CONFLICT (...) DO NOTHING` against that index —
      // atomic, so this is now safe under genuine concurrency too (proven
      // this round: 4 concurrent finalizes of the SAME quarantine set
      // produce exactly 1 row). A `detail` with no `playId` (the
      // `clock_skew` kind, keyed on `fixIds` instead) is untouched by any
      // of this — always inserts, never deduped, same as before.
      //
      // Scoped STRICTLY to `kind === "quarantined_evidence_row"`: the
      // partial index only exists for that kind, so using `ON CONFLICT`
      // for any other kind would either match nothing (harmless no-op
      // clause) or, worse, silently mask a real constraint-name typo — a
      // plain unconditional insert for every OTHER kind is simpler and
      // exactly as correct.
      async insert(kind: string, detail: Record<string, unknown>): Promise<void> {
        if (kind !== "quarantined_evidence_row") {
          await trx`insert into app.fraud_signal (user_id, kind, detail) values (${uid}, ${kind}, ${trx.json(detail as never)})`;
          return;
        }
        const playId = typeof detail.playId === "string" ? detail.playId : null;
        const quarantineDigest = typeof detail.quarantineDigest === "string" ? detail.quarantineDigest : null;
        if (playId === null || quarantineDigest === null) {
          // Every REAL call site (evidence/handler.ts) always computes
          // both before calling this — a missing one here is this
          // codebase's own bug, not a client-triggerable shape, and
          // silently falling back to an undeduped insert would defeat
          // the entire point of this fix. Fail loud.
          throw new Error(`Repo#fraudSignal.insert: kind "quarantined_evidence_row" requires detail.playId and detail.quarantineDigest to both be strings (got playId=${JSON.stringify(detail.playId)}, quarantineDigest=${JSON.stringify(detail.quarantineDigest)})`);
        }
        await trx`
          insert into app.fraud_signal (user_id, kind, detail)
          values (${uid}, ${kind}, ${trx.json(detail as never)})
          on conflict ((detail ->> 'playId'), (detail ->> 'quarantineDigest')) where kind = 'quarantined_evidence_row'
          do nothing
        `;
      },
    },

    // P3f: the reward-activation repository — implemented in the delimited
    // "P3f" section at the END of this file (one seam here, everything else
    // appended below).
    rewards: buildRewardsRepo(trx, uid, mode),

    // App Attest key registration (follow-up F2) — implemented in the delimited "App Attest key
    // registration" section at the END of this file (one seam here).
    attestKey: buildAttestKeyRepo(trx, uid, mode),

    // O12: the sign-in-methods repository — implemented in the delimited "O12 sign-in" section at the END of this file (one
    // seam here, everything else appended below).
    signin: buildSigninRepo(trx, uid, mode),

    device: {
      async findOwn(deviceId: string) {
        const rows = await trx`select id from app.device where id = ${deviceId} and user_id = ${uid}`;
        return rows[0] ? { id: rows[0].id } : null;
      },
      async ensureOwn(deviceId: string | null, platform: "ios" | "android" | null) {
        if (deviceId) {
          const rows = await trx`select id from app.device where id = ${deviceId} and user_id = ${uid}`;
          if (rows[0]) return { id: rows[0].id };
        }
        // FIX (found via the Deno integration suite — a whole-device-
        // identity bug, not merely a concurrency one). The prior version
        // NEVER wrote the caller's own `deviceId` into the new row at
        // all — it inserted with no `id` column, letting
        // `DEFAULT gen_random_uuid()` mint an UNRELATED random id, and
        // returned THAT. Since no response anywhere in this round's
        // endpoints (evidence, evidence-batch, checkin-challenge,
        // checkin-token) ever echoes the resolved device id back to the
        // caller, the client's own `deviceId` — the whole reason
        // `findOwn`/`ensureOwn` exist as a pair, per this file's own
        // types.ts doc ("looks up a device WITHOUT creating one") — was
        // simply discarded: every subsequent request with that SAME
        // `deviceId` would find nothing (it was never actually stored
        // under that id), mint ANOTHER stray row, forever, defeating
        // both device-identity continuity and the P3c gate round 2 item
        // 7 device cap it exists to bound (each retry looks like a brand
        // NEW device, not the same one). This also silently broke the
        // per-device cap under real concurrency: two concurrent
        // first-ever requests for what the CLIENT considers the SAME
        // device id each got a DIFFERENT real row, so
        // `countOpenPrefetched`'s own advisory lock (keyed by the real
        // device id) never even saw them as related — caught by this
        // suite's own concurrent-prefetch-request test, which expected
        // ONE shared device and got three unrelated ones instead. The id
        // is now the caller's own `deviceId` when given (falling back to
        // a fresh id only when none was supplied at all, never expected
        // from either real call site — both evidence/handler.ts and
        // checkin/challenge-handler.ts always pass a real, already
        // UUID-validated deviceId). `ON CONFLICT (id) DO NOTHING` +
        // fallback SELECT (the SAME idempotent-insert idiom
        // `evidence.insertIdempotent` above already uses) closes the
        // matching race: two concurrent FIRST-ever requests for the
        // SAME real device id now converge on ONE row, not two.
        const id = deviceId ?? crypto.randomUUID();
        const inserted = await trx`
          insert into app.device (id, user_id, platform) values (${id}, ${uid}, ${platform ?? "ios"})
          on conflict (id) do nothing
          returning id`;
        if (inserted[0]) return { id: inserted[0].id };
        const existing = await trx`select id from app.device where id = ${id} and user_id = ${uid}`;
        // ⛔ FIX (P3c gate round 3, should-fix: "ensureOwn on another
        // user's device id: return 409, not 500"). `id` is either the
        // caller's OWN deviceId or a freshly minted one, so reaching an ON
        // CONFLICT with no row found FOR THIS USER means the SAME id
        // already belongs to a DIFFERENT user's app.device row (a plain
        // client id collision, or a stale id replayed against the wrong
        // account — not a server bug). The bare `throw new Error(...)`
        // this used to be surfaced as an uncaught exception -> a generic
        // 500 (http.ts#handleRequest's own catch-all), leaking nothing
        // useful and mis-classifying a client-caused, expected-shape
        // conflict as a server fault. `Errors.conflict` (409) matches
        // every other identity-conflict shape this round already uses.
        if (!existing[0]) {
          throw Errors.conflict("device_owned_by_other_user", "this deviceId is already registered to a different account");
        }
        return { id: existing[0].id };
      },
      async countForUser(): Promise<number> {
        const rows = await trx`select count(*)::int as n from app.device where user_id = ${uid}`;
        return rows[0]?.n ?? 0;
      },
    },

    challenge: {
      async insert(input) {
        // FIX (found via the Deno integration suite, item 8's own
        // concurrent-prefetch-request scenario): the column's own
        // `issued_at timestamptz NOT NULL DEFAULT now()` (0005) uses
        // Postgres's `now()`, which is fixed to the ENCLOSING
        // TRANSACTION's start time — NOT the moment THIS statement
        // actually runs. Under real concurrency, `countOpenPrefetched`'s
        // own `pg_advisory_xact_lock` (above) can make a queued
        // transaction wait a meaningful stretch AFTER it began before
        // this INSERT ever executes, while `expires_at` (computed by the
        // CALLER, challenge-handler.ts, from `repo.now()` — real wall-
        // clock time, read AFTER that same wait) reflects whatever time
        // it actually is BY THEN. The result: `expires_at` can end up
        // LATER than `issued_at (txn-start) + 24h`, tripping
        // checkin_challenge_expires_at_bounded's own CHECK
        // (0017_money_path_hardening.sql) with a raw, unhandled
        // constraint-violation exception — never reachable from a fake
        // Repo, which has no transaction-vs-statement clock distinction
        // at all. `clock_timestamp()` (Postgres's own actual-wall-clock
        // function, re-evaluated on every call, unlike `now()`) pins
        // `issued_at` to the SAME kind of "real time when this statement
        // ran" `expires_at` was already computed from, keeping the two
        // internally consistent regardless of how long this specific
        // transaction waited on the advisory lock beforehand.
        // ⛔ FIX (P3c gate round 4: "remove the leftover staffUserId
        // parameter from challenge.insert"). staff_presence/partner
        // -attest routes are out of this round's scope and were never
        // built (request-shape.ts's own REJECTED_SOURCES) — every real
        // call site (checkin/challenge-handler.ts) always passed
        // `staffUserId: null`, so the parameter was dead weight (and a
        // structural temptation for a future caller to pass something
        // else without a real staff-issuance path behind it). Every
        // challenge this round is issued to the authenticated actor
        // themselves — `user_id = uid, staff_user_id = NULL` always.
        // `app.checkin_challenge`'s own CHECK (0005) still requires
        // exactly one of the two to be set; that invariant is trivially
        // satisfied by never inserting a staff-issued row at all, not by
        // this function branching on a parameter nothing supplies.
        const rows = await trx`
          insert into app.checkin_challenge (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at)
          values (${uid}, null, ${input.deviceId}, ${input.facilityId}, ${input.nonceHash}, ${input.kind}, clock_timestamp(), ${input.expiresAt})
          returning id, expires_at`;
        return { id: rows[0].id, expiresAt: rows[0].expires_at.toISOString() };
      },

      async countOpenPrefetched(deviceId: string): Promise<number> {
        // ⛔ FIX (P3c gate round 2, item 8): same advisory-lock fix as
        // evidence.countOpenQueued above, namespaced separately (3) and
        // keyed by device so two concurrent prefetch requests for the
        // SAME device serialize against each other.
        const [k1, k2] = advisoryLockKeys(3, deviceId);
        await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
        const rows = await trx`
          select count(*)::int as n from app.checkin_challenge
          where device_id = ${deviceId} and user_id = ${uid} and used_at is null and expires_at > now()`;
        return rows[0]?.n ?? 0;
      },

      async getOwn(challengeId: string): Promise<ChallengeRow | null> {
        const rows = await trx`
          select id, device_id, facility_id, nonce_hash, kind, expires_at, used_at
          from app.checkin_challenge where id = ${challengeId} and user_id = ${uid}`;
        const r = rows[0];
        if (!r) return null;
        return { id: r.id, deviceId: r.device_id, facilityId: r.facility_id, nonceHash: r.nonce_hash, kind: r.kind, expiresAt: r.expires_at.toISOString(), usedAt: r.used_at ? r.used_at.toISOString() : null };
      },

      async consume(challengeId: string, nonceHash: string): Promise<boolean> {
        const rows = await trx`
          update app.checkin_challenge set used_at = now()
          where id = ${challengeId} and user_id = ${uid} and nonce_hash = ${nonceHash} and used_at is null
          returning id`;
        return rows.length > 0;
      },
    },

    checkinToken: {
      async insert(input) {
        // Same fix, same reasoning as challenge.insert above: pin
        // issued_at to clock_timestamp() rather than the column's own
        // transaction-frozen `now()` default, so it always stays
        // internally consistent with whatever expires_at the caller
        // computed from real wall-clock time.
        const rows = await trx`
          insert into app.checkin_token (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at)
          values (${input.challengeId}, ${uid}, ${input.deviceId}, ${input.facilityId}, ${input.attestationGrade}::app.attestation_grade, ${input.challengeKind}, clock_timestamp(), ${input.expiresAt})
          returning jti, expires_at`;
        return { jti: rows[0].jti, expiresAt: rows[0].expires_at.toISOString() };
      },

      async consumeForFix(jti: string, submittingDeviceId: string, capturedAtMs: number): Promise<ConsumedCheckinToken | null> {
        // ⛔ FIX (P3c gate round 2, item 4): ONE atomic statement enforces
        // ownership (user_id), single use (consumed_at IS NULL), the
        // submitting device matching the token's own device_id, AND a
        // window clamp — no separate read-then-decide-then-write race
        // window.
        //
        // ⛔ FIX (P3c gate round 3, should-fix "clamp live fixes to the
        // CHALLENGE window, not the token's"). The prior version clamped
        // capturedAt against the TOKEN's own issued_at/expires_at — but
        // the token's own TTL is the 15-minute grace window a device has
        // to actually SUBMIT the fix after redeeming a challenge for a
        // token (checkin/token-handler.ts's TOKEN_TTL_SECONDS), not the
        // window during which the ATTESTATION the token represents is
        // meaningful. That window is the CHALLENGE's own, narrower one:
        // 120s for a live challenge, 24h for a prefetched one
        // (checkin/challenge-handler.ts's LIVE_TTL_SECONDS /
        // PREFETCH_TTL_SECONDS) — clamping to the token's own 15-minute
        // TTL let a capturedAt up to ~13 minutes stale (long past a live
        // challenge's real 120s attestation window, though still inside
        // the token's own separate 15-minute redemption TTL) pass as a
        // valid co-signal. This now joins app.checkin_challenge (via the
        // token's own challenge_id FK, 0019) and clamps against ITS
        // issued_at/expires_at instead — automatically correct for
        // whichever kind (live or prefetched) the challenge actually was,
        // since it reads that row's own real values rather than assuming
        // one TTL. Every column below is explicitly table-qualified: both
        // tables share user_id/device_id/facility_id/expires_at column
        // names, so an unqualified reference would be ambiguous (or worse,
        // silently resolve to the wrong table's column).
        const capturedAt = new Date(capturedAtMs);
        const rows = await trx`
          update app.checkin_token
          set consumed_at = now()
          from app.checkin_challenge cc
          where checkin_token.challenge_id = cc.id
            and checkin_token.jti = ${jti}
            and checkin_token.user_id = ${uid}
            and checkin_token.device_id = ${submittingDeviceId}
            and checkin_token.consumed_at is null
            and checkin_token.expires_at > now()
            and cc.issued_at <= ${capturedAt}
            and ${capturedAt} <= cc.expires_at
          returning checkin_token.facility_id, checkin_token.attestation_grade, checkin_token.challenge_kind`;
        const r = rows[0];
        if (!r) return null;
        return { facilityId: r.facility_id, attestationGrade: r.attestation_grade, challengeKind: r.challenge_kind };
      },
    },

    // P3d: DELETE /v1/me, GET /v1/me/export. Both DB functions this
    // namespace calls are the ones the docstrings on Repo#me point at
    // (0015's private.delete_my_data, 0021's private.export_my_data) —
    // this Repo layer never reimplements their logic, only invokes them
    // through the same service_role connection every other write in this
    // file already uses.
    me: {
      async listSigninProviders(): Promise<string[]> {
        const rows = await trx`select distinct provider from app.signin_provider_token where user_id = ${uid}`;
        return rows.map((r) => r.provider as string);
      },
      async listConnectorProviders(): Promise<string[]> {
        const rows = await trx`select distinct provider from app.connector_account where user_id = ${uid}`;
        return rows.map((r) => r.provider as string);
      },
      async deleteMyData() {
        // P3f: a held (or approved-unredeemed) offer code is RESERVING offer
        // budget; deleting the account deletes the code, so the reservation is
        // handed back FIRST, in this same transaction (0027's own header). Runs
        // before delete_my_data because that removes the offer_code rows this
        // reads. Idempotent: a retried deletion finds nothing left to release.
        //
        // EDGE MODE (PR1b): edge_actor can call neither function, and does not need to —
        // `private.delete_my_data_for_actor()` deletes the BOUND actor (no uid argument) and releases
        // the account's reservations itself, first, in the same call.
        if (mode === "legacy") await trx`select app.release_account_reservations(${uid})`;
        const rows = mode === "edge"
          ? await trx`select private.delete_my_data_for_actor() as result`
          : await trx`select private.delete_my_data(${uid}) as result`;
        const result = rows[0]?.result as { user_id?: string; deleted_at?: string } | undefined;
        if (!result || typeof result.user_id !== "string" || typeof result.deleted_at !== "string") {
          throw new Error("me.deleteMyData: private.delete_my_data returned an unexpected shape");
        }
        return { userId: result.user_id, deletedAt: result.deleted_at };
      },
      async exportMyData() {
        const rows = mode === "edge"
          ? await trx`select private.export_my_data_for_actor() as result`
          : await trx`select private.export_my_data(${uid}) as result`;
        const result = rows[0]?.result as Record<string, unknown> | undefined;
        if (!result || typeof result !== "object") {
          throw new Error("me.exportMyData: private.export_my_data returned an unexpected shape");
        }
        return result;
      },
    },

    // P3d: POST /v1/me/push-token (build plan line 832).
    pushToken: {
      async upsert(deviceId: string, expoToken: string) {
        const rows = await trx`
          insert into app.push_token (user_id, device_id, expo_token, updated_at)
          values (${uid}, ${deviceId}, ${expoToken}, now())
          on conflict (user_id, device_id) do update set expo_token = excluded.expo_token, updated_at = excluded.updated_at
          returning device_id, updated_at`;
        const r = rows[0];
        return { deviceId: r.device_id, updatedAt: r.updated_at.toISOString() };
      },
      async countForUser(): Promise<number> {
        const rows = await trx`select count(*)::int as n from app.push_token where user_id = ${uid}`;
        return rows[0]?.n ?? 0;
      },
    },
  };
}

// ⛔ FIX (P3c gate PASS follow-up 13, "503 after a successful commit"):
// "make the database give up before the HTTP timeout (SET LOCAL
// statement_timeout and lock_timeout below the 15s HTTP race inside
// withOwnership)." Both are well under http.ts's own DEFAULT_REQUEST_
// TIMEOUT_MS (15s): lock_timeout (5s) bounds how long a statement may
// wait to ACQUIRE a lock before giving up (the shape a concurrent writer
// holding e.g. an app.play row/table lock produces); statement_timeout
// (10s) is the backstop for any other slow-running statement once it IS
// executing. lock_timeout firing first (5s < 10s) is deliberate: a lock
// wait is the specific, named failure mode this follow-up exists for,
// and it should be reported as exactly that (lock_not_available) rather
// than however statement_timeout's later, broader cutoff would present
// the same wait.
const STATEMENT_TIMEOUT = "10s";
const LOCK_TIMEOUT = "5s";

// ⛔ NOTE: both are embedded as LITERAL SQL text below (`set local
// statement_timeout = '10s'`), never through a `${...}` tagged-template
// substitution — postgres.js turns every `${...}` into a bound `$n`
// parameter, and `SET`/`SET LOCAL` is a utility statement whose grammar
// does not accept a bind parameter in place of its value (only a
// literal/identifier) `[unverified — training knowledge; not exercised
// against a live driver in this session beyond confirming the OTHER SET
// LOCAL calls in this file, e.g. "set local role service_role", are all
// literal text with no interpolation]`. Both constants are internal,
// compile-time strings (never derived from request input), so literal
// embedding carries no injection risk.
//
// Postgres SQLSTATEs this file maps to a 503 (Errors.serviceUnavailable)
// rather than letting them surface as an opaque 500: 57014 =
// query_canceled (statement_timeout), 55P03 = lock_not_available
// (lock_timeout). `[unverified — training knowledge that postgres.js's
// thrown PostgresError exposes `.code` as the raw SQLSTATE, the same
// convention node-postgres uses; this session had no live Postgres+Deno
// harness run to confirm the exact shape against THIS driver version —
// see tools/db/test.sh's own db-tests run, which DOES exercise this
// against a real cluster, for the empirical confirmation once it runs].
const PG_TIMEOUT_SQLSTATES = new Set(["57014", "55P03"]);
// P3f (gate M1): 40P01 = deadlock_detected, 40001 = serialization_failure. Both
// ABORT the transaction (nothing committed) and are the database telling the
// caller to run it again; the account-deletion / activation / play-hold paths
// take row locks in different orders on purpose-built-but-not-provably-disjoint
// sets (a scoring cascade locks a play's codes in arbitrary order), so a
// deadlock is a possible, correct, retryable outcome — never an opaque 500. A
// SEPARATE set so `PG_TIMEOUT_SQLSTATES` above keeps meaning exactly "timeout".
const PG_RETRYABLE_SQLSTATES = new Set(["40P01", "40001"]);

/** Maps a thrown error to `Errors.serviceUnavailable()` when it is one of
 * the two Postgres timeout SQLSTATEs `STATEMENT_TIMEOUT`/`LOCK_TIMEOUT`
 * above produce; returns every other error unchanged (never masks a real
 * application error, e.g. an `HttpError` a handler threw on purpose, as
 * a 503). Shared by `withOwnership` and `withOwnershipBatch` so the two
 * timeouts mean the same thing in both. */
function mapPgTimeoutError(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === "string" && PG_TIMEOUT_SQLSTATES.has(code)) {
    return Errors.serviceUnavailable("the database could not complete this request in time (statement/lock timeout) — safe to retry");
  }
  // P3d should-fix 1 ("transaction_timeout"): confirmed empirically this
  // round, against a real PG17 cluster via THIS EXACT driver version —
  // exceeding `transaction_timeout` is NOT a normal, catchable-and-the-
  // session-continues ERROR the way statement_timeout/lock_timeout are.
  // Postgres sends a FATAL ("terminating connection due to transaction
  // timeout") and closes the TCP connection outright. postgres.js
  // surfaces that as a plain `Error` with `.code === "CONNECTION_CLOSED"`
  // (a driver-level socket-error code, never a Postgres SQLSTATE) — NOT
  // present in `PG_TIMEOUT_SQLSTATES` above, which only ever inspects
  // `.code` as a SQLSTATE string. Also confirmed: the connection POOL
  // recovers on its own (a later query opens a fresh connection; proven
  // by running one immediately afterward in the same test) — not a
  // pool-damaging event.
  //
  // ⛔ FIX (P3d gate round 3, S3): this message USED to say "(transaction
  // timeout) — safe to retry" — a specific CAUSAL claim this handler
  // cannot actually verify. `CONNECTION_CLOSED` is a driver-level signal
  // that the TCP connection dropped; `transaction_timeout` is ONE thing
  // that produces it (confirmed empirically this round), but so does a
  // network blip, a pooler recycling the connection, or the database
  // process itself restarting — this code path has no way to tell them
  // apart, and asserting "timeout" here is exactly the confident-but-
  // unverified causal claim this project's own accuracy discipline warns
  // against. What IS true, and what this response says instead: the
  // outcome of whatever was in flight is unknown to the caller (the
  // connection dropped before a result came back, which — because
  // `withOwnership`/`withOwnershipBatch` always run inside a single
  // transaction — means either everything committed or nothing did,
  // never a partial write), and every write path this maps onto is
  // idempotent by construction (evidence intake replay by input_hash,
  // delete_my_data's own generic pass, redemption's advisory locking),
  // so retrying is always safe regardless of which of those causes it
  // actually was.
  if ((err as { code?: unknown } | null)?.code === "CONNECTION_CLOSED") {
    return Errors.serviceUnavailable("outcome unknown; retrying is idempotent");
  }
  if (typeof code === "string" && PG_RETRYABLE_SQLSTATES.has(code)) {
    return Errors.serviceUnavailable("the database rolled this request back because it conflicted with a concurrent one (deadlock/serialization) — nothing was changed; safe to retry");
  }
  return err;
}

// P3d should-fix 1: `transaction_timeout` is PG17+ only — confirmed
// empirically this round (`--describe-config` against both this repo's
// pinned PG16 and PG17 binaries: present on 17, absent on 16). Cached
// after the first check (one query per cold start, not per transaction)
// so every write endpoint doesn't pay an extra round trip. `[unverified —
// the REAL hosted Supabase project's own Postgres major version for this
// environment; the P3 build plan's own week-1 spike item list already
// names "the P3 spike confirms" for several PG-version-dependent facts —
// this joins that list]`.
let _supportsTransactionTimeout: boolean | null = null;
async function supportsTransactionTimeout(db: ReturnType<typeof postgres>): Promise<boolean> {
  if (_supportsTransactionTimeout !== null) return _supportsTransactionTimeout;
  const rows = await db`select current_setting('server_version_num') as v`;
  _supportsTransactionTimeout = Number(rows[0]?.v ?? 0) >= 170000;
  return _supportsTransactionTimeout;
}

/**
 * The ONLY sanctioned way an Edge Function touches a privileged
 * (service-role) operation (build plan §4.7.1a).
 *
 * ⛔ FIX (P3c gate round 2, item 2: "writes silently lost"). Every
 * statement used to autocommit on its own connection — a DEFERRABLE FK
 * violation (or any later statement's failure) would leave EARLIER
 * statements in this same logical operation already durably committed,
 * while postgres.js itself still resolved the whole call successfully
 * (each query is its own implicit transaction; nothing here ever rolled
 * one back). The whole `op(repo)` callback now runs inside ONE
 * `sql.begin()` — every write it makes commits together or not at all,
 * and a DEFERRABLE constraint violation at the (now real) COMMIT point
 * correctly fails the entire request instead of silently succeeding with
 * some rows written and some not.
 */
export async function withOwnership<T>(actor: Actor, op: Op<T>): Promise<T> {
  if (getDbMode() === "edge") {
    // Edge mode (see the EDGE ROLE banner): the whole `op(repo)` is ONE transaction as edge_actor,
    // bound to `actor.uid`; every error maps exactly as in legacy.
    try {
      return await openScopedTx("actor", userBind(actor.uid), (trx) => op(buildRepo(trx, actor, "edge")));
    } catch (err) {
      throw mapPgTimeoutError(err);
    }
  }
  const db = sql();
  const txTimeoutSupported = await supportsTransactionTimeout(db);
  try {
    // The explicit `as Promise<T>`: postgres.js's own `.d.ts` types
    // `begin<T2>(cb: (sql) => T2 | Promise<T2>): Promise<UnwrapPromiseArray<T2>>`
    // — a SEPARATE generic (T2) from this function's own `T`, and
    // `UnwrapPromiseArray<T2>` is not provably assignable back to an
    // UNCONSTRAINED `T` for every possible instantiation (`deno check`
    // TS2322, caught this round by the P3c gate round 2 integration suite
    // work — never actually run before). Every caller here always passes a
    // plain (non-array, non-nested-Promise) value through `op`, so the cast
    // is sound in practice; the type system alone can't prove it generically.
    return await (db.begin(async (trx: TxSql) => {
      // "Conditions on the BYPASSRLS design" (required): the connecting
      // role is NOT assumed to already be service_role (it may be
      // `postgres` on a real hosted project — [unverified], see this
      // file's own header). Activate it explicitly and verify.
      await trx`set local role service_role`;
      // Follow-up 13: below both http.ts's request timeout AND the
      // caller's own patience — a request that would otherwise hang past
      // 15s and 503 with the transaction STILL committing behind it
      // instead fails fast, inside the same transaction, so nothing is
      // left half-applied for the client to be wrong about.
      // Literal SQL text (no `${...}` substitution — see this file's own
      // note above `STATEMENT_TIMEOUT`/`LOCK_TIMEOUT` for why); the two
      // named constants exist for the doc comment to point at, not for
      // runtime interpolation here.
      await trx`set local statement_timeout = '10s'`;
      await trx`set local lock_timeout = '5s'`;
      // P3d should-fix 1: the BACKSTOP for a transaction made of many
      // short statements, none individually over statement_timeout, but
      // whose CUMULATIVE duration still exceeds http.ts's 15s request
      // race — 12s is comfortably under that, and deliberately ABOVE
      // statement_timeout (10s) so a single long statement is still
      // reported via ITS OWN, more specific timeout first.
      if (txTimeoutSupported) await trx`set local transaction_timeout = '12s'`;
      const check = await trx`select current_user as u`;
      if (check[0]?.u !== "service_role") {
        throw new Error(`withOwnership: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
      }
      const repo = buildRepo(trx, actor, "legacy");
      return op(repo);
    }) as Promise<T>);
  } catch (err) {
    throw mapPgTimeoutError(err);
  }
}

/**
 * The batch counterpart to `withOwnership` (P3c gate round 3, blocking
 * MEDIUM 4: "Batch: one failing item aborts the whole transaction").
 * `evidence-batch/index.ts` is the one caller — every item runs inside
 * its OWN `trx.savepoint(...)` of the SAME outer transaction: a failing
 * item's writes roll back to just before its own savepoint (postgres.js's
 * own `savepoint()` semantics — see this repo's own confirmation of that
 * behaviour in the round-3 report), while every EARLIER item's already
 * -committed-to-the-outer-transaction work is untouched, and later items
 * still run. This is deliberately a SEPARATE export from `withOwnership`
 * rather than a `Repo`-level escape hatch (a raw "give me a savepoint"
 * method would break the "named methods over fixed tables... never the
 * supabase-js client" narrow-repo discipline this file's own header
 * documents) — the ONE place that needs per-item transactional isolation
 * gets a purpose-built entry point instead.
 *
 * ⛔ P3c gate round 4, blocking HIGH: `perItem` must NEVER call
 * `hitRateLimitForActor` (or anything that opens a second pooled
 * connection) — by the time `perItem` runs, this function's own
 * `db.begin()` is already holding one of the pool's `max: 5`
 * connections, so a second `db.begin()` from inside it deadlocks the
 * SAME way `Repo#rateLimit.hit` used to (see `hitRateLimitForActor`'s
 * own doc). `evidence-batch/index.ts` hits every rate limit for every
 * item BEFORE calling this function at all, precisely so `perItem` here
 * only ever needs the ONE connection this transaction already holds.
 */
export async function withOwnershipBatch<T>(
  actor: Actor,
  itemCount: number,
  perItem: (repo: Repo, index: number) => Promise<T>,
): Promise<Array<{ ok: true; value: T } | { ok: false; error: unknown }>> {
  if (getDbMode() === "edge") {
    // Edge mode: the same per-item savepoint isolation, inside one edge_actor transaction.
    try {
      return await openScopedTx("actor", userBind(actor.uid), async (trx) => {
        const out: Array<{ ok: true; value: T } | { ok: false; error: unknown }> = [];
        for (let i = 0; i < itemCount; i++) {
          try {
            const value = (await trx.savepoint(async (sp: TxSql) => perItem(buildRepo(sp, actor, "edge"), i))) as T;
            out.push({ ok: true, value });
          } catch (err) {
            out.push({ ok: false, error: mapPgTimeoutError(err) });
          }
        }
        return out;
      });
    } catch (err) {
      throw mapPgTimeoutError(err);
    }
  }
  const db = sql();
  const txTimeoutSupported = await supportsTransactionTimeout(db);
  try {
    return await (db.begin(async (trx: TxSql) => {
      await trx`set local role service_role`;
      // Follow-up 13 — same reasoning as withOwnership's own note above.
      await trx`set local statement_timeout = '10s'`;
      await trx`set local lock_timeout = '5s'`;
      // P3d should-fix 1: THIS is the function the coordinator's own
      // repro named directly ("a transaction of many short statements
      // still commits after a 503: 833 of 900 rows committed after seven
      // 503 batches") — a batch is EXACTLY "many short statements," one
      // savepoint per item, so the cumulative-duration backstop matters
      // most here.
      if (txTimeoutSupported) await trx`set local transaction_timeout = '12s'`;
      const check = await trx`select current_user as u`;
      if (check[0]?.u !== "service_role") {
        throw new Error(`withOwnershipBatch: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
      }
      const out: Array<{ ok: true; value: T } | { ok: false; error: unknown }> = [];
      for (let i = 0; i < itemCount; i++) {
        try {
          // Same `UnwrapPromiseArray<T>` quirk as `withOwnership`'s own
          // `db.begin()` cast above — `.savepoint`'s generic is a SEPARATE
          // one from this function's own `T`, and TS can't prove the
          // unwrap is `T` for every possible instantiation. Every caller
          // here always passes a plain (non-array, non-nested-Promise)
          // value through `perItem`, so the cast is sound in practice.
          const value = (await trx.savepoint(async (sp: TxSql) => {
            const repo = buildRepo(sp, actor, "legacy");
            return perItem(repo, i);
          })) as T;
          out.push({ ok: true, value });
        } catch (err) {
          // Follow-up 13: a per-item statement/lock timeout is mapped to
          // the SAME 503 shape withOwnership's own outer catch produces,
          // so evidence-batch/index.ts's per-item error surfacing (which
          // reads `HttpError#code`/`#message` off whatever lands in
          // `error` here) reports it as `service_unavailable`, not a raw,
          // unmapped Postgres error.
          out.push({ ok: false, error: mapPgTimeoutError(err) });
        }
      }
      return out;
    }) as Promise<Array<{ ok: true; value: T } | { ok: false; error: unknown }>>);
  } catch (err) {
    // A timeout OUTSIDE any per-item savepoint (e.g. during the initial
    // `SET LOCAL`/role-check statements themselves) fails the whole batch
    // the same way any other such failure already does — mapped here too
    // for consistency.
    throw mapPgTimeoutError(err);
  }
}

// ============================================================================
// P3e: `import-catalog` (build plan §3.3) — a CLEARLY DELIMITED, ADDITIVE
// section appended at the end of the file per this task's own
// instruction ("keep edits to privileged.ts minimal and additive: a
// clearly delimited new section at the end, not interleaved with
// existing code, because another builder is editing that file and the
// two will be merged"). Nothing above this line is touched beyond the
// single `import type {...}` block widening near the top of the file.
//
// SYSTEM-ACTOR DESIGN (task instruction: "if import-catalog is a
// non-user (system) actor, design an explicit system-actor path rather
// than faking a user — document why it is safe"):
//
// Every OTHER privileged operation in this file (`withOwnership`,
// `withOwnershipBatch`, `hitRateLimitForActor`) takes an `Actor { uid,
// role }` — a real Supabase-Auth-JWT-verified user id
// (`getActorFromRequest`, above), because every table those operations
// touch is owned by a specific player (`user_id` FKs into `auth.users`)
// and RLS/ownership checks are meaningless without one.
//
// `import-catalog` is not a user at all: it has no JWT, no `auth.users`
// row, and — this is the part that makes a system-actor path SAFE rather
// than merely convenient — every table it writes to carries no
// `user_id`/actor-identity column whatsoever:
//   - `app.catalog_version`, `app.catalog_id_ledger` (0002_catalog_tables.sql):
//     global, shared catalog state, not owned by any one user.
//   - `app.evidence.status` (the ONE column `queuedCatalog.promoteToAccepted`/
//     `markNeedsAttention` below ever writes) — scoped not by an actor id
//     the caller claims, but by the row's OWN, already-persisted identity
//     (`WHERE id = $1 AND status = 'queued_catalog'`) — there is no
//     "actor.uid" this write could need or could get wrong, because it
//     never reads or writes `app.evidence.user_id` at all.
// There is therefore no ownership/authorization DECISION a fake `Actor`
// could stand in for — the authorization boundary for this whole file
// (build plan §4.7.1a: "the authorization boundary on writes is each
// Edge Function's own ownership and scope check") is instead the
// CALLER-level HMAC check (`_shared/catalog/webhook-auth.ts`) that
// `import-catalog/index.ts` runs BEFORE ever reaching
// `withSystemCatalogImport` at all — same shape as `hitRateLimitForActor`
// being called before `withOwnership` opens, just with a different (non
// -JWT) credential. `withSystemCatalogImport` below takes NO actor
// parameter, constructs NO `Actor` object, and reads NO `auth.users`
// row — "explicit", not "an Actor with a placeholder uid", because a
// placeholder uid is exactly the "faking a user" shape the task warns
// against (it would silently create a code path where a FUTURE change
// could scope a query by that fake uid and nobody would notice it was
// never a real one).
// ============================================================================

/** Same `SET LOCAL ROLE service_role` + role-assertion + timeout
 * discipline as `withOwnership`'s own doc — see that function for the
 * full "Conditions on the BYPASSRLS design" reasoning, unchanged here.
 *
 * ⛔ FIX (P3e round 2 gate: "align `withSystemCatalogImport` with P3d's
 * own `supportsTransactionTimeout()`/`mapPgTimeoutError()` CONNECTION_CLOSED
 * pattern"). This function's own round-1 `transaction_timeout` guard was a
 * bespoke try/catch on the SET LOCAL statement itself, string-matching
 * "unrecognized configuration parameter" — written before P3d's own
 * empirical finding (see `mapPgTimeoutError`'s own doc, above): exceeding
 * `transaction_timeout` is not a catchable, session-continues error at
 * all, it's a FATAL that closes the connection outright, surfaced by
 * postgres.js as `.code === "CONNECTION_CLOSED"` — a case this function's
 * own try/catch never handled (it only ever guarded the SET statement,
 * never a later query inside the same transaction actually timing out).
 * Reuses `withOwnership`'s own two pieces instead of re-deriving them:
 * `supportsTransactionTimeout()` (cached PG-version feature probe, so
 * this function no longer needs its own "is this GUC recognized" guess)
 * and `mapPgTimeoutError()` (now maps CONNECTION_CLOSED -> 503 for this
 * function's own callers too, not just `withOwnership`'s). */
export async function withSystemCatalogImport<T>(op: (repo: ImporterRepo) => Promise<T>): Promise<T> {
  const db = sql();
  const txTimeoutSupported = await supportsTransactionTimeout(db);
  try {
    return await (db.begin(async (trx: TxSql) => {
      await trx`set local role service_role`;
      await trx`set local statement_timeout = '10s'`;
      await trx`set local lock_timeout = '5s'`;
      if (txTimeoutSupported) await trx`set local transaction_timeout = '12s'`;
      const check = await trx`select current_user as u`;
      if (check[0]?.u !== "service_role") {
        throw new Error(`withSystemCatalogImport: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
      }
      const repo = buildImporterRepo(trx);
      return op(repo);
    }) as Promise<T>);
  } catch (err) {
    throw mapPgTimeoutError(err);
  }
}

/** Same FNV-1a-based advisory-lock-key derivation as `advisoryLockKeys`
 * above, namespaced separately (3) so it can never collide with the
 * per-user queued-catalog-cap lock (namespace 2) or any future one —
 * this file's own existing helper takes an actor-scoped `id` string;
 * this call site's own "id" is a FIXED key (there is only ever one
 * "assign the next catalog_version" serialization point, system-wide,
 * not one per anything), so it reuses `advisoryLockKeys` directly rather
 * than duplicating the hash. */
function buildImporterRepo(trx: TxSql): ImporterRepo {
  return {
    now(): Date {
      return new Date();
    },

    catalog: {
      async listSiteVersions(): Promise<Array<{ siteVersion: string; version: number }>> {
        const rows = await trx`select site_version, version from app.catalog_version where site_version is not null`;
        return rows.map((r) => ({ siteVersion: r.site_version, version: r.version }));
      },

      async currentVersion(): Promise<ImporterCurrentVersionRow | null> {
        const rows = await trx`select version, site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, siteVersion: r.site_version };
      },

      async importVersion(input: ImportVersionInput): Promise<ImportVersionResult> {
        const existing = await trx`select version, sha256 from app.catalog_version where site_version = ${input.siteVersion}`;
        if (existing[0]) {
          if (existing[0].sha256 !== input.sha256) {
            throw new Error(`importVersion: siteVersion "${input.siteVersion}" was already imported with a different sha256 — append-only violation, refusing to overwrite`);
          }
          return { version: existing[0].version, wasNew: false };
        }
        // Serializes concurrent "assign the next int version" attempts —
        // held until COMMIT, same pattern as evidence.countOpenQueued's
        // own advisory lock (P3c gate round 2, item 8) for the same class
        // of count-then-insert race.
        const [k1, k2] = advisoryLockKeys(3, "catalog_version_assign");
        await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
        // Re-check under the lock — another concurrent call may have
        // inserted this exact siteVersion between this call's own
        // unlocked check above and acquiring the lock just now.
        const recheck = await trx`select version, sha256 from app.catalog_version where site_version = ${input.siteVersion}`;
        if (recheck[0]) {
          if (recheck[0].sha256 !== input.sha256) {
            throw new Error(`importVersion: siteVersion "${input.siteVersion}" was already imported with a different sha256 — append-only violation, refusing to overwrite`);
          }
          return { version: recheck[0].version, wasNew: false };
        }
        const maxRow = await trx`select coalesce(max(version), 0)::int as max from app.catalog_version`;
        const nextVersion = Number(maxRow[0]?.max ?? 0) + 1;
        await trx`
          insert into app.catalog_version (version, site_version, contract_version, sha256, kid, published_at)
          values (${nextVersion}, ${input.siteVersion}, ${input.contractVersion}, ${input.sha256}, ${input.kid}, ${input.publishedAt})`;
        return { version: nextVersion, wasNew: true };
      },

      async getSigningKey(kid: string): Promise<ImporterSigningKeyRow | null> {
        const rows = await trx`select k.kid, k.public_key_b64url,
            coalesce(k.revoked_at, (select r.recorded_at from app.catalog_kid_revocation r where r.kid = k.kid)) as revoked_at
          from app.catalog_signing_key k where k.kid = ${kid}`;
        const r = rows[0];
        if (!r) return null;
        return { kid: r.kid, publicKeyB64Url: r.public_key_b64url, revokedAt: r.revoked_at ? r.revoked_at.toISOString() : null };
      },

      // M3 (migration 0025): append-only; never updates/deletes.
      async recordRevokedKids(kids: string[], catalogVersion: string): Promise<void> {
        if (kids.length === 0) return;
        await trx`
          insert into app.catalog_kid_revocation (kid, first_revoked_in_catalog_version)
          select k, ${catalogVersion} from unnest(${kids as never}::text[]) as k
          on conflict (kid) do nothing`;
      },

      // ⛔ H3 (P3e round 2 gate): SET-BASED — one statement per call
      // over parallel `unnest` arrays, never one round trip per ledger
      // id (a ~40k-id ledger would otherwise blow the 12s
      // transaction_timeout on round trips alone).
      async ensureLedgerIdsExist(rows: LedgerBaseRow[]): Promise<void> {
        if (rows.length === 0) return;
        await trx`
          insert into app.catalog_id_ledger (id, kind, status, first_catalog_version)
          select t.id, t.kind, 'stub'::app.ledger_status, t.first_version
          from unnest(${rows.map((r) => r.id)}::text[], ${rows.map((r) => r.kind)}::text[], ${rows.map((r) => r.firstCatalogVersionInt)}::int[]) as t(id, kind, first_version)
          on conflict (id) do nothing`;
      },

      // M3: fail-closed ledger conflict detection, set-based. Reads the
      // STORED columns directly (NOT resolveLedgerId, which walks the
      // merge closure and so never shows a merged row's own merged_into).
      // A conflict is: stored merged_into differs from the incoming one
      // (including incoming null), or a stored tombstone the incoming
      // entry no longer claims (a tombstone reversal).
      async findLedgerConflict(rows: LedgerStateRow[]): Promise<string | null> {
        if (rows.length === 0) return null;
        const found = await trx`
          select l.id, l.merged_into as stored_merged_into, t.merged_into as incoming_merged_into, (l.tombstoned_at is not null) as stored_tombstoned, (t.tombstoned = 1) as incoming_tombstoned
          from app.catalog_id_ledger l
          join unnest(${rows.map((r) => r.id)}::text[], ${rows.map((r) => r.mergedInto ?? "")}::text[], ${rows.map((r) => (r.tombstoned ? 1 : 0))}::int[]) as t(id, merged_into, tombstoned) on t.id = l.id
          where (l.merged_into is not null and l.merged_into is distinct from nullif(t.merged_into, ''))
             or (l.tombstoned_at is not null and t.tombstoned = 0)
          limit 1`;
        const r = found[0];
        if (!r) {
          // ⛔ FIX (P3e round 2 gate, LOW): a conflicting `split_from` fails
          // closed exactly like a conflicting `mergedInto` (M3) — never a
          // silent "keep the first write" that leaves one signed ledger
          // contradicting the stored lineage.
          const claimed = new Map<string, string>();
          for (const row of rows) {
            for (const sib of row.splitSiblings) {
              const prior = claimed.get(sib);
              if (prior !== undefined && prior !== row.id) {
                return `id-ledger.json: split sibling "${sib}" is claimed by both "${prior}" and "${row.id}" in one ledger — refusing to pick one`;
              }
              claimed.set(sib, row.id);
            }
          }
          if (claimed.size === 0) return null;
          const sibIds = [...claimed.keys()];
          const keptIds = sibIds.map((sib) => claimed.get(sib) ?? "");
          const splitConflict = await trx`
            select l.id, l.split_from as stored
            from app.catalog_id_ledger l
            join unnest(${sibIds}::text[], ${keptIds}::text[]) as t(sib, kept) on t.sib = l.id
            where l.split_from is not null and l.split_from <> t.kept
            limit 1`;
          const c = splitConflict[0];
          if (!c) return null;
          return `id-ledger.json: split sibling "${c.id}" is already on file as split from "${c.stored}", but this import claims a different kept course — refusing to silently keep either write`;
        }
        if (r.stored_merged_into !== null && r.stored_merged_into !== (r.incoming_merged_into || null)) {
          return `id-ledger.json: entry "${r.id}" claims mergedInto ${r.incoming_merged_into ? `"${r.incoming_merged_into}"` : "none"}, but is already on file merged into "${r.stored_merged_into}" — refusing to silently keep either write`;
        }
        return `id-ledger.json: entry "${r.id}" is already tombstoned on file, but this import claims it is not tombstoned — refusing a tombstone reversal`;
      },

      async applyLedgerState(rows: LedgerStateRow[]): Promise<void> {
        // Two-pass design (import-handler.ts's own doc): every id this
        // batch's own `mergedInto` could reference already exists by now
        // (ensureLedgerIdsExist just ran for the WHOLE shard, including
        // every survivor id) — this statement can safely set it.
        //
        // Append-only IN EFFECT: `verified_in_version`/`tombstoned_at` only
        // ever move FORWARD (`greatest`, `coalesce(tombstoned_at, now())`),
        // `status` only ever moves stub -> verified, never back (G3-01).
        if (rows.length === 0) return;
        await trx`
          update app.catalog_id_ledger l set
            status = case when l.status = 'verified' or t.status = 'verified' then 'verified'::app.ledger_status else 'stub'::app.ledger_status end,
            verified_in_version = nullif(greatest(coalesce(l.verified_in_version, 0), t.verified_version), 0),
            tombstoned_at = case when t.tombstoned = 1 then coalesce(l.tombstoned_at, now()) else l.tombstoned_at end,
            merged_into = coalesce(l.merged_into, nullif(t.merged_into, ''))
          from unnest(
            ${rows.map((r) => r.id)}::text[],
            ${rows.map((r) => r.status)}::text[],
            ${rows.map((r) => (r.tombstoned ? 1 : 0))}::int[],
            ${rows.map((r) => r.mergedInto ?? "")}::text[],
            ${rows.map((r) => r.verifiedInVersionInt ?? 0)}::int[]
          ) as t(id, status, tombstoned, merged_into, verified_version)
          where l.id = t.id`;
      },

      async resolveLedgerId(id: string): Promise<ImporterLedgerRow | null> {
        // System-scoped duplicate of Repo#catalog.resolveLedgerId's own
        // merge-closure walk (buildRepo, above) — see this section's own
        // header for why ImporterRepo intentionally does not share
        // machinery with the actor-scoped Repo.
        let currentId = id;
        for (let hop = 0; hop < 10; hop++) {
          const rows = await trx`select id, kind, status, merged_into from app.catalog_id_ledger where id = ${currentId}`;
          const r = rows[0];
          if (!r) return null;
          if (r.merged_into && r.merged_into !== currentId) {
            currentId = r.merged_into;
            continue;
          }
          return { id: r.id, kind: r.kind, status: r.status, mergedInto: r.merged_into };
        }
        return null;
      },

      // ⛔ NEW (P3e round 2 gate, H2/H3): the real directory shards, one
      // SET-BASED statement per call (`unnest` over parallel arrays) —
      // not one round trip per row. Every id referenced here was already
      // established in `app.catalog_id_ledger` by `ensureLedgerIdsExist`
      // (import-handler.ts's own ordering: ledger pass, THEN directory
      // pass), so these FKs are always satisfied.
      async upsertTrails(rows: { id: string; slug: string; name: string; catalogVersionInt: number }[]): Promise<void> {
        if (rows.length === 0) return;
        await trx`
          insert into app.catalog_trail (id, slug, name, catalog_version)
          select * from unnest(
            ${rows.map((r) => r.id)}::text[],
            ${rows.map((r) => r.slug)}::text[],
            ${rows.map((r) => r.name)}::text[],
            ${rows.map((r) => r.catalogVersionInt)}::int[]
          )
          on conflict (id) do update set
            slug = excluded.slug, name = excluded.name, catalog_version = excluded.catalog_version`;
      },

      async upsertDesigners(rows: { id: string; name: string; catalogVersionInt: number }[]): Promise<void> {
        if (rows.length === 0) return;
        await trx`
          insert into app.catalog_designer (id, name, catalog_version)
          select * from unnest(
            ${rows.map((r) => r.id)}::text[],
            ${rows.map((r) => r.name)}::text[],
            ${rows.map((r) => r.catalogVersionInt)}::int[]
          )
          on conflict (id) do update set
            name = excluded.name, catalog_version = excluded.catalog_version`;
      },

      async upsertFacilities(rows: { id: string; slug: string; region: string; tz: string; name: string; verificationStatus: string; catalogVersionInt: number }[]): Promise<void> {
        if (rows.length === 0) return;
        await trx`
          insert into app.catalog_facility (id, slug, region, tz, name, catalog_version)
          select * from unnest(
            ${rows.map((r) => r.id)}::text[],
            ${rows.map((r) => r.slug)}::text[],
            ${rows.map((r) => r.region)}::text[],
            ${rows.map((r) => r.tz)}::text[],
            ${rows.map((r) => r.name)}::text[],
            ${rows.map((r) => r.catalogVersionInt)}::int[]
          )
          on conflict (id) do update set
            slug = excluded.slug, region = excluded.region, tz = excluded.tz,
            name = excluded.name, catalog_version = excluded.catalog_version`;
        // verification_status lives on app.catalog_facility too, but the
        // column doesn't exist there (0002 — only app.catalog_course has
        // one). See upsertCourses's own note: this importer's chosen
        // reading is that a COURSE's verification_status mirrors its
        // facility's own Facility.verification.status (the artifact
        // carries no separate per-course verification field at all).
      },

      async upsertHoles(rows: { id: string; courseId: string; number: number; catalogVersionInt: number }[]): Promise<void> {
        if (rows.length === 0) return;
        await trx`
          insert into app.catalog_hole (id, course_id, number, catalog_version)
          select * from unnest(
            ${rows.map((r) => r.id)}::text[], ${rows.map((r) => r.courseId)}::text[],
            ${rows.map((r) => r.number)}::int[], ${rows.map((r) => r.catalogVersionInt)}::int[])
          on conflict (id) do update set course_id = excluded.course_id, number = excluded.number, catalog_version = excluded.catalog_version`;
      },

      // R3 — roster versions + members, set-based through jsonb_to_recordset
      // (members carry an `anyOf` ARRAY, which a 1-D unnest cannot). A roster
      // version is immutable: members are written ONLY alongside a newly
      // inserted version row (the CTE's `returning` join), so a re-import of
      // an already-stored version is a no-op.
      async upsertRosters(rows: RosterVersionInput[]): Promise<void> {
        if (rows.length === 0) return;
        const versions = rows.map((r) => ({
          trail_id: r.trailId, version: r.version, completion_unit: r.completionUnit, marker_unit: r.markerUnit,
          completion_rule: r.completionRule.kind, completion_rule_n: r.completionRule.n, completion_rule_source: r.completionRule.source,
          marker_rule: r.markerRule.kind, marker_rule_n: r.markerRule.n, marker_rule_source: r.markerRule.source,
          tracking_starts_on: r.trackingStartsOn, effective_from: `${r.effectiveFrom}T00:00:00Z`,
        }));
        const members = rows.flatMap((r) => r.members.map((m) => ({
          trail_id: r.trailId, roster_version: r.version, unit: m.unit, course_id: m.courseId, any_of: m.anyOfCourseIds,
          facility_id: m.facilityId, hole_id: m.holeId, stop_order: m.stopOrder, removed_on: m.removedOn,
        })));
        await trx`
          with v as (
            insert into app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, completion_rule, completion_rule_n, completion_rule_source, marker_rule, marker_rule_n, marker_rule_source, tracking_starts_on, effective_from)
            select x.trail_id, x.version, x.completion_unit::app.roster_unit, x.marker_unit::app.roster_unit,
                   x.completion_rule::app.roster_rule_kind, x.completion_rule_n, x.completion_rule_source,
                   x.marker_rule::app.roster_rule_kind, x.marker_rule_n, x.marker_rule_source,
                   x.tracking_starts_on, x.effective_from
            from jsonb_to_recordset(${trx.json(versions as never)}) as x(trail_id text, version int, completion_unit text, marker_unit text, completion_rule text, completion_rule_n int, completion_rule_source text, marker_rule text, marker_rule_n int, marker_rule_source text, tracking_starts_on date, effective_from timestamptz)
            on conflict (trail_id, version) do nothing
            returning trail_id, version
          )
          insert into app.catalog_roster_member (trail_id, roster_version, unit, course_id, any_of_course_ids, facility_id, hole_id, stop_order, removed_on)
          select m.trail_id, m.roster_version, m.unit::app.roster_unit, m.course_id,
                 case when m.any_of is null then null else array(select jsonb_array_elements_text(m.any_of)) end,
                 m.facility_id, m.hole_id, m.stop_order, m.removed_on
          from jsonb_to_recordset(${trx.json(members as never)}) as m(trail_id text, roster_version int, unit text, course_id text, any_of jsonb, facility_id text, hole_id text, stop_order int, removed_on date)
          join v on v.trail_id = m.trail_id and v.version = m.roster_version`;
      },

      async findStubPromotions(rows: LedgerStateRow[]): Promise<string[]> {
        if (rows.length === 0) return [];
        const found = await trx`
          select l.id from app.catalog_id_ledger l
          join unnest(${rows.map((r) => r.id)}::text[], ${rows.map((r) => r.status)}::text[]) as t(id, status) on t.id = l.id
          where l.kind = 'course' and l.status = 'stub' and t.status = 'verified'`;
        return found.map((r) => r.id as string);
      },

      async applySplits(rows: LedgerStateRow[]): Promise<string[]> {
        const sibs: string[] = [];
        const kepts: string[] = [];
        for (const r of rows) for (const sib of r.splitSiblings) {
          sibs.push(sib);
          kepts.push(r.id);
        }
        if (sibs.length === 0) return [];
        const changed = await trx`
          update app.catalog_id_ledger l set split_from = t.kept
          from unnest(${sibs}::text[], ${kepts}::text[]) as t(sib, kept)
          where l.id = t.sib and l.split_from is null and l.id <> t.kept
          returning t.kept`;
        return [...new Set(changed.map((r) => r.kept as string))];
      },

      async enqueueRescore(courseIds: string[], reason: "promotion" | "split", catalogVersionInt: number): Promise<void> {
        if (courseIds.length === 0) return;
        await trx`
          insert into app.catalog_rescore_backlog (course_id, reason, catalog_version)
          select c, ${reason}, ${catalogVersionInt} from unnest(${courseIds}::text[]) as c
          on conflict (course_id, reason, catalog_version) do nothing`;
      },

      async upsertCourses(rows: { id: string; facilityId: string; designerId: string | null; name: string; holes: number | null; verificationStatus: string; closed: boolean; catalogVersionInt: number }[]): Promise<void> {
        if (rows.length === 0) return;
        // Deliberately excludes designer_id from this bulk statement:
        // app.catalog_course.designer_id REFERENCES app.catalog_designer(id)
        // — a course whose claimed designer wasn't ALSO present in this
        // same import's designers.json (a legitimate, unremarkable case:
        // designers.json is optional, per emit-catalog.ts) must not fail
        // the WHOLE bulk insert over one dangling FK. Inserted NULL here,
        // then set in a SEPARATE, per-row-guarded pass below that only
        // touches rows whose designer id actually resolves.
        await trx`
          insert into app.catalog_course (id, facility_id, name, holes, verification_status, closed, catalog_version)
          select t.id, t.facility_id, t.name, t.holes, t.verification_status, t.closed = 1, t.catalog_version from unnest(
            ${rows.map((r) => r.id)}::text[],
            ${rows.map((r) => r.facilityId)}::text[],
            ${rows.map((r) => r.name)}::text[],
            ${rows.map((r) => r.holes)}::int[],
            ${rows.map((r) => r.verificationStatus)}::app.verification_status[],
            ${rows.map((r) => (r.closed ? 1 : 0))}::int[],
            ${rows.map((r) => r.catalogVersionInt)}::int[]
          ) as t(id, facility_id, name, holes, verification_status, closed, catalog_version)
          on conflict (id) do update set
            facility_id = excluded.facility_id, name = excluded.name, holes = coalesce(excluded.holes, app.catalog_course.holes),
            verification_status = excluded.verification_status, closed = excluded.closed,
            catalog_version = excluded.catalog_version`;
        const withDesigner = rows.filter((r) => r.designerId !== null);
        if (withDesigner.length > 0) {
          await trx`
            update app.catalog_course c set designer_id = d.designer_id
            from unnest(${withDesigner.map((r) => r.id)}::text[], ${withDesigner.map((r) => r.designerId)}::text[]) as d(course_id, designer_id)
            where c.id = d.course_id and exists (select 1 from app.catalog_designer where id = d.designer_id)`;
        }
      },
    },

    rescoreBacklog: {
      async listOpen(limit: number, sweepDelaySeconds: number): Promise<RescoreBacklogRow[]> {
        const rows = await trx`
          select id, course_id, reason, cursor_play_id, cursor_created_at::text as cursor_created_at, finished_at::text as finished_at, swept,
                 (finished_at is not null and clock_timestamp() >= finished_at + make_interval(secs => ${sweepDelaySeconds}::double precision)) as sweep_ready
          from app.catalog_rescore_backlog where done_at is null order by id limit ${limit}`;
        return rows.map((r) => ({
          id: Number(r.id),
          courseId: r.course_id as string,
          reason: r.reason as "promotion" | "split",
          cursor: r.cursor_play_id ? { playId: r.cursor_play_id as string, createdAt: r.cursor_created_at as string } : null,
          finishedAt: (r.finished_at as string | null) ?? null,
          swept: Boolean(r.swept),
          sweepReady: Boolean(r.sweep_ready),
        }));
      },
      async markFinished(id: number, cursor: RescoreCursor | null): Promise<void> {
        await trx`
          update app.catalog_rescore_backlog set
            cursor_play_id = ${cursor?.playId ?? null}, cursor_created_at = ${cursor?.createdAt ?? null}::text::timestamptz,
            finished_at = coalesce(finished_at, clock_timestamp())
          where id = ${id}`;
      },
      async beginSweep(id: number, cursor: RescoreCursor | null, overlapSeconds: number): Promise<RescoreCursor | null> {
        // Rewind by the overlap, in SQL on the stored (microsecond-exact)
        // timestamp; the nil uuid sorts before every real id, so every play at
        // or after the rewound instant is revisited. With no cursor at all
        // (a course with no plays) there is nothing to rewind.
        if (cursor === null) {
          await trx`update app.catalog_rescore_backlog set swept = true where id = ${id}`;
          return null;
        }
        const rows = await trx`
          update app.catalog_rescore_backlog set
            swept = true,
            cursor_play_id = '00000000-0000-0000-0000-000000000000'::uuid,
            cursor_created_at = ${cursor.createdAt}::text::timestamptz - make_interval(secs => ${overlapSeconds}::double precision)
          where id = ${id}
          returning cursor_play_id, cursor_created_at::text as cursor_created_at`;
        const r = rows[0];
        return r ? { playId: r.cursor_play_id as string, createdAt: r.cursor_created_at as string } : null;
      },
      async purgeFixCoords(retentionDays: number, limit: number): Promise<number> {
        const rows = await trx`
          with doomed as (
            select e.id from app.evidence e
            where e.integrity ? 'fixCoords'
              and (
                e.created_at < now() - make_interval(days => ${retentionDays}::int)
                or e.course_id is null
                or not exists (
                  select 1 from app.catalog_id_ledger l
                  where l.id = e.course_id
                    and (l.status = 'stub'
                         or l.split_from is not null
                         or exists (select 1 from app.catalog_id_ledger s where s.split_from = l.id)
                         or exists (select 1 from app.catalog_rescore_backlog b where b.course_id = l.id and b.done_at is null))
                )
              )
            order by e.created_at
            limit ${limit}
          )
          update app.evidence e set integrity = e.integrity - 'fixCoords'
          from doomed d where e.id = d.id
          returning e.id`;
        return rows.length;
      },
      async purgeInstallLinkTombstones(maxRows: number): Promise<number> {
        // F19 retention (owner decision 2026-10-02): the 24 months are `private.purge_install_link_tombstones`'s own.
        // service_role holds EXECUTE (legacy); edge_system does too (the PR3 importer path).
        const rows = await trx`select private.purge_install_link_tombstones(${maxRows}::int) as n`;
        return Number(rows[0]?.n ?? 0);
      },
      async nextPlays(courseId: string, after: RescoreCursor | null, limit: number): Promise<RescorePlayRef[]> {
        // Stable keyset over (created_at, id): a play inserted while the
        // drain is mid-course has a created_at at/after the cursor, so it
        // can never fall BEHIND it the way a bare random-uuid ordering
        // would let it (a LOW from the round-2 gate).
        // The text form is kept END TO END: postgres.js would parse a value it
        // infers as timestamptz into a JS Date (millisecond precision) and
        // truncate the cursor — so it is cast text -> timestamptz in SQL.
        const afterAt = after?.createdAt ?? null;
        const afterId = after?.playId ?? null;
        const rows = await trx`
          select id, user_id, facility_id, course_id, play_date, created_at::text as created_at_text from app.play
          where course_id = ${courseId} and (${afterId}::uuid is null or (created_at, id) > (${afterAt}::text::timestamptz, ${afterId}::uuid))
          order by created_at, id limit ${limit}`;
        return rows.map((r) => ({
          playId: r.id as string, userId: r.user_id as string, facilityId: r.facility_id as string, courseId: r.course_id as string,
          playDate: r.play_date instanceof Date ? r.play_date.toISOString().slice(0, 10) : String(r.play_date),
          createdAt: r.created_at_text as string,
        }));
      },
      async advance(id: number, cursor: RescoreCursor | null, done: boolean): Promise<void> {
        await trx`update app.catalog_rescore_backlog set cursor_play_id = ${cursor?.playId ?? null}, cursor_created_at = ${cursor?.createdAt ?? null}::text::timestamptz, done_at = case when ${done} then now() else null end where id = ${id}`;
      },
    },

    queuedCatalog: {
      // ⛔ FIX (P3e round 2 gate, B2): no more system-scoped
      // promoteToAccepted/markNeedsAttention here — draining now goes
      // through the actor-scoped `Repo#evidence.resolveQueuedRow`/
      // `markQueuedTerminal` (a PER-ROW `withOwnership` transaction,
      // opened by drain-orchestrator.ts) so a promotion can actually
      // re-run real intake derivation (facility/course resolution, the
      // matcher, scorePlay) instead of being a raw, unscored status flip
      // — see this file's own `Repo#evidence` section, and
      // evidence/handler.ts#redrainQueuedEvidenceRow's header, for the
      // full "why".
      async listOpen(limit: number): Promise<QueuedEvidenceRow[]> {
        const rows = await trx`
          select id, user_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, created_at
          from app.evidence
          where status = 'queued_catalog'
          order by created_at asc
          limit ${limit}`;
        return rows.map((r) => ({
          id: r.id,
          userId: r.user_id,
          claimedFacilityId: r.claimed_facility_id,
          claimedCourseId: r.claimed_course_id,
          claimedCatalogVersion: r.claimed_catalog_version,
          queuedInput: r.queued_input,
          createdAt: r.created_at.toISOString(),
        }));
      },

      async currentSiteVersion(): Promise<string | null> {
        const rows = await trx`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
        return rows[0]?.site_version ?? null;
      },
    },
  };
}

/** Same short-own-transaction shape as `hitRateLimitForActor` (see that
 * function's own doc for why a rate-limit hit must never open a SECOND
 * connection from inside an already-open transaction) — the system
 * -scoped counterpart: no `Actor` to prefix the bucket key with (this
 * section's own header on why import-catalog has none), so the caller's
 * own bucket key IS the whole key, unscoped. Used by
 * `import-catalog/index.ts` as a coarse defense-in-depth cap on the HMAC
 * -authenticated endpoint itself (bounds the blast radius of a leaked
 * webhook secret, distinct from — and in addition to — the HMAC check
 * that gates the endpoint at all). */
export async function hitSystemRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult> {
  if (getDbMode() === "edge") {
    // Edge mode: as edge_system through `private.hit_system_rate_limit`, which stores the bucket as
    // `system:<key>`. (Behaviour difference from legacy, which stored the bare key: the two modes keep
    // SEPARATE counters for the same import-catalog key; irrelevant once PR4 deletes legacy.)
    const count = await openScopedTx("system", { expectedUid: null }, async (rateTrx) => {
      const rows = await rateTrx`select private.hit_system_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}::int) as count`;
      return Number(rows[0]?.count ?? 0);
    });
    if (count > max) return { ok: false, count, retryAfterSeconds: windowSeconds };
    return { ok: true, count };
  }
  const db = sql();
  return db.begin(async (rateTrx: TxSql) => {
    await rateTrx`set local role service_role`;
    const check = await rateTrx`select current_user as u`;
    if (check[0]?.u !== "service_role") {
      throw new Error(`hitSystemRateLimit: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
    }
    const rows = await rateTrx`select private.hit_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}) as count`;
    const count = Number(rows[0]?.count ?? 0);
    if (count > max) {
      return { ok: false, count, retryAfterSeconds: windowSeconds };
    }
    return { ok: true, count };
  }) as Promise<RateLimitResult>;
}

export type { CatalogImportEnvConfig } from "./types.ts";

/** The ONE place `import-catalog/index.ts` reads its own env config from —
 * every value here is either a narrow, single-purpose secret
 * (`CATALOG_IMPORT_HMAC_SECRET` — never `service_role`, never a DB
 * credential) or plain operational config (the artifact URL, its host
 * allow-list), but NONE of the three is on
 * `tools/service-role-lint`'s own `PUBLIC_ENV_VAR_ALLOWLIST`
 * (`SUPABASE_URL`/`SUPABASE_ANON_KEY`/`ENVIRONMENT`/`NODE_ENV`/
 * `DENO_ENV`) — so, per that lint's own rule, this file (the sole
 * allow-listed `Deno.env.get` site for anything else) is the only place
 * they may be read. Returns `null` (never throws) when any is missing —
 * the caller maps that to a clean 500 ("this environment is not
 * configured for catalog import") rather than a raw exception; task
 * instruction: "No secrets, emails, or phone numbers in any file" —
 * nothing here is a literal secret VALUE, only the env VAR NAMES that
 * name where one lives. */
export function getCatalogImportEnvConfig(): CatalogImportEnvConfig | null {
  const artifactBaseUrl = Deno.env.get("CATALOG_ARTIFACT_BASE_URL");
  const allowedHostsRaw = Deno.env.get("CATALOG_ARTIFACT_ALLOWED_HOSTS");
  const webhookHmacSecret = Deno.env.get("CATALOG_IMPORT_HMAC_SECRET");
  if (!artifactBaseUrl || !allowedHostsRaw || !webhookHmacSecret) return null;
  const allowedHosts = allowedHostsRaw.split(",").map((h) => h.trim()).filter((h) => h.length > 0);
  if (allowedHosts.length === 0) return null;
  return { artifactBaseUrl, allowedHosts, webhookHmacSecret };
}

// ============================================================================
// ==== P3f additions — `rewards-activate` (build plan §7.5, A2-08) ============
// ============================================================================
// Everything between this banner and the matching END banner is P3f's. It is
// appended (not interleaved) on purpose: other P3 builders append their own
// delimited sections to this file too, and one block per builder keeps the
// merge to "keep both". The only P3f line elsewhere in this file is the single
// `rewards: buildRewardsRepo(trx, uid)` seam inside `buildRepo`.

const REWARDS_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function rewardsStateConflict(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  // SQLSTATEs app.activate_* / app.resolve_held_* raise (0027): P0002 = no such
  // reward for this user; 55000 = the reward's state does not allow the
  // transition; 23514 = the DB refused an `activate` the table's rows 2/3 forbid
  // (a fraud signal raised, or the reward's basis changed, since the handler
  // read them — a retry re-runs the table on fresh facts).
  if (code === "P0002") return Errors.notFound("no such reward");
  if (code === "55000") return Errors.conflict("reward_not_activatable", "this reward cannot be activated in its current state");
  if (code === "23514") return Errors.conflict("reward_state_changed", "the reward or the account changed while this was being activated — retry");
  return err;
}

function buildRewardsRepo(trx: TxSql, uid: string, mode: DbMode): RewardsRepo {
  return {
    async isAppReviewDemoAccount(): Promise<boolean> {
      const rows = await trx`select exists (select 1 from app.app_review_demo_account where user_id = ${uid}) as demo`;
      return Boolean(rows[0]?.demo);
    },

    async lockOwnReward(id: string): Promise<OwnReward | null> {
      // A non-UUID would make the driver raise 22P02 and surface as a 500 — it
      // is simply "no such reward" (404), the same as any id that is not theirs.
      if (!REWARDS_UUID_RE.test(id)) return null;
      // Ownership is part of the WHERE clause, never a post-hoc check: another
      // user's id and a nonexistent id are the same empty result.
      // EDGE MODE (0033): edge_actor holds no UPDATE on offer_code / entitlement, and `SELECT ... FOR UPDATE`
      // needs one. The lock is taken by `private.lock_own_reward_for_actor(id)` instead — a definer that does
      // the same `FOR UPDATE` on the BOUND actor's row, and a row lock lasts until the TRANSACTION ends whoever
      // took it — so concurrent activations of one reward are serialised exactly as in legacy. (Dropping the
      // lock altogether, on the argument that `private.activate_*_for_actor` lock the row themselves, was tried
      // and refuted by the integration suite: the handler DECIDES from the state it reads here, BEFORE those
      // functions lock, so a racing second request could turn an already-issued code into held_review.)
      // Legacy keeps its `for update` verbatim.
      if (mode === "edge") await trx`select private.lock_own_reward_for_actor(${id}::uuid)`;
      const lockOc = mode === "legacy" ? trx`for update of oc` : trx``;
      const codes = await trx`
        select oc.id, oc.state, oc.activated_device_id, oc.expires_at, oc.expiry_paused_at,
               (oc.rests_on_unattestable and oc.review_cleared_at is null) as rests_on_unattestable,
               coalesce(p.held_review, false) as play_held
        from app.offer_code oc
        left join app.play p on p.id = oc.play_id and p.user_id = oc.user_id
        where oc.id = ${id} and oc.user_id = ${uid}
        ${lockOc}`;
      const c = codes[0];
      if (c) {
        return {
          kind: "offer_code",
          id: c.id,
          state: c.state,
          activatedDeviceId: c.activated_device_id ?? null,
          expiresAt: c.expires_at ? c.expires_at.toISOString() : null,
          expiryPaused: c.expiry_paused_at !== null && c.expiry_paused_at !== undefined,
          // The reward's own flag stops counting once a reviewer cleared it (H2,
          // folded into the SELECT above); a held PLAY is not cleared by a review
          // of the code. Row 3 only: a review never waives an account-level signal.
          restsOnUnattestable: Boolean(c.rests_on_unattestable) || Boolean(c.play_held),
        };
      }
      const lockEnt = mode === "legacy" ? trx`for update of e` : trx``;
      const ents = await trx`
        select e.id, e.state, e.activated_device_id,
               (e.rests_on_unattestable and e.review_cleared_at is null) as rests_on_unattestable,
               coalesce(p.held_review, false) as play_held
        from app.entitlement e
        left join app.play p on p.id = e.play_id and p.user_id = e.user_id
        where e.id = ${id} and e.user_id = ${uid}
        ${lockEnt}`;
      const e = ents[0];
      if (!e) return null;
      return {
        kind: "entitlement",
        id: e.id,
        state: e.state,
        activatedDeviceId: e.activated_device_id ?? null,
        expiresAt: null,
        expiryPaused: false,
        restsOnUnattestable: Boolean(e.rests_on_unattestable) || Boolean(e.play_held),
      };
    },

    async deviceAttestState(deviceId: string) {
      // An attested grade requires a REGISTERED key (0034, F2): the key (and its id) are handed to the
      // verifier only when `attest_registered_at` is set, i.e. only for a key written by
      // app.register_attest_key after a verified attestation. A key written any other way reads as "no key"
      // here, and the verifier answers `unattestable` — never `attested`.
      const rows = await trx`
        select id, platform, attest_counter,
               case when attest_registered_at is not null then attest_key_id end as attest_key_id,
               case when attest_registered_at is not null then attest_public_key end as attest_public_key
        from app.device where id = ${deviceId} and user_id = ${uid}`;
      const r = rows[0];
      if (!r) return null;
      return {
        id: r.id,
        platform: r.platform as "ios" | "android",
        attestKeyId: r.attest_key_id ?? null,
        // bigint arrives as a string from postgres.js.
        attestCounter: Number(r.attest_counter),
        attestPublicKey: r.attest_public_key ? new Uint8Array(r.attest_public_key) : null,
      };
    },

    async advanceAttestCounter(deviceId: string, counter: number): Promise<boolean> {
      // One atomic, monotonic statement: a replayed or racing counter updates 0
      // rows, whichever of two concurrent requests lost.
      const rows = await trx`
        update app.device set attest_counter = ${counter}, last_seen = now()
        where id = ${deviceId} and user_id = ${uid} and attest_counter < ${counter}
        returning id`;
      return rows.length > 0;
    },

    async recordDeviceVerdict(deviceId: string, verdict: { grade: string; tokenHash: string | null }): Promise<void> {
      // `integrity_last` is part of GET /v1/me/export (0022): grade + time only,
      // never the diagnostic reasons.
      await trx`
        update app.device set
          devicecheck_token_hash = coalesce(${verdict.tokenHash}::text, devicecheck_token_hash),
          integrity_last = ${trx.json({ grade: verdict.grade, at: new Date().toISOString() } as never)},
          last_seen = now()
        where id = ${deviceId} and user_id = ${uid}`;
    },

    async hasOpenAttestationFailedSignal(): Promise<boolean> {
      // Only the signal's own cleared_at releases it (N3): a review of one reward
      // never waives an account-level signal.
      const rows = await trx`
        select exists (
          select 1 from app.fraud_signal where user_id = ${uid} and kind = 'attestation_failed' and cleared_at is null
        ) as open`;
      return Boolean(rows[0]?.open);
    },

    async canReserveBudget(rewardId: string): Promise<boolean> {
      // Advisory and lock-free: see RewardsRepo#canReserveBudget. No row of the
      // result is the caller's to lock; the database re-decides under the offer lock.
      const rows = await trx`
        select (o.face_value <= 0 or oc.reserved_amount > 0 or oc.state <> 'earned'
                or o.budget_used + o.budget_reserved + o.face_value <= o.budget_cap) as ok
        from app.offer_code oc join app.offer o on o.id = oc.offer_id
        where oc.id = ${rewardId} and oc.user_id = ${uid}`;
      // Not a code (an entitlement reserves nothing) or not found: nothing to refuse.
      return rows.length === 0 ? true : Boolean(rows[0]!.ok);
    },

    async raiseAttestationFailedIfNone(detail: Record<string, unknown>): Promise<boolean> {
      // Serialised per account so two concurrent activations cannot both see
      // "none open" and insert two.
      const [k1, k2] = advisoryLockKeys(4, uid);
      await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
      const rows = await trx`
        insert into app.fraud_signal (user_id, kind, detail)
        select ${uid}::uuid, 'attestation_failed', ${trx.json(detail as never)}::jsonb
        where not exists (
          select 1 from app.fraud_signal where user_id = ${uid} and kind = 'attestation_failed' and cleared_at is null
        )
        returning id`;
      return rows.length > 0;
    },

    async raiseFraudSignalOnce(kind: string, detail: Record<string, unknown>, onceKey: string): Promise<boolean> {
      const [k1, k2] = advisoryLockKeys(5, `${uid}:${kind}:${onceKey}`);
      await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
      const stored = { ...detail, onceKey };
      const rows = await trx`
        insert into app.fraud_signal (user_id, kind, detail)
        select ${uid}::uuid, ${kind}::text, ${trx.json(stored as never)}::jsonb
        where not exists (
          select 1 from app.fraud_signal
          where user_id = ${uid} and kind = ${kind} and cleared_at is null and detail ->> 'onceKey' = ${onceKey}
        )
        returning id`;
      return rows.length > 0;
    },

    async hasPriorReward(): Promise<boolean> {
      // A reward the account actually RECEIVED, ON A DEVICE: a ledger row, or its
      // own record in a post-activation state with an activated_device_id.
      // Earned, held and void rewards do not count, and neither does a reward no
      // device ever ran the table on (H2).
      const rows = await trx`
        select (
          exists (select 1 from app.device_reward_ledger where user_id = ${uid})
          or exists (select 1 from app.offer_code where user_id = ${uid} and state in ('issued', 'redeemed') and activated_device_id is not null)
          or exists (select 1 from app.entitlement where user_id = ${uid} and state in ('redeemable', 'vouchered', 'redeemed') and activated_device_id is not null)
        ) as prior`;
      return Boolean(rows[0]?.prior);
    },

    async applyActivation(input) {
      const detail = input.holdDetail === null ? null : trx.json(input.holdDetail as never);
      try {
        // EDGE MODE (PR1b): `private.activate_*_for_actor` run the SAME P3f functions as private_definer
        // for the BOUND actor — there is no user argument (the uid is the binding's), edge_actor cannot
        // call `app.activate_*`, and the SQLSTATEs (P0002 / 42501 / 55000 / 23514) are the P3f ones.
        if (input.kind === "offer_code") {
          const rows = mode === "edge"
            ? await trx`select private.activate_offer_code_for_actor(${input.rewardId}::uuid, ${input.deviceId}::uuid, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`
            : await trx`select app.activate_offer_code(${input.rewardId}, ${uid}, ${input.deviceId}, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`;
          return { state: rows[0]!.state as string };
        }
        const rows = mode === "edge"
          ? await trx`select private.activate_entitlement_for_actor(${input.rewardId}::uuid, ${input.deviceId}::uuid, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`
          : await trx`select app.activate_entitlement(${input.rewardId}, ${uid}, ${input.deviceId}, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`;
        return { state: rows[0]!.state as string };
      } catch (err) {
        throw rewardsStateConflict(err);
      }
    },

    async recordInstallLink(deviceId: string, installLinkHash: string): Promise<void> {
      // One SQL function (0027 5g): stamps the link on the device row (first
      // writer wins) and writes the account's pseudonymous tombstone row, which
      // survives account deletion (N4). service_role holds EXECUTE; the vault key
      // is read inside a SECURITY DEFINER function, never here.
      await trx`select app.record_install_link(${uid}, ${deviceId}, ${installLinkHash})`;
    },

    async androidInstallSignals(deviceId: string) {
      // EDGE MODE (PR1b): `app.device_link_signals` counts accounts ACROSS users, which edge_actor's own-row
      // policies would silently turn into an undercount (a fail-OPEN); `private.device_link_signals_for_actor`
      // is the definer that does the cross-account read for the actor's OWN device (same result shape).
      const rows = mode === "edge"
        ? await trx`
          select s.accounts_on_install, s.voided_account_used_install,
                 (d.install_link_hash is not null or d.attest_key_id is not null) as linkable
          from app.device d
          cross join lateral private.device_link_signals_for_actor(d.id) s
          where d.id = ${deviceId} and d.user_id = ${uid}`
        : await trx`
          select s.accounts_on_install, s.voided_account_used_install,
                 (d.install_link_hash is not null or d.attest_key_id is not null) as linkable
          from app.device d
          cross join lateral app.device_link_signals(d.id) s
          where d.id = ${deviceId} and d.user_id = ${uid}`;
      const r = rows[0];
      if (!r || !r.linkable) return null;
      return { accountsOnInstall: Number(r.accounts_on_install), voidedAccountUsedInstall: Boolean(r.voided_account_used_install) };
    },
  };
}

/** Reads the vendor configuration for `rewards-activate` from the environment.
 * `null` for a platform means UNCONFIGURED, and production-ports.ts turns that
 * into a port that does not exist (every request carrying that platform's
 * attestation material then fails closed). A platform is configured only when
 * EVERY one of its variables is present and non-empty — a half-set
 * configuration is "not configured", never a default.
 *
 * Secrets (the DeviceCheck .p8 key, the Google service-account key) live ONLY
 * in the environment; nothing in this repository carries one.
 *   Apple:  GR_APPLE_TEAM_ID, GR_APPLE_BUNDLE_ID, GR_APPLE_DEVICECHECK_KEY_ID,
 *           GR_APPLE_DEVICECHECK_PRIVATE_KEY (PKCS#8 PEM),
 *           GR_APPLE_DEVICECHECK_ENV ("production" | "development")
 *   Google: GR_PLAY_PACKAGE_NAME, GR_PLAY_CERT_SHA256 (comma-separated base64url),
 *           GR_PLAY_SERVICE_ACCOUNT_EMAIL, GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY (PEM) */
export function loadRewardsAttestationConfig(): RewardsAttestationConfig {
  const teamId = Deno.env.get("GR_APPLE_TEAM_ID") ?? "";
  const bundleId = Deno.env.get("GR_APPLE_BUNDLE_ID") ?? "";
  const keyId = Deno.env.get("GR_APPLE_DEVICECHECK_KEY_ID") ?? "";
  const privateKeyPem = Deno.env.get("GR_APPLE_DEVICECHECK_PRIVATE_KEY") ?? "";
  const environment = Deno.env.get("GR_APPLE_DEVICECHECK_ENV") ?? "";
  const appleComplete = teamId !== "" && bundleId !== "" && keyId !== "" && privateKeyPem !== "" && (environment === "production" || environment === "development");

  const packageName = Deno.env.get("GR_PLAY_PACKAGE_NAME") ?? "";
  const digests = (Deno.env.get("GR_PLAY_CERT_SHA256") ?? "").split(",").map((d) => d.trim()).filter((d) => d !== "");
  const serviceAccountEmail = Deno.env.get("GR_PLAY_SERVICE_ACCOUNT_EMAIL") ?? "";
  const serviceAccountPrivateKeyPem = Deno.env.get("GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY") ?? "";
  const googleComplete = packageName !== "" && digests.length > 0 && serviceAccountEmail !== "" && serviceAccountPrivateKeyPem !== "";

  return {
    apple: appleComplete ? { teamId, bundleId, keyId, privateKeyPem, environment: environment as "production" | "development" } : null,
    google: googleComplete ? { packageName, certificateSha256Digests: digests, serviceAccountEmail, serviceAccountPrivateKeyPem } : null,
  };
}
// ---- postgres.js closed-socket guard (P3f gate round 2, LOW) ----------------
// When Postgres kills a connection mid-transaction (`transaction_timeout` is a
// FATAL that drops the socket — see `mapPgTimeoutError`), postgres.js v3.4.5 can
// still have a write queued for that connection: its deferred `nextWrite`
// (connection.js, scheduled through the setImmediate polyfill) then runs with
// `socket === null` and throws `TypeError: Cannot read properties of null
// (reading 'write')` FROM A TIMER CALLBACK — an uncaught exception no caller can
// `catch`. Reproduced here under `deno test` (it fails the whole runner, after
// the request itself had already been answered with the correct 503); in an Edge
// isolate an uncaught error event is the kind of thing that can take the worker
// down, and every other in-flight request on it with it. This is a LIBRARY bug we
// cannot patch (the import is pinned and hash-locked), so it is CONTAINED: this
// one exact signature (a TypeError reading 'write' of null, from postgres.js's
// connection.js `nextWrite`) is marked handled. Anything else — including any
// other TypeError — is left to surface exactly as before.
// The stack must name the PINNED module URL (the import is hash-locked to exactly
// this version): a different postgres.js version, or any other file's identical
// message, is NOT matched and surfaces as before. Bumping the pin means revisiting
// this guard — which is the point.
const POSTGRESJS_PINNED_CONNECTION = /deno\.land\/x\/postgresjs@v3\.4\.5\/src\/connection\.js/;
let containedClosedSocketWrites = 0;
/** How many closed-socket writes this isolate has contained (for tests and logs). */
export function getContainedClosedSocketWrites(): number {
  return containedClosedSocketWrites;
}
export function isPostgresJsClosedSocketWrite(err: unknown): boolean {
  if (!(err instanceof TypeError)) return false;
  const stack = String(err.stack ?? "");
  return /reading 'write'/.test(err.message) && POSTGRESJS_PINNED_CONNECTION.test(stack) && /nextWrite/.test(stack);
}
function containClosedSocketWrite(ev: Event, err: unknown): void {
  if (!isPostgresJsClosedSocketWrite(err)) return;
  ev.preventDefault();
  containedClosedSocketWrites++;
  console.error(`privileged: contained a postgres.js write to an already-closed socket (connection killed mid-transaction); total this isolate: ${containedClosedSocketWrites}`);
}
if (typeof globalThis.addEventListener === "function") {
  globalThis.addEventListener("error", (ev: Event) => containClosedSocketWrite(ev, (ev as ErrorEvent).error));
  globalThis.addEventListener("unhandledrejection", (ev: Event) => containClosedSocketWrite(ev, (ev as PromiseRejectionEvent).reason));
}
// ==== END P3f additions ======================================================

// ============================================================================
// ==== App Attest key registration additions — `devices-attest-key` (F2) ======
// =====================================================================
// ============================================================================
// Everything between this banner and the matching END banner belongs to App Attest key registration
// (`POST /v1/devices/attest-key`, 0034). Appended, not interleaved, like the P3f section above; the only line
// elsewhere in this file is the single `attestKey: buildAttestKeyRepo(trx, uid)` seam inside `buildRepo` (and the
// one-statement `deviceAttestState` change in the P3f section, which now returns only a REGISTERED key).
import type { AttestKeyRepo } from "./rewards/types.ts";
import type { RegistrationVerifierConfig } from "./rewards/app-attest-registration.ts";
import { APPLE_APP_ATTEST_ROOT_DER } from "./rewards/apple-app-attest-root.ts";

function attestKeyError(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  // SQLSTATEs app.register_attest_key raises (0034): 55000 = the device already holds this very key; 23514 = this
  // key was retired on this device and may not return (or the one-way counter trigger refused); P0002 = no such
  // device for this user; 22023 = a malformed key / non-iOS device (the verifier makes both unreachable).
  if (code === "55000") return Errors.conflict("key_already_registered", "this key is already registered on this device");
  if (code === "23514") return Errors.conflict("key_previously_retired", "this key was retired on this device and cannot be registered again");
  if (code === "P0002") return Errors.notFound("no such device");
  if (code === "22023") return Errors.unprocessable("attestation_rejected", "the attestation could not be verified");
  return err;
}

function buildAttestKeyRepo(trx: TxSql, uid: string, mode: DbMode): AttestKeyRepo {
  return {
    async deviceKey(deviceId: string) {
      // Ownership is part of the WHERE clause: another user's id and a nonexistent id are the same empty result.
      const rows = await trx`select platform, attest_key_id from app.device where id = ${deviceId} and user_id = ${uid}`;
      const r = rows[0];
      if (!r) return null;
      return { platform: r.platform as "ios" | "android", keyId: (r.attest_key_id as string | null) ?? null };
    },

    async register(input: { deviceId: string; keyId: string; publicKey: Uint8Array }): Promise<"registered" | "replaced"> {
      try {
        // One SQL function (0034): validates the key against its id, locks the caller's own device row, writes the key
        // (a reinstall's replacement restarts the counter, retires the old key) and audits it.
        // EDGE MODE (0034): edge_actor cannot call `app.register_attest_key` (it names any user); `private.register_attest_key_for_actor`
        // runs it as private_definer for the BOUND actor (no user argument). Same SQLSTATEs either way.
        const rows =
          mode === "edge"
            ? await trx`select private.register_attest_key_for_actor(${input.deviceId}::uuid, ${input.keyId}, ${input.publicKey}) as result`
            : await trx`select app.register_attest_key(${uid}, ${input.deviceId}, ${input.keyId}, ${input.publicKey}) as result`;
        return rows[0]!.result as "registered" | "replaced";
      } catch (err) {
        throw attestKeyError(err);
      }
    },
  };
}

/** Reads the configuration for `devices-attest-key` from the environment (this file is the only one allowed to).
 * `null` = UNCONFIGURED, and the endpoint then answers 503 before reading or writing anything. Configured only
 * when EVERY variable is present and sane — a half-set configuration is "not configured", never a default.
 *   GR_APPLE_TEAM_ID, GR_APPLE_BUNDLE_ID   the App ID whose SHA-256 is the attestation's rpIdHash (the same two
 *                                           variables the DeviceCheck / assertion path reads)
 *   GR_APPLE_APPATTEST_ENV                  "production" | "development": which aaguid an attestation must carry.
 *                                           Deliberately its own variable (not GR_APPLE_DEVICECHECK_ENV): it is a
 *                                           property of the app BUILD's entitlement, DeviceCheck's is a property of
 *                                           the API host, and registration needs no DeviceCheck credential. In a
 *                                           normal deployment the two agree.
 * THE TRUST ANCHOR is not configuration: it is Apple's root, pinned in code (rewards/apple-app-attest-root.ts) and
 * set here, and only here, as `trustAnchorDer`. No variable, request field or row can supply another. */
export function loadAttestKeyVerifierConfig(): RegistrationVerifierConfig | null {
  const teamId = (Deno.env.get("GR_APPLE_TEAM_ID") ?? "").trim();
  const bundleId = (Deno.env.get("GR_APPLE_BUNDLE_ID") ?? "").trim();
  const environment = (Deno.env.get("GR_APPLE_APPATTEST_ENV") ?? "").trim();
  if (teamId === "" || bundleId === "" || /\s/.test(teamId + bundleId) || (environment !== "production" && environment !== "development")) return null;
  return { appId: `${teamId}.${bundleId}`, environment, trustAnchorDer: APPLE_APP_ATTEST_ROOT_DER };
}
// ==== END App Attest key registration additions ===============================

// ============================================================================
// ==== O12 sign-in additions — `me-signin-methods`, provider-grant revocation ==
// ============================================================================
// Everything between this banner and the matching END banner is the O12 sign-in builder's (build plan §3.4 Auth row, §4.4
// `signin_provider_token`, §4.8, §7.8; migration 0035). It is appended (not interleaved) on purpose: other builders append their
// own delimited sections to this file too, and one block per builder keeps the merge to "keep both". The only O12 line elsewhere
// in this file is the single `signin: buildSigninRepo(trx, uid)` seam inside `buildRepo`. The imports below are ES imports and
// hoist, so they sit with the code they serve rather than in the header.
//
// ⚠ Nothing here has been exercised against Apple, Google or a real Supabase Auth (no credentials, no route): the Apple and Google
// adapters (_shared/signin/) are proven against scripted fakes, the database half against the real harness cluster.

import { kekFromBase64, type Kek } from "./signin/envelope.ts";
import type { AppleSecretConfig } from "./signin/apple-client-secret.ts";
import { NotConfiguredError } from "./signin/errors.ts";
import { constantTimeEqual } from "./signin/bytes.ts";
import type { ClaimedRevocation, EmailOtpResult, EmailOtpVerifier, LinkIdentityInput, OtpFailureCounter, RevocationDb, RevocationJob, SigninMethodRow, SigninRepo, SigninSystemOps } from "./signin/types.ts";

/** The Sign in with Apple server configuration, or `null` when ANY of the four values is absent or blank (a half-set configuration is
 * "not configured", never a default). These are the only environment reads for this feature, and this is the only place they happen.
 *   GR_APPLE_TEAM_ID            Apple developer team id (shared with the DeviceCheck configuration)
 *   GR_APPLE_SIWA_CLIENT_ID     the client id: the app's bundle id for the native flow (the `aud` of the identity token)
 *   GR_APPLE_SIWA_KEY_ID        the id of the Sign in with Apple private key
 *   GR_APPLE_SIWA_PRIVATE_KEY   that key's `.p8` contents (PKCS#8 PEM); a secret, never logged, never sent to any client
 * Supabase Auth's OWN Apple provider settings (the Services ID, the team id, the key id and a pre-generated client-secret JWT) are a
 * dashboard step, not code: see docs/security/p3-money-path-requirements.md ("Sign in with Apple, server side"). */
export function loadAppleSiwaConfig(): AppleSecretConfig | null {
  const teamId = (Deno.env.get("GR_APPLE_TEAM_ID") ?? "").trim();
  const clientId = (Deno.env.get("GR_APPLE_SIWA_CLIENT_ID") ?? "").trim();
  const keyId = (Deno.env.get("GR_APPLE_SIWA_KEY_ID") ?? "").trim();
  const privateKeyPem = Deno.env.get("GR_APPLE_SIWA_PRIVATE_KEY") ?? "";
  if (teamId === "" || clientId === "" || keyId === "" || privateKeyPem.trim() === "") return null;
  return { teamId, clientId, keyId, privateKeyPem };
}

/** True only when the request carries the project's service-role key as its bearer token (constant-time). The revocation drain is
 * system work, called by a scheduler holding that key; Supabase's gateway check alone would also admit an anon key. */
export function isServiceRoleBearer(req: Request): boolean {
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const header = req.headers.get("Authorization") ?? "";
  if (key === "" || !header.toLowerCase().startsWith("bearer ")) return false;
  return constantTimeEqual(header.slice(header.indexOf(" ") + 1).trim(), key);
}

/** SQLSTATEs the private.signin_* definers raise (0035) -> the HTTP answers. */
function signinDbError(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  const message = String((err as { message?: unknown } | null)?.message ?? "");
  if (code === "23505") {
    return message.startsWith("provider_already_linked")
      ? Errors.conflict("provider_already_linked", "this account already has a different identity linked for that provider")
      : Errors.conflict("identity_conflict", "that sign-in identity is already linked to another account");
  }
  if (code === "P0002") return Errors.notFound("that sign-in method is not linked");
  if (code === "55000") return Errors.unprocessable("last_sign_in_method", "the only remaining sign-in method cannot be unlinked");
  return mapPgTimeoutError(err);
}

const SIGNIN_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const toBytes = (v: unknown): Uint8Array => new Uint8Array(v as ArrayLike<number>);

async function readKek(run: () => Promise<{ o_kek_id: string; o_kek_b64: string }[]>): Promise<Kek> {
  let rows: { o_kek_id: string; o_kek_b64: string }[];
  try {
    rows = await run();
  } catch (e) {
    const code = (e as { code?: unknown } | null)?.code;
    // P0002: no such secret in Vault. 22023: present but not a base64 32-byte key. Both are "the key is not usable": fail closed.
    if (code === "P0002") throw new NotConfiguredError("kek_missing");
    if (code === "22023") throw new NotConfiguredError("kek_malformed");
    throw e;
  }
  const row = rows[0];
  if (!row) throw new NotConfiguredError("kek_missing");
  return kekFromBase64(row.o_kek_id, row.o_kek_b64); // EnvelopeError('kek_length') if the decoded key is not 32 bytes
}

/** The system operations (queue claim / complete / purge, the KEK by id, the OTP-failure counter). Same SQL in both modes: the queue
 * functions are granted to service_role AND edge_system, `get_signin_token_kek` to service_role, edge_actor and edge_system, and the
 * OTP-failure functions to service_role and edge_actor. WHICH transaction runs them is decided by `withSigninSystem` (queue) and
 * `signinOtpFailuresFor` (OTP counter) below. */
function buildSigninSystemOps(trx: TxSql): SigninSystemOps {
  const kekRows = async (kekId: string | null) =>
    (await trx`select o_kek_id, o_kek_b64 from private.get_signin_token_kek(${kekId}::text)`) as unknown as { o_kek_id: string; o_kek_b64: string }[];
  return {
    async claim(ids, limit, leaseSeconds): Promise<ClaimedRevocation[]> {
      // Validated, then passed as a literal array text and cast: no id ever reaches the statement unchecked.
      if (ids !== null && !ids.every((i) => SIGNIN_UUID_RE.test(i))) throw new Error("signin claim: a queue id is not a uuid");
      const arr = ids === null ? null : `{${ids.join(",")}}`;
      const rows = await trx`
        select o_id, o_provider, o_ciphertext, o_dek_wrapped, o_kek_id, o_attempts, o_expires_at
        from private.claim_signin_revocations(${arr}::uuid[], ${limit}::int, ${leaseSeconds}::int)`;
      return rows.map(
        (r): ClaimedRevocation => ({
          id: r.o_id,
          provider: r.o_provider,
          envelope: { ciphertext: toBytes(r.o_ciphertext), dekWrapped: toBytes(r.o_dek_wrapped), kekId: r.o_kek_id },
          attempts: Number(r.o_attempts),
          expiresAt: r.o_expires_at instanceof Date ? r.o_expires_at.toISOString() : String(r.o_expires_at),
        }),
      );
    },
    async complete(id, outcome, errorCode, backoffSeconds): Promise<string> {
      const rows = await trx`select private.complete_signin_revocation(${id}::uuid, ${outcome}, ${errorCode}, ${backoffSeconds}::int) as state`;
      return String(rows[0]?.state ?? "pending");
    },
    async purge(olderThanDays): Promise<number> {
      const rows = await trx`select private.purge_signin_revocation_queue(make_interval(days => ${olderThanDays}::int)) as n`;
      return Number(rows[0]?.n ?? 0);
    },
    kekById: (kekId: string) => readKek(() => kekRows(kekId)),
    async peekOtpFailures(emailHash): Promise<number> {
      const rows = await trx`select private.peek_signin_otp_failures(${emailHash}) as n`;
      return Number(rows[0]?.n ?? 0);
    },
    async recordOtpFailure(emailHash): Promise<number> {
      const rows = await trx`select private.hit_signin_otp_failure(${emailHash}) as n`;
      return Number(rows[0]?.n ?? 0);
    },
  };
}

/** Per-user operations. `legacy`: the 0035 CORE definers with an explicit uid (service_role). `edge`: the `_for_actor` wrappers (edge_actor,
 * no uid argument: the bound actor of this transaction; a wrong uid cannot even be expressed). The result shapes are identical. The one
 * operation with no edge form is linking an identity to ANOTHER account (the OTP-proven link): there is deliberately no edge definer for it
 * (it would be an "attach an identity to any account" primitive), so in edge mode `crossAccountLink` is false and the handler answers 501
 * before it consumes an OTP or exchanges a code (docs/security/edge-role-design.md §12; PR3 item O5). */
function buildSigninRepo(trx: TxSql, uid: string, mode: DbMode): SigninRepo {
  const guard = async <T>(op: () => Promise<T>): Promise<T> => {
    try {
      return await op();
    } catch (e) {
      throw signinDbError(e);
    }
  };
  const kekRows = async (kekId: string | null) =>
    (await trx`select o_kek_id, o_kek_b64 from private.get_signin_token_kek(${kekId}::text)`) as unknown as { o_kek_id: string; o_kek_b64: string }[];
  const edge = mode === "edge";
  const mustBeSelf = (target: string) => {
    if (edge && target.toLowerCase() !== uid.toLowerCase()) throw new HttpError(501, "email_proof_link_unavailable", "linking an identity to another account is not available in this mode");
  };
  return {
    crossAccountLink: !edge,

    listMethods: () =>
      guard(async () => {
        const rows = edge
          ? await trx`select o_provider, o_subject, o_email, o_is_private_relay, o_linked_at, o_has_token from private.signin_methods_for_actor()`
          : await trx`select o_provider, o_subject, o_email, o_is_private_relay, o_linked_at, o_has_token from private.signin_methods(${uid}::uuid)`;
        return rows.map(
          (r): SigninMethodRow => ({
            provider: r.o_provider,
            subject: r.o_subject,
            email: r.o_email ?? null,
            isPrivateRelay: Boolean(r.o_is_private_relay),
            linkedAt: r.o_linked_at instanceof Date ? r.o_linked_at.toISOString() : String(r.o_linked_at),
            hasToken: Boolean(r.o_has_token),
          }),
        );
      }),

    findAccountByEmail: (email: string) =>
      guard(async () => {
        const rows = await trx`select private.signin_find_account_by_email(${email}) as id`;
        return (rows[0]?.id as string | null | undefined) ?? null;
      }),

    linkIdentity: (targetUserId: string, input: LinkIdentityInput) =>
      guard(async () => {
        if (!SIGNIN_UUID_RE.test(targetUserId)) throw Errors.internal();
        mustBeSelf(targetUserId);
        const rows = edge
          ? await trx`select private.signin_link_identity_for_actor(${input.provider}, ${input.subject}, ${input.email}, ${input.emailVerified}, ${input.isPrivateRelay}) as created`
          : await trx`select private.signin_link_identity(${targetUserId}::uuid, ${input.provider}, ${input.subject}, ${input.email}, ${input.emailVerified}, ${input.isPrivateRelay}) as created`;
        return Boolean(rows[0]?.created);
      }),

    storeToken: (targetUserId: string, provider, envelope) =>
      guard(async () => {
        if (!SIGNIN_UUID_RE.test(targetUserId)) throw Errors.internal();
        mustBeSelf(targetUserId);
        // Uint8Array parameters, cast to bytea: postgres.js serialises them as bytea (never as text).
        if (edge) {
          await trx`select private.signin_store_token_for_actor(${provider}, ${envelope.ciphertext}::bytea, ${envelope.dekWrapped}::bytea, ${envelope.kekId})`;
        } else {
          await trx`select private.signin_store_token(${targetUserId}::uuid, ${provider}, ${envelope.ciphertext}::bytea, ${envelope.dekWrapped}::bytea, ${envelope.kekId})`;
        }
      }),

    unlinkIdentity: (provider: string) =>
      guard(async () => {
        const rows = edge
          ? await trx`select o_queue_id from private.signin_unlink_identity_for_actor(${provider})`
          : await trx`select o_queue_id from private.signin_unlink_identity(${uid}::uuid, ${provider})`;
        return rows.map((r) => r.o_queue_id as string);
      }),

    enqueueRevocations: () =>
      guard(async () => {
        const rows = edge
          ? await trx`select o_queue_id, o_provider from private.signin_enqueue_revocations_for_actor()`
          : await trx`select o_queue_id, o_provider from private.signin_enqueue_revocations(${uid}::uuid)`;
        return rows.map((r): RevocationJob => ({ queueId: r.o_queue_id as string, provider: r.o_provider as string }));
      }),

    currentKek: () => readKek(() => kekRows(null)),
    kekById: (kekId: string) => readKek(() => kekRows(kekId)),
    system: buildSigninSystemOps(trx),
  };
}

/** The identity the LEGACY-mode sign-in system operations run under: `withOwnership` needs an actor to build its Repo, and these operations
 * (the revocation queue) act on no account, so they never read it. */
const SIGNIN_SYSTEM_ACTOR: Actor = { uid: "00000000-0000-0000-0000-000000000000", role: "authenticated" };

/** The revocation-queue operations, each call its own short transaction. `legacy`: through `withOwnership` as service_role (the nil-uid
 * actor above is never read). `edge`: through `openScopedTx("system", ...)` as **edge_system**, the role 0035 granted claim / complete /
 * purge / the KEK reader to (no actor is bound; edge_system has no privilege on any PII table, check 12). The OTP-failure counter is NOT
 * here: edge_system has no grant on it, so it runs as the caller's actor (`signinOtpFailuresFor`). */
function withSigninSystem<T>(op: (sys: SigninSystemOps) => Promise<T>): Promise<T> {
  if (getDbMode() === "edge") {
    return openScopedTx("system", { expectedUid: null }, (trx) => op(buildSigninSystemOps(trx))).catch((err) => {
      throw mapPgTimeoutError(err);
    });
  }
  return withOwnership(SIGNIN_SYSTEM_ACTOR, (repo) => op(repo.signin.system));
}

/** The revocation queue, as the runner (_shared/signin/revocation.ts) needs it. Every call is its OWN short transaction: a vendor call is
 * never made while one is open. */
export const signinRevocationDb: RevocationDb = {
  claim: (ids, limit, leaseSeconds) => withSigninSystem((s) => s.claim(ids, limit, leaseSeconds)),
  complete: (id, outcome, errorCode, backoffSeconds) => withSigninSystem((s) => s.complete(id, outcome, errorCode, backoffSeconds)),
  kekById: (kekId) => withSigninSystem((s) => s.kekById(kekId)),
  purge: (olderThanDays) => withSigninSystem((s) => s.purge(olderThanDays)),
};

/** The OTP-proof failure counter (§4.7 item 8), run AS THE CALLER (service_role in legacy mode, the bound edge_actor in edge mode: both
 * hold the two OTP-failure functions and nothing wider is needed). `record` commits on its own, BEFORE the request fails, so a failed
 * proof always counts (the same ordering rule as hitRateLimitForActor). */
export function signinOtpFailuresFor(actor: Actor): OtpFailureCounter {
  return {
    peek: (emailHash) => withOwnership(actor, (repo) => repo.signin.system.peekOtpFailures(emailHash)),
    record: (emailHash) => withOwnership(actor, (repo) => repo.signin.system.recordOtpFailure(emailHash)),
  };
}

/** Proof of mailbox control by an email OTP, through Supabase Auth's verifyOtp with the ANON key (the response's session is
 * discarded: this server never hands one to a client). A wrong or expired code is `{ ok: false }`; a transport or server failure
 * THROWS, so it is not counted against the address. `[unverified — training knowledge of GoTrue's verifyOtp error statuses]`. */
export const supabaseEmailOtpVerifier: EmailOtpVerifier = {
  async verify(email: string, code: string): Promise<EmailOtpResult> {
    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!url || !anonKey) throw new Error("privileged.ts: SUPABASE_URL/SUPABASE_ANON_KEY are not set in this environment");
    const client = createClient(url, anonKey, { auth: { autoRefreshToken: false, persistSession: false } });
    const { data, error } = await client.auth.verifyOtp({ email, token: code, type: "email" });
    if (error) {
      const status = (error as { status?: number }).status;
      if (status === 400 || status === 401 || status === 403 || status === 404 || status === 422) return { ok: false };
      throw new Error("supabase auth verifyOtp failed");
    }
    const id = data?.user?.id;
    if (!id) throw new Error("supabase auth verifyOtp returned no user");
    return { ok: true, userId: id };
  },
};
// ==== END O12 sign-in additions ==============================================
