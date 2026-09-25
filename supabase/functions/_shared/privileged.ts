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
import { Errors } from "./http.ts";

import type {
  Actor,
  CatalogVersionRow,
  ChallengeRow,
  ConsumedCheckinToken,
  ExistingEvidenceRow,
  InsertEvidenceResult,
  LedgerRow,
  MatchResult,
  NewEvidenceRow,
  RateLimitResult,
  Repo,
  SigningKeyRow,
  StoredEvidenceRow,
  StoredPlayRow,
  UpsertPlayInput,
  UpsertPlayResult,
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

function sql(): ReturnType<typeof postgres> {
  if (_sql) return _sql;
  const dbUrl = Deno.env.get("SUPABASE_DB_URL");
  if (!dbUrl) {
    throw new Error("privileged.ts: SUPABASE_DB_URL is not set in this environment");
  }
  _sql = postgres(dbUrl, {
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
  return _sql;
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
function buildRepo(trx: TxSql, actor: Actor): Repo {
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
      async currentVersion(): Promise<CatalogVersionRow | null> {
        const rows = await trx`
          select version, contract_version, sha256, kid, published_at
          from app.catalog_version order by version desc limit 1`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, contractVersion: r.contract_version, sha256: r.sha256, kid: r.kid, publishedAt: r.published_at.toISOString() };
      },

      async versionRow(version: number): Promise<CatalogVersionRow | null> {
        const rows = await trx`
          select version, contract_version, sha256, kid, published_at
          from app.catalog_version where version = ${version}`;
        const r = rows[0];
        if (!r) return null;
        return { version: r.version, contractVersion: r.contract_version, sha256: r.sha256, kid: r.kid, publishedAt: r.published_at.toISOString() };
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
        const rows = await trx`select count(*)::int as n from app.catalog_hole where course_id = ${courseId}`;
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
        const rows = await trx`select kid, public_key_b64url, revoked_at from app.catalog_signing_key where kid = ${kid}`;
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
        const inserted = await trx`
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
    },

    fraudSignal: {
      // ⛔ FIX (P3d gate round 3, S2, MEDIUM): "make repeated finalize
      // idempotent for fraud signals: no duplicate quarantined_evidence_row
      // signal on each retry." `finalizeScoringForKey` (evidence/
      // handler.ts) can now genuinely run twice for the SAME play — once
      // from a batch's own phase 2b, once more from `buildReplayResult`'s
      // new live-retry path (this same round's S2 fix) if a client
      // retries after an interrupted batch — and both passes independently
      // decide whether a quarantine signal is warranted from the SAME
      // underlying evidence rows, so a naive unconditional INSERT would
      // raise it twice. Deduped on (kind, detail->>'playId') via a single
      // atomic `INSERT ... SELECT ... WHERE NOT EXISTS` (not a separate
      // SELECT-then-INSERT, which would leave a race window) whenever the
      // caller's own `detail` carries a `playId` — every current
      // `quarantined_evidence_row` call site does. A `detail` with no
      // `playId` (the `clock_skew` kind, keyed on `fixIds` instead) has no
      // dedupe key to work from and is left exactly as before — always
      // inserts, never silently dropped.
      async insert(kind: string, detail: Record<string, unknown>): Promise<void> {
        const playId = typeof detail.playId === "string" ? detail.playId : null;
        if (playId === null) {
          await trx`insert into app.fraud_signal (user_id, kind, detail) values (${uid}, ${kind}, ${trx.json(detail as never)})`;
          return;
        }
        await trx`
          insert into app.fraud_signal (user_id, kind, detail)
          select ${uid}, ${kind}, ${trx.json(detail as never)}
          where not exists (
            select 1 from app.fraud_signal where kind = ${kind} and detail ->> 'playId' = ${playId}
          )
        `;
      },
    },

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
        const rows = await trx`select private.delete_my_data(${uid}) as result`;
        const result = rows[0]?.result as { user_id?: string; deleted_at?: string } | undefined;
        if (!result || typeof result.user_id !== "string" || typeof result.deleted_at !== "string") {
          throw new Error("me.deleteMyData: private.delete_my_data returned an unexpected shape");
        }
        return { userId: result.user_id, deletedAt: result.deleted_at };
      },
      async exportMyData() {
        const rows = await trx`select private.export_my_data(${uid}) as result`;
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
      const repo = buildRepo(trx, actor);
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
            const repo = buildRepo(sp, actor);
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
