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
// test` can import and resolve `postgres` and `@supabase/supabase-js`
// from these exact pinned URLs (now resolved through
// supabase/functions/deno.json's import map — see the should-fix note
// below) over this session's network proxy, and separately confirmed
// Deno 2.5.2's `crypto.subtle` supports Ed25519 (catalog/signature.ts) —
// neither confirms this exact driver version behaves identically inside
// the REAL hosted Supabase Edge Runtime, which this session has no
// access to. Flagged per this repo's own accuracy discipline, alongside
// the pre-existing "pin --config at deploy time" unverified flag in
// docs/security/p3-money-path-requirements.md.]
//
// ⛔ FIX (P3c gate round 2, should-fix "supply chain"): these two used to
// be raw `https://` string-literal imports, invisible to
// tools/service-role-lint's own pinned-target discipline in a way no
// OTHER third-party dependency in this codebase is (zod/@noble/hashes/
// tz-lookup all resolve through the reviewed
// supabase/functions/deno.json import map + pinned-import-targets.json
// allow-list — see generate-bundle.sh's own header for why). Moved to
// bare specifiers resolved through that SAME reviewed map: privileged.ts
// itself stays exempt from the lint's AST content scan (rule (a)/(b)/(c)
// — it legitimately needs the raw env access / client construction every
// other file is banned from), but its import GRAPH is no longer a
// special case — config.ts's own model validates every deno.json's
// import-map target against pinned-import-targets.json regardless of
// which file resolves through it (see that module's own header, point
// 1: "regardless of whether any source file currently imports through
// it"), so bumping either pin now means touching the SAME two reviewed,
// diffable files (deno.json + pinned-import-targets.json) every other
// dependency bump already requires — not an inline URL edit invisible to
// that discipline.
import postgres from "postgres";
import { createClient } from "@supabase/supabase-js";

import type {
  Actor,
  CatalogVersionRow,
  ChallengeRow,
  ConsumedCheckinToken,
  InsertEvidenceResult,
  LedgerRow,
  MatchResult,
  NewEvidenceRow,
  RateLimitResult,
  Repo,
  SigningKeyRow,
  StoredEvidenceRow,
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
 * callback in ONE sql.begin()"). */
type TxSql = ReturnType<typeof postgres>;

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
  });
  return _sql;
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

function buildRepo(trx: TxSql, actor: Actor): Repo {
  const uid = actor.uid;
  return {
    now(): Date {
      return new Date();
    },

    rateLimit: {
      async hit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult> {
        // ⛔ FIX (found via the P3c gate round 2 Deno integration suite,
        // item 5's own class of bug: "withOwnership ignores the actor").
        // Every caller (evidence/handler.ts, checkin/challenge-handler.ts,
        // checkin/token-handler.ts, evidence-batch/index.ts) passes a
        // BARE bucket key like "evidence:user" or "checkin-token:user" —
        // it relies on THIS method to scope it per actor, exactly like
        // every other Repo method closes over `uid` itself. Without the
        // prefix below, every user on the platform shared the SAME
        // "evidence:user" bucket in private.rate_limit_bucket — a global
        // rate limit, not a per-user one (the device-keyed bucket,
        // `evidence:device:${device.id}`, already happened to be
        // per-device by construction, but the per-USER buckets were not
        // per-user at all). Caught only by running this against a real
        // Postgres cluster with two distinct actors — no fake/unit test
        // exercised two actors racing the SAME literal bucket key.
        const scopedBucketKey = `${uid}:${bucketKey}`;
        try {
          const rows = await trx`select private.hit_rate_limit(${scopedBucketKey}, ${windowSeconds + " seconds"}::interval, ${max}) as count`;
          return { ok: true, count: Number(rows[0]?.count ?? 0) };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (message.includes("rate_limit_exceeded") || (err as { code?: string })?.code === "P0429") {
            return { ok: false, count: max + 1, retryAfterSeconds: windowSeconds };
          }
          throw err;
        }
      },
    },

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
            user_id, device_id, source, source_ref, course_id, facility_id,
            started_at, ended_at, local_date, summary, integrity, cosignal,
            attestation_grade, matcher_version, catalog_version, status
          ) values (
            ${uid}, ${row.deviceId}, ${row.source}::app.evidence_source, ${row.sourceRef}, ${row.courseId}, ${row.facilityId},
            ${row.startedAt}, ${row.endedAt}, ${row.localDate}, ${trx.json(row.summary as never)}, ${trx.json(row.integrity as never)}, ${trx.json(row.cosignal as never)},
            ${row.attestationGrade}::app.attestation_grade, ${row.matcherVersion}, ${row.catalogVersion}, ${row.status}::app.evidence_status
          )
          on conflict (user_id, source, source_ref) do nothing
          returning id, status`;
        if (inserted[0]) {
          return { id: inserted[0].id, wasNew: true, status: inserted[0].status };
        }
        const existing = await trx`select id, status from app.evidence where user_id = ${uid} and source = ${row.source}::app.evidence_source and source_ref = ${row.sourceRef}`;
        if (!existing[0]) throw new Error("insertIdempotent: conflict reported but no existing row found");
        return { id: existing[0].id, wasNew: false, status: existing[0].status };
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
    },

    fraudSignal: {
      async insert(kind: string, detail: Record<string, unknown>): Promise<void> {
        await trx`insert into app.fraud_signal (user_id, kind, detail) values (${uid}, ${kind}, ${trx.json(detail as never)})`;
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
        if (!existing[0]) throw new Error("ensureOwn: conflict reported but no existing row found for this user");
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
        const rows = await trx`
          insert into app.checkin_challenge (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at)
          values (${input.staffUserId ? null : uid}, ${input.staffUserId}, ${input.deviceId}, ${input.facilityId}, ${input.nonceHash}, ${input.kind}, clock_timestamp(), ${input.expiresAt})
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
        // submitting device matching the token's own device_id, AND the
        // challenge-window clamp (issued_at <= capturedAt <= expires_at)
        // — no separate read-then-decide-then-write race window.
        const capturedAt = new Date(capturedAtMs);
        const rows = await trx`
          update app.checkin_token
          set consumed_at = now()
          where jti = ${jti}
            and user_id = ${uid}
            and device_id = ${submittingDeviceId}
            and consumed_at is null
            and expires_at > now()
            and issued_at <= ${capturedAt}
            and ${capturedAt} <= expires_at
          returning facility_id, attestation_grade, challenge_kind`;
        const r = rows[0];
        if (!r) return null;
        return { facilityId: r.facility_id, attestationGrade: r.attestation_grade, challengeKind: r.challenge_kind };
      },
    },
  };
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
  // The explicit `as Promise<T>`: postgres.js's own `.d.ts` types
  // `begin<T2>(cb: (sql) => T2 | Promise<T2>): Promise<UnwrapPromiseArray<T2>>`
  // — a SEPARATE generic (T2) from this function's own `T`, and
  // `UnwrapPromiseArray<T2>` is not provably assignable back to an
  // UNCONSTRAINED `T` for every possible instantiation (`deno check`
  // TS2322, caught this round by the P3c gate round 2 integration suite
  // work — never actually run before). Every caller here always passes a
  // plain (non-array, non-nested-Promise) value through `op`, so the cast
  // is sound in practice; the type system alone can't prove it generically.
  return db.begin(async (trx: TxSql) => {
    // "Conditions on the BYPASSRLS design" (required): the connecting
    // role is NOT assumed to already be service_role (it may be
    // `postgres` on a real hosted project — [unverified], see this
    // file's own header). Activate it explicitly and verify.
    await trx`set local role service_role`;
    const check = await trx`select current_user as u`;
    if (check[0]?.u !== "service_role") {
      throw new Error(`withOwnership: expected current_user = 'service_role' after SET LOCAL ROLE, got '${check[0]?.u}'`);
    }
    const repo = buildRepo(trx, actor);
    return op(repo);
  }) as Promise<T>;
}
