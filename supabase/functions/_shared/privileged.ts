// supabase/functions/_shared/privileged.ts
// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1183-1205): "Writes and privileged reads go only through
// supabase/functions/_shared/privileged.ts -> withOwnership(actor, op)."
//
// THIS FILE is the SOLE allow-listed construction site for a Postgres connection and for the one remaining service-role-keyed
// client (`adminClient`, GoTrue admin calls only), and the sole allow-listed place a raw `.from()`/`.rpc()`/Storage call, a
// Postgres driver import, or an env read of anything outside the public allow-list may appear (tools/service-role-lint rules
// (a)-(c)): `tools/service-role-lint/src/lint.ts`'s `isAllowedFile` exempts this EXACT path (`supabase/functions/_shared/
// privileged.ts`) from the general rules, and since edge role PR4b a SEPARATE privileged-file pass (`lintPrivilegedSource`) runs
// over it and fails on any `service_role` / `set role` literal other than the two edge roles, any `SUPABASE_DB_URL`, the
// service-role key anywhere but `adminClient` and `isServiceRoleBearer`, a `.begin(` / `.savepoint(` outside `openScopedTx` /
// `withOwnershipBatch`, a `set_config(` / `current_setting(` in TypeScript, and any `EDGE_DB_MODE`.
//
// THE DATABASE ROLE MODEL (docs/security/edge-role-design.md): every transaction this file opens is `SET LOCAL ROLE edge_actor`
// (per-user work, identity = the database-side binding `private.bind_actor(uid)`) or `edge_system` (the catalog importer and the
// system drains), over ONE pool connecting as the NOBYPASSRLS login `edge_gateway` (GOLFRAVEN_EDGE_DB_URL). FORCE RLS therefore
// backs every Repo method. There is no `service_role` / BYPASSRLS path left (edge role PR4b deleted it, together with the
// `EDGE_DB_MODE` switch and every use of `SUPABASE_DB_URL` for database access).
//
// WHY A DIRECT POSTGRES CONNECTION, NOT supabase-js `.from()`/`.rpc()`:
// `supabase/config.toml` sets `db.schemas = ["api"]` — PostgREST (which `supabase-js` talks to) exposes ONLY the `api` schema.
// Every table this code reads or writes (`app.evidence`, `app.play`, ...) lives in `app`, and the rate-limit helper
// (`private.hit_actor_rate_limit`) lives in `private`: neither is PostgREST-exposed, at any role, so there is no `supabase-js`
// call shape that could ever reach them.
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
import { makeSelfCheckGate, type SelfCheckGate } from "./edge-selfcheck-gate.ts";
import {
  type AdminEnrolmentResult,
  type ChallengeIssue,
  type CourseQrDb,
  type CourseQrMintResult,
  type CourseQrPrintKeyResult,
  type CourseQrPrintReadResult,
  type CourseQrPrintWriteResult,
  type CourseQrRefreshResult,
  type CourseQrTx,
  type CoursePinRotateResult,
  type CoursePinShowResult,
  type CredentialLookup,
  type CredentialOptionsResult,
  type CredentialRegisterInput,
  type CredentialRevokeStatus,
  type CredentialSubject,
  type CredentialView,
  type EmailOtpPort,
  type EnrolmentAcceptResult,
  type EnrolmentAcceptStatus,
  type InviteAcceptResult,
  type InviteAcceptStatus,
  type InviteCreateResult,
  type InviteMemberAcceptResult,
  type InviteMemberAcceptStatus,
  type InviteRevokeStatus,
  type InviteRole,
  type InviteView,
  type MemberRecoverResult,
  type MemberRevokeStatus,
  type MintInput,
  type MintResult,
  type OrgRevokeAllResult,
  type AttestKind,
  type AttestResult,
  type AttestStatus,
  type EntitlementQueueRow,
  type HandoverMintResult,
  type HandoverMintStatus,
  type HeldQueueRow,
  type FacilityProgrammeRow,
  type FacilityProgrammeUpsertStatus,
  type OfferAdminRow,
  type OfferApproveStatus,
  type OfferEndStatus,
  type OfferUpsertResult,
  type OfferUpsertStatus,
  type OperatorRollupRow,
  type PartnerAttestTx,
  type PartnerDb,
  type PartnerEntitlementsTx,
  type OfferQueueRow,
  type OfferRedeemMethod,
  type OfferRedeemResult,
  type OfferRedeemStatus,
  type PartnerOffersAdminTx,
  type PartnerOffersRedeemTx,
  type PartnerProgrammeTx,
  type PartnerReviewTx,
  type PartnerSettlementExportTx,
  type PartnerSponsorshipsTx,
  type PartnerStockTx,
  type SettlementExportResult,
  type SettlementLine,
  type ExportsStoragePort,
  type RedeemMethod,
  type RedeemResult,
  type RedeemStatus,
  type ResolveHeldResult,
  type ResolveHeldStatus,
  type ReviewSlaSummary,
  type ShiftLogRow,
  type SponsorRollupRow,
  type SponsorshipApproveStatus,
  type SponsorshipRow,
  type SponsorshipUpsertResult,
  type SponsorshipUpsertStatus,
  type StaffActivityRow,
  type StockMoveKind,
  type StockMoveResult,
  type StockMoveStatus,
  type StockRow,
  type TrailProgrammeRow,
  type TrailProgrammeUpsertStatus,
  type VoucherResult,
  type VoucherStatus,
  type PartnerInviteMintTx,
  type PartnerInvitesTx,
  type PartnerMembersTx,
  type PartnerMintTx,
  type PartnerSessionTx,
  PartnerAuthorityRefused,
  PartnerConflict,
  PartnerInvalidArgument,
  PartnerNotConfigured,
  PartnerSessionRefused,
  type PinChangeInput,
  type PinCheckStatus,
  type PinParams,
  type PinSetInput,
  type PinVerifyResult,
  type PinWriteResult,
  type PinResetStatus,
  type PinWriteStatus,
  type ReauthCredential,
  type ReauthInput,
  type RegisterFirstInput,
  type RegisterFirstResult,
  type RpConfig,
  type TotpConfirmResult,
  type TotpConfirmStatus,
  type TotpEnrolResult,
  type TotpEnrolStatus,
  type TotpResetResult,
  type TotpVerifyResult,
  type TotpVerifyStatus,
} from "./partner/ports.ts";
import { parseAllowedOrigin } from "./partner/cors.ts";

import type { OwnReward, RewardsRepo } from "./rewards/types.ts";
import type { RewardsAttestationConfig } from "./rewards/production-ports.ts";
import type { PlayIntegrityConfig } from "./rewards/play-integrity-client.ts";
import type { VerificationConfig } from "./rewards/verification-ports.ts";
import type {
  Actor,
  CatalogVersionRow,
  ChallengeRow,
  ConsumedCheckinToken,
  IssuedCheckinTokenRow,
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
  DelegateRef,
  RescoreBacklogRow,
  RescoreCursor,
  RescorePlayRef,
  RetentionStep,
  RosterVersionInput,
  OfflineSeedProvision,
  CourseQrPublicKey,
  MarkerCosignalAttachInput,
  MarkerCosignalAttachResult,
  MarkerPurchaseView,
  MarkerScanRecordInput,
  MarkerScanRecordResult,
  MarkerScanRefusal,
  PinAttemptResult,
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

// ============================================================================
// EDGE ROLE (follow-up 6): the one database path.
// ============================================================================
// docs/security/edge-role-design.md. Every transaction runs as `edge_actor` (per-user work: FORCE RLS backs every Repo method, the
// identity is the database-side binding `private.bind_actor(uid)`, and a forgotten bind fails closed) or `edge_system` (the catalog
// importer, the drains, the purges), through ONE pool opened from GOLFRAVEN_EDGE_DB_URL (connecting as the NOBYPASSRLS login
// `edge_gateway`). The system path acts on a user's rows only through the delegate binders (`withDelegatedActor`).
//
// Edge role PR4b made this the ONLY mode: the `EDGE_DB_MODE` switch, the `service_role` (BYPASSRLS) pool, `SUPABASE_DB_URL` as a database
// input, `SIGNIN_SYSTEM_ACTOR` and the legacy rate-limit buckets are gone. The lint's privileged-file pass keeps them gone
// (tools/service-role-lint `lintPrivilegedSource`).

function openPool(): ReturnType<typeof postgres> {
  // The pool's ONLY input, read here and nowhere else: openPool takes no argument, so no caller can point a pool at another database, and the
  // lint's privileged-file pass (tools/service-role-lint) rejects a declaration with a parameter, a call with an argument, and a driver call
  // whose URL is anything but this constant (edge role PR4c, LOW-1).
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  if (!dbUrl) {
    throw new Error("privileged.ts: GOLFRAVEN_EDGE_DB_URL is not set (the edge_gateway connection string): every database path needs it");
  }
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

let _edgeSql: ReturnType<typeof postgres> | null = null;

function edgeSql(): ReturnType<typeof postgres> {
  if (_edgeSql) return _edgeSql;
  _edgeSql = openPool();
  return _edgeSql;
}

/** Roles the edge connection must never reach: the privileged ones PR1's check 9 keeps out of the closure. */
const EDGE_FORBIDDEN_MEMBERSHIPS = ["service_role", "authenticated", "anon", "authenticator", "private_definer", "supabase_admin", "postgres"];

/**
 * The self-check (edge mode), run on a pool's first connection and then periodically (see `edgeChecked`): the
 * session user is `edge_gateway`; nothing in its membership closure (itself included)
 * is a superuser or BYPASSRLS; and it is not a member of `service_role`, `authenticated`
 * (or the other privileged roles above). Any failure rejects with a plain Error — a 500
 * from every handler, i.e. FAILS CLOSED — and is not cached, so the next request
 * re-checks (a misconfiguration is never "remembered as fine", a transient error is retried).
 * WHEN it runs is `edgeChecked()`'s schedule below: on first use, then periodically (PR3).
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

/**
 * The self-check SCHEDULE (edge role PR3). PR2 ran `assertEdgeConnectionSafe` once per pool and remembered the success for the pool's
 * life; a worker lives for hours, and `ALTER ROLE edge_gateway BYPASSRLS` or `GRANT service_role TO edge_gateway` made after the first
 * request went unseen until the worker was recycled. The check now repeats: after EDGE_SELF_CHECK_INTERVAL_MS since the last success, or
 * EDGE_SELF_CHECK_EVERY_N_TX transactions, whichever comes first. A repeat costs one small catalog query; within the window the gate costs
 * nothing. A failure is never remembered (the next transaction checks again), and a repeat that fails refuses exactly as the first does:
 * a plain Error, a 500 from every handler. The schedule logic is `edge-selfcheck-gate.ts` (unit-tested without a database).
 *
 * Honest limit: this narrows the window from "the worker's lifetime" to the interval; it does not close it. A change made just after a
 * check is seen up to one interval (or N transactions) later, and the per-transaction assertion in `openScopedTx` is what covers the roles
 * the transaction switches INTO (edge_actor / edge_system gaining SUPERUSER or BYPASSRLS) at once.
 */
const EDGE_SELF_CHECK_INTERVAL_MS = 5 * 60 * 1000;
const EDGE_SELF_CHECK_EVERY_N_TX = 1000;

function newEdgeSelfCheckGate(over: { intervalMs?: number; everyNCalls?: number; now?: () => number } = {}): SelfCheckGate {
  return makeSelfCheckGate({
    check: () => assertEdgeConnectionSafe(edgeSql()),
    intervalMs: over.intervalMs ?? EDGE_SELF_CHECK_INTERVAL_MS,
    everyNCalls: over.everyNCalls ?? EDGE_SELF_CHECK_EVERY_N_TX,
    now: over.now,
  });
}

let _edgeGate: SelfCheckGate = newEdgeSelfCheckGate();

function edgeChecked(): Promise<void> {
  return _edgeGate.ensure();
}

/** Tests only: replaces the self-check schedule (a tiny interval, a fake clock, a call budget) and forgets earlier successes. The next
 * `resetPrivilegedConnectionsForTests` puts the production schedule back. Returns how many checks the gate has started, as a function. */
export function setEdgeSelfCheckScheduleForTests(over: { intervalMs?: number; everyNCalls?: number; now?: () => number }): () => number {
  const gate = newEdgeSelfCheckGate(over);
  _edgeGate = gate;
  return () => gate.checksStarted;
}

/** Tests only: closes the pool and forgets the self-check, so a test can point `GOLFRAVEN_EDGE_DB_URL` somewhere else and start clean. */
export async function resetPrivilegedConnectionsForTests(): Promise<void> {
  const b = _edgeSql;
  _edgeSql = null;
  _edgeGate.reset();
  _edgeGate = newEdgeSelfCheckGate();
  _supportsTransactionTimeout = null;
  await Promise.allSettled([b?.end({ timeout: 1 })]);
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
 * The system path's binding (edge role PR3): the DELEGATE binders, callable by `edge_system` only. Each binds the owner of ONE row, and only
 * while that row's precondition holds (migration 0030): `bind_delegate_for_queued_evidence` while the evidence is still `queued_catalog`;
 * `bind_delegate_for_rescore` while the backlog row is open and the play is at its course. `expectedUid` is the owner the caller believes the
 * row has (the drain read it from the system list); the transaction compares it with the database's own answer and refuses on a mismatch,
 * so a delegate can only ever act as the owner of the row it names.
 */
export function delegateBind(ref: DelegateRef, expectedUid: string): ScopedBind {
  if (ref.kind === "queued_evidence") {
    return { expectedUid, run: (trx) => trx`select private.bind_delegate_for_queued_evidence(${ref.evidenceId}::uuid)` };
  }
  return { expectedUid, run: (trx) => trx`select private.bind_delegate_for_rescore(${ref.backlogId}::bigint, ${ref.playId}::uuid)` };
}

/**
 * The partner lane's binding (partner-auth design 4.2, slice S1.2): `private.bind_partner_session(sha256(token))`, run as `edge_partner`. It binds NO uid the caller supplies: `expectedUid` is null,
 * because the handler never names a person (the session names the member, in the database). The Edge keeps only the HASH of the token; the raw token never reaches this function.
 */
export function partnerBind(tokenHash: string): ScopedBind {
  return { expectedUid: null, run: (trx) => trx`select private.bind_partner_session(${tokenHash})` };
}

/**
 * THE one way an edge-mode transaction is opened (design §6): in order,
 *   1. `SET LOCAL ROLE edge_actor | edge_system | edge_signin_minter | edge_partner | edge_partner_minter` (the session user, `edge_gateway`, may SET into each; the two minter kinds are for the
 *      email-proof minter and the partner sign-in minter only, design §12.1 and partner design 4.4);
 *   2. the three timeouts (`statement`, `lock`, and `transaction` where PG17+ has it);
 *   3. the bind (`private.bind_actor(uid)`; the system kind binds nothing; the DELEGATE kind starts as `edge_system`, calls a delegate
 *      binder, and only then switches to `edge_actor`: `bind_delegate_*` is `edge_system`-only, and the work that follows is the owner's;
 *      the PARTNER kind runs `private.bind_partner_session(hash)` as `edge_partner`);
 *   4. an assertion that `current_user` is the expected role, that role is neither SUPERUSER nor
 *      BYPASSRLS, and (actor / delegate kinds) `private.actor_uid()` equals the expected uid; for the partner kind, that `private.partner_binding_kind()` reads back as 'partner'.
 * Any failure throws before `op` runs. The self-check has already passed on this pool (and repeats, see `edgeChecked`).
 */
export async function openScopedTx<T>(kind: "actor" | "system" | "delegate" | "signin_mint" | "partner" | "partner_mint", bind: ScopedBind, op: (trx: TxSql) => Promise<T>): Promise<T> {
  await edgeChecked();
  const db = edgeSql();
  const txTimeoutSupported = await supportsTransactionTimeout(db);
  // `signin_mint` (migration 0041) is the ONE kind that runs as `edge_signin_minter`: the only role holding EXECUTE on private.signin_record_email_proof. It binds
  // nothing (the definer refuses inside an actor-bound transaction), and the privileged lint (privileged-mint-scope) lets only `signinEmailProofs` ask for it.
  // `partner_mint` (migration 0048) is the same shape for `edge_partner_minter` (the sign-in mint): it binds nothing, and the lint lets only `withPartnerMint` ask for it.
  // `partner` runs as `edge_partner`: no table privilege, `bind_partner_session` is its one way in, and a bind is REQUIRED (a partner transaction that binds nothing could call nothing useful).
  const role =
    kind === "system" ? "edge_system"
    : kind === "signin_mint" ? "edge_signin_minter"
    : kind === "partner" ? "edge_partner"
    : kind === "partner_mint" ? "edge_partner_minter"
    : "edge_actor";
  if (kind === "signin_mint" && (bind.run !== undefined || bind.expectedUid !== null)) throw new Error("openScopedTx: the signin_mint kind binds no actor (the minter refuses inside an actor-bound transaction)");
  if (kind === "partner_mint" && (bind.run !== undefined || bind.expectedUid !== null)) throw new Error("openScopedTx: the partner_mint kind binds no actor (the minter refuses inside a bound transaction)");
  if (kind === "partner" && (bind.run === undefined || bind.expectedUid !== null)) throw new Error("openScopedTx: the partner kind binds a SESSION (a bind is required) and names no actor uid (the handler never supplies one)");
  return await (db.begin(async (trx: TxSql) => {
    // Literal SQL text (no `${...}`): SET LOCAL takes no bind parameter — see the note above STATEMENT_TIMEOUT.
    if (kind === "actor") await trx`set local role edge_actor`;
    else if (kind === "signin_mint") await trx`set local role edge_signin_minter`;
    else if (kind === "partner") await trx`set local role edge_partner`;
    else if (kind === "partner_mint") await trx`set local role edge_partner_minter`;
    else await trx`set local role edge_system`;
    await trx`set local statement_timeout = '10s'`;
    await trx`set local lock_timeout = '5s'`;
    if (txTimeoutSupported) await trx`set local transaction_timeout = '12s'`;
    if (bind.run) await bind.run(trx);
    // A delegate acts as the owner it just bound: from here on the transaction is edge_actor's (the binding stays: it is keyed on the
    // backend and the transaction, not on the role).
    if (kind === "delegate") await trx`set local role edge_actor`;
    if (kind === "partner") {
      // The post-bind assertion of design 4.2 (R2-L3): the transaction runs as edge_partner (so no edge_actor privilege exists in it), the role is neither SUPERUSER nor BYPASSRLS, and the binding reads
      // back as kind 'partner' through the one read-only helper edge_partner may execute. It deliberately does NOT call private.actor_uid(): that function is edge_actor's alone (0030:568), and
      // "the user lane sees no actor" is enforced where it can be, inside private.bind_partner_session, which checks from the row it just wrote that actor_uid() is NULL and the kind is 'partner'.
      // The role is checked FIRST, in a statement of its own: under any other role `private.partner_binding_kind()` is not even executable, and the refusal must name the role, not a permission.
      const check = await trx`
        select current_user::text as u,
               (select r.rolsuper or r.rolbypassrls from pg_catalog.pg_roles r where r.rolname = current_user) as privileged`;
      const c = check[0];
      if (c?.u !== role) throw new Error(`openScopedTx: expected current_user = '${role}' after SET LOCAL ROLE, got '${c?.u}'`);
      if (c?.privileged !== false) throw new Error(`openScopedTx: role '${role}' is SUPERUSER or BYPASSRLS — refusing to run`);
      const bound = await trx`select private.partner_binding_kind() as kind`;
      if (bound[0]?.kind !== "partner") throw new Error(`openScopedTx: the partner binding kind is '${bound[0]?.kind ?? null}', expected 'partner' — refusing to run`);
    } else if (kind !== "system" && kind !== "signin_mint" && kind !== "partner_mint") {
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
  // Its own short transaction, as edge_actor, through `private.hit_actor_rate_limit`, which builds the `<uid>:<key>` bucket IN THE DATABASE
  // from the bound actor (so the Edge code cannot reach another user's bucket, nor the global one). The increment commits on its own,
  // before any request transaction opens; `private.hit_actor_rate_limit` never raises over the cap (0020), so the decision is made here
  // from the returned count. The database bounds the key (<= 128 chars), the window (1 s .. 1 day) and the max (1 .. 1,000,000), raising 22023.
  const count = await openScopedTx("actor", userBind(actor.uid), async (rateTrx) => {
    const rows = await rateTrx`select private.hit_actor_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}::int) as count`;
    return Number(rows[0]?.count ?? 0);
  });
  if (count > max) return { ok: false, count, retryAfterSeconds: windowSeconds };
  return { ok: true, count };
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
  // PA-11 (partner design 4.2, N5): a PARTNER session token (`gr_ps_`) or an invite token (`gr_inv_`) is never an identity of the player lane, and it must never be sent to a third party: it is refused HERE, before
  // the environment is read and before any client exists, so no request to GoTrue is ever made with it. (Case-insensitively: a mangled partner token is still not a Supabase JWT.)
  const lowered = token.toLowerCase();
  if (lowered.startsWith("gr_ps_") || lowered.startsWith("gr_inv_")) return null;

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) return null;

  const client = createClient(url, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data, error } = await client.auth.getUser(token);
  if (error || !data?.user) return null;
  // 0051: THE one choke point every authenticated Edge Function passes through, so the app-review account's gate lives here. For an ordinary account the gate
  // answers `not_review` and writes nothing; for the review account it writes ONE audit row per GoTrue session (first request under each new session id, with the
  // refusal outcome too) and answers `disabled` outside a submission window, which is a 403 and never reaches a handler. The database refuses to bind the account
  // outside a window as well (private.bind_actor_internal), so a path that skipped this call still fails closed.
  const verdict = await reviewAccountGate(data.user.id, sessionIdOfAccessToken(token));
  if (verdict === "disabled") throw new HttpError(403, REVIEW_ACCOUNT_DISABLED_CODE, "this account is not enabled right now");
  return { uid: data.user.id, role: "authenticated" };
}

/** The 403 code a disabled review account receives (0051). Stable: the mobile app and the runbook name it. */
export const REVIEW_ACCOUNT_DISABLED_CODE = "review_account_disabled";

/**
 * 0051: asks the database whether `uid` is the App Store review account and whether a submission window is open, recording the session's audit row on the way
 * (`private.review_account_gate`: one row per (account, GoTrue session, outcome), committed WITH a refusal because the function returns a status and never raises
 * over the outcome, the 0020 lesson). Its own short transaction as `edge_system` (the only role holding EXECUTE), run BEFORE any request transaction opens, so it
 * never holds a second pooled connection from inside one (the hitRateLimitForActor ordering rule). `sessionId` is the `session_id` claim of the already-verified
 * token; the database canonicalises it or treats anything else as an unknown session.
 */
async function reviewAccountGate(uid: string, sessionId: string | null): Promise<"not_review" | "allowed" | "disabled"> {
  // The overhead of the gate is one short `edge_system` transaction (about eight statements: begin, role, three timeouts, the role check, the call, commit), which for EVERY authenticated request
  // is too much to pay to learn that the caller is an ordinary player. So the answer "not a review account" (and ONLY that answer) is remembered in this process for REVIEW_GATE_NEGATIVE_TTL_MS:
  //   - `allowed` and `disabled` are NEVER cached: the review account is asked on every request (a window's end is exact, and every session is audited);
  //   - what a stale `not_review` can do is bounded: it only matters for an account that BECAME the review account less than the TTL ago (provisioning marks a fresh, banned account, which has
  //     made no request, so this is the --adopt corner only) and it costs at most that account's first-session audit row; the database backstop (private.bind_actor_internal) does not read this cache
  //     and refuses the account outside a window regardless;
  //   - a cached entry never outlives the process, and the map is bounded (cleared when full).
  const now = reviewGateNow();
  const cachedUntil = reviewGateNegativeCache.get(uid);
  if (cachedUntil !== undefined && cachedUntil > now) return "not_review";
  reviewGateDbCalls += 1;
  const verdict = await openScopedTx("system", { expectedUid: null }, async (trx) => {
    const rows = await trx`select private.review_account_gate(${uid}::uuid, ${sessionId}::text) as verdict`;
    return rows[0]?.verdict;
  });
  // anything but the three known answers fails CLOSED (an unexpected value must never read as "fine")
  if (verdict === "not_review" || verdict === "allowed") {
    if (verdict === "not_review") {
      if (reviewGateNegativeCache.size >= REVIEW_GATE_NEGATIVE_MAX) reviewGateNegativeCache.clear();
      reviewGateNegativeCache.set(uid, now + REVIEW_GATE_NEGATIVE_TTL_MS);
    }
    return verdict;
  }
  return "disabled";
}

const REVIEW_GATE_NEGATIVE_TTL_MS = 30_000;
const REVIEW_GATE_NEGATIVE_MAX = 5_000;
const reviewGateNegativeCache = new Map<string, number>();
let reviewGateDbCalls = 0;
let reviewGateNow: () => number = () => Date.now();

/** Test hooks (the integration suite measures the gate's overhead with and without the negative cache, and starts every case from an empty one). */
export function resetReviewGateCacheForTests(): void {
  reviewGateNegativeCache.clear();
}
export function reviewGateDbCallsForTests(): number {
  return reviewGateDbCalls;
}
/** Test hook: the clock the negative cache reads (null restores the real one), so a test can prove the TTL without sleeping 30 seconds. */
export function setReviewGateClockForTests(now: (() => number) | null): void {
  reviewGateNow = now ?? (() => Date.now());
}

// THE SERVICE-ROLE KEY: the two places it is still read (the lint's privileged-file pass allows exactly these two functions, and nothing else).
//   1. `adminClient` (below): a supabase-js client keyed with it, used ONLY for GoTrue admin calls that have no database form: today,
//      `auth.admin.deleteUser` (`deleteAuthUser`). It is never handed to a caller and never reaches Postgres: every database statement in this file
//      runs as edge_actor / edge_system through the edge pool. Supabase injects the key into every function's environment whether or not the code reads
//      it, so reading it here adds no exposure; removing it needs a GoTrue-side admin path that does not exist (PR5 follow-up, design doc section 10).
//   2. `isServiceRoleBearer` (below): a constant-time COMPARISON of an inbound bearer token with it, so a scheduler that holds the key (Supabase's
//      documented cron pattern) can call the system functions (`signin-revocation-drain`, `retention-purge`). It authenticates the CALLER; it opens
//      nothing, and a leaked scheduler token grants only "run an idempotent, bounded, rate-limited maintenance pass".
// `verifyOtp` is NOT a use of the key: it runs with the anon key (`supabaseEmailOtpVerifier`).
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
 * privileged-module exemption `getActorFromRequest` already relies
 * on (`tools/service-role-lint/src/lint.ts`'s `isAllowedFile` — this
 * whole file is the one construction site for a Postgres connection and
 * for the one service-role-keyed client, `adminClient`) — routed through
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
    // all — see `hitRateLimitForActor`'s own doc, above, for the
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

      // P5.1a S2a (course-QR scan): a facility has no geometry of its own, only its courses do. A fix is "inside the facility" when it is inside the polygon + 50 m of ANY of
      // its play-verified polygon courses (the same ST_DWithin and the same 50 m as `matchFix`, §4.5). Anything else is the conservative default: never a co-signal.
      async matchFacilityFix(facilityId: string, lat: number, lng: number): Promise<MatchResult> {
        const rows = await trx`
          select exists (
            select 1 from app.catalog_course c
            where c.facility_id = ${facilityId}
              and c.verification_status = 'play-verified'
              and c.geometry_kind = 'polygon'
              and c.boundary is not null
              and ST_DWithin(c.boundary::geography, ST_SetSRID(ST_MakePoint(${lng}, ${lat}), 4326)::geography, 50)
          ) as inside`;
        return rows[0]?.inside === true
          ? { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true }
          : { verificationTier: "unverified", geometryKind: "radius", insideBuffer: false };
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

      // Edge role PR3: the drain's re-read of the raw submission AS THE ROW'S OWNER (see types.ts). Guarded by status so a row a
      // concurrent drain already resolved reads as "gone", never as a stale submission to re-run.
      async readQueuedInput(id: string): Promise<{ queuedInput: unknown } | null> {
        // PR3 gate P1 (edge role PR4b): this is the FIRST statement of the drain's per-row transaction, and it LOCKS the evidence row
        // (`for update skip locked`) until that transaction ends. Without the lock, two concurrent drains that both listed the row each read
        // `queued_input` (the row is still `queued_catalog` in both snapshots) and BOTH re-derive it: the facility/course resolution, the
        // matcher and the play re-score run twice, and only the final status UPDATE (guarded by `status = 'queued_catalog'`) serialises them.
        // With it, the second drain finds the row locked and gets NO row back, which the drain reads as "gone" (handled by someone else:
        // counted in `scanned` only), so it skips the row instead of re-deriving it.
        // SKIP LOCKED, not NOWAIT: NOWAIT raises 55P03 (a 503 through mapPgTimeoutError) and the drain would count the row as errored and,
        // for an aged row, try to age it out; SKIP LOCKED is the answer this call already has for "not yours to work on any more". It
        // does not wait either, so a drain never sits behind another for the 5 s lock_timeout. A row the first drain COMMITTED while the
        // second was waiting its turn fails the `status = 'queued_catalog'` re-check (READ COMMITTED re-evaluates a locked row's new version),
        // so it is also "gone". The lock needs UPDATE on the table, which edge_actor holds on this table's columns (0031); no grant was added.
        const rows = await trx`select queued_input from app.evidence where id = ${id} and user_id = ${uid} and status = 'queued_catalog' for update skip locked`;
        const r = rows[0];
        return r ? { queuedInput: r.queued_input } : null;
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
    rewards: buildRewardsRepo(trx, uid),

    // App Attest key registration (follow-up F2) — implemented in the delimited "App Attest key
    // registration" section at the END of this file (one seam here).
    attestKey: buildAttestKeyRepo(trx, uid),

    // O12: the sign-in-methods repository — implemented in the delimited "O12 sign-in" section at the END of this file (one
    // seam here, everything else appended below).
    signin: buildSigninRepo(trx, uid),

    // P4.2b-3a: the offline staff code (migration 0045) — implemented in the delimited "Offline staff code" section at the END of this file (one seam here).
    offlineCode: buildOfflineCodeRepo(trx),
    markerScan: buildMarkerScanRepo(trx),

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
          insert into app.device (id, user_id, platform) values (${id}, ${uid}, ${platform})
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
      async claimPlatform(deviceId: string, platform: "ios" | "android"): Promise<"ios" | "android" | null> {
        // 0042: a device first seen by an endpoint that carries no platform has platform NULL (unknown). The first platform-bearing use sets it
        // (first wins) through the definer; the platform now on record comes back, so the caller can refuse a mismatch. edge_actor holds no UPDATE
        // on the column itself. The definer answers NULL (it does not raise) for a device that is not the actor's own, because an error raised
        // here would abort the request's transaction.
        const rows = await trx`select private.claim_device_platform_for_actor(${deviceId}::uuid, ${platform}) as platform`;
        const p = rows[0]?.platform;
        return p === "ios" || p === "android" ? p : null;
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

      async findByChallenge(challengeId: string): Promise<IssuedCheckinTokenRow | null> {
        // Actor-scoped read of the one token (UNIQUE(challenge_id), 0019) a consumed challenge produced; `checkin-token` uses it to answer a
        // repeat redemption with the ORIGINAL token. edge_actor's own-row SELECT policy on app.checkin_token (0031) is all this needs.
        const rows = await trx`
          select jti, expires_at, attestation_grade, consumed_at from app.checkin_token
          where challenge_id = ${challengeId} and user_id = ${uid}`;
        const r = rows[0];
        if (!r) return null;
        return { jti: r.jti, expiresAt: r.expires_at.toISOString(), attestationGrade: r.attestation_grade, consumedAt: r.consumed_at ? r.consumed_at.toISOString() : null };
      },

      async hasAttestedOnDevice(deviceId: string): Promise<boolean> {
        const rows = await trx`
          select exists (
            select 1 from app.checkin_token where user_id = ${uid} and device_id = ${deviceId} and attestation_grade = 'attested'::app.attestation_grade
          ) as attested`;
        return Boolean(rows[0]?.attested);
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

      /** The read-only twin of `consumeForFix` (same predicates, no UPDATE): see `Repo#checkinToken.peekForFix`. */
      async peekForFix(jti: string, submittingDeviceId: string, capturedAtMs: number): Promise<ConsumedCheckinToken | null> {
        const capturedAt = new Date(capturedAtMs);
        const rows = await trx`
          select checkin_token.facility_id, checkin_token.attestation_grade, checkin_token.challenge_kind
          from app.checkin_token
          join app.checkin_challenge cc on checkin_token.challenge_id = cc.id
          where checkin_token.jti = ${jti}
            and checkin_token.user_id = ${uid}
            and checkin_token.device_id = ${submittingDeviceId}
            and checkin_token.consumed_at is null
            and checkin_token.expires_at > now()
            and cc.issued_at <= ${capturedAt}
            and ${capturedAt} <= cc.expires_at`;
        const r = rows[0];
        if (!r) return null;
        return { facilityId: r.facility_id, attestationGrade: r.attestation_grade, challengeKind: r.challenge_kind };
      },
    },

    // P3d: DELETE /v1/me, GET /v1/me/export. Both DB functions this
    // namespace calls are the ones the docstrings on Repo#me point at
    // (0015's private.delete_my_data, 0021's private.export_my_data) —
    // this Repo layer never reimplements their logic, only invokes them
    // through the `_for_actor` definers (the bound actor, no uid argument).
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
        // P3f: a held (or approved-unredeemed) offer code is RESERVING offer budget; deleting the account deletes the code, so the
        // reservation is handed back FIRST, in this same transaction (0027's own header). edge_actor can call neither
        // `app.release_account_reservations` nor `private.delete_my_data`, and does not need to: `private.delete_my_data_for_actor()`
        // deletes the BOUND actor (no uid argument) and releases the account's reservations itself, first, in the same call.
        const rows = await trx`select private.delete_my_data_for_actor() as result`;
        const result = rows[0]?.result as { user_id?: string; deleted_at?: string } | undefined;
        if (!result || typeof result.user_id !== "string" || typeof result.deleted_at !== "string") {
          throw new Error("me.deleteMyData: private.delete_my_data returned an unexpected shape");
        }
        return { userId: result.user_id, deletedAt: result.deleted_at };
      },
      async exportMyData() {
        const rows = await trx`select private.export_my_data_for_actor() as result`;
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
// LOCAL calls in this file, e.g. "set local role edge_actor", are all
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
  // `pg_settings`, not `current_setting(...)`: the lint's privileged-file pass bans that call in TypeScript (identity never rides a GUC).
  const rows = await db`select setting as v from pg_catalog.pg_settings where name = 'server_version_num'`;
  _supportsTransactionTimeout = Number(rows[0]?.v ?? 0) >= 170000;
  return _supportsTransactionTimeout;
}

/**
 * The ONLY sanctioned way an Edge Function opens a per-user database
 * transaction (build plan §4.7.1a): one transaction as `edge_actor`, bound
 * to `actor.uid` (edge role design, docs/security/edge-role-design.md).
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
  // The whole `op(repo)` is ONE transaction as edge_actor, bound to `actor.uid` (`openScopedTx`: the role, the three timeouts, the bind and
  // the post-bind assertions run before `op` does). Every error maps through `mapPgTimeoutError`.
  try {
    return await openScopedTx("actor", userBind(actor.uid), (trx) => op(buildRepo(trx, actor)));
  } catch (err) {
    throw mapPgTimeoutError(err);
  }
}

/**
 * Edge role PR3: the system path's per-row USER transaction — the drain (`queued_catalog`) and the re-score backlog act on one user's rows
 * on the user's behalf, with no JWT. In `edge` mode this is NOT `withOwnership`: the transaction starts as `edge_system`, binds the row's
 * owner through the delegate binder named by `delegate` (`private.bind_delegate_for_queued_evidence` / `bind_delegate_for_rescore`, each
 * valid only while the row's own precondition holds: the evidence is still `queued_catalog`; the backlog row is open and the play is at
 * its course), then switches to `edge_actor`, so FORCE RLS scopes every statement to that one user exactly as for a signed-in request.
 * `actor.uid` is the owner the caller EXPECTS (the system list's `user_id`); the database's answer is compared with it before `op` runs.
 * A delegate-bound transaction cannot be re-bound, and cannot delete or export the account, activate a reward, or touch sign-in state
 * (those definers require a `kind = 'user'` binding): it can do the ordinary per-user Repo work the drain needs and nothing wider.
 */
export async function withDelegatedActor<T>(delegate: DelegateRef, actor: Actor, op: Op<T>): Promise<T> {
  try {
    return await openScopedTx("delegate", delegateBind(delegate, actor.uid), (trx) => op(buildRepo(trx, actor)));
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
  // The per-item savepoint isolation, inside one edge_actor transaction. A per-item statement/lock timeout is mapped to the same 503 shape
  // `withOwnership`'s own outer catch produces, so evidence-batch/index.ts's per-item error surfacing (which reads `HttpError#code` /
  // `#message` off whatever lands in `error`) reports it as `service_unavailable`, not a raw, unmapped Postgres error.
  try {
    return await openScopedTx("actor", userBind(actor.uid), async (trx) => {
      const out: Array<{ ok: true; value: T } | { ok: false; error: unknown }> = [];
      for (let i = 0; i < itemCount; i++) {
        try {
          // `.savepoint`'s generic is a SEPARATE one from this function's own `T`, and TS cannot prove the unwrap is `T` for every possible
          // instantiation; every caller passes a plain (non-array, non-nested-Promise) value through `perItem`, so the cast is sound.
          const value = (await trx.savepoint(async (sp: TxSql) => perItem(buildRepo(sp, actor), i))) as T;
          out.push({ ok: true, value });
        } catch (err) {
          out.push({ ok: false, error: mapPgTimeoutError(err) });
        }
      }
      return out;
    });
  } catch (err) {
    // A timeout OUTSIDE any per-item savepoint (e.g. during the initial SET LOCAL / bind statements themselves) fails the whole batch the
    // same way any other such failure already does, mapped here too for consistency.
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

/** The importer repo's transaction: `openScopedTx("system")` (`SET LOCAL ROLE edge_system`, the same three timeouts and role assertion as
 * every other transaction in this file).
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
 * Reuses `openScopedTx`'s own two pieces instead of re-deriving them:
 * `supportsTransactionTimeout()` (cached PG-version feature probe, so
 * this function no longer needs its own "is this GUC recognized" guess)
 * and `mapPgTimeoutError()` (now maps CONNECTION_CLOSED -> 503 for this
 * function's own callers too, not just `withOwnership`'s). */
export async function withSystemCatalogImport<T>(op: (repo: ImporterRepo) => Promise<T>): Promise<T> {
  // The importer repo runs as `edge_system` through the edge pool. Every statement stays inside edge_system's column grants and policies
  // (0031); what edge_system cannot read (evidence, plays) goes through the list / purge definers (see buildImporterRepo).
  try {
    return await openScopedTx("system", { expectedUid: null }, (trx) => op(buildImporterRepo(trx)));
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
        // edge_system has no privilege on app.evidence: the work runs inside `private.purge_fix_coords` (0030/0032) as `private_definer`,
        // which can only remove the `fixCoords` key from rows that still carry it, with the retention pinned to 7..30 days and the limit to
        // 1..10000 (a violation raises 22023). The importer and the retention purge pass 30 days and 5000.
        // The retention schedule's own try-lock (`retention:fix_coords`): while `retention-purge` is purging this class, the import's pass skips it
        // (0 rows) instead of running a second purge over the same rows. A skipped pass loses nothing: the other run is doing exactly this work.
        if (!(await tryRetentionStepLock(trx, "fix_coords"))) return 0;
        const purged = await trx`select private.purge_fix_coords(${retentionDays}::int, ${limit}::int) as n`;
        return Number(purged[0]?.n ?? 0);
      },
      async purgeInstallLinkTombstones(maxRows: number): Promise<number> {
        // F19 retention (owner decision 2026-10-02): the 24 months are `private.purge_install_link_tombstones`'s own.
        // edge_system holds EXECUTE (service_role does too, which nothing in this runtime uses any more).
        // The same try-lock as the retention schedule's `install_link_tombstones` step (see purgeFixCoords above).
        if (!(await tryRetentionStepLock(trx, "install_link_tombstones"))) return 0;
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
        // edge_system has no privilege on app.play: `private.list_rescore_plays` (0030) is the same keyset page, readable only for a course
        // that has an OPEN backlog row, capped at 500 rows (the orchestrator never asks for more: MAX_RESCORE_PAGE). The cursor stays text end
        // to end and is cast to timestamptz in SQL, so the keyset keeps its microseconds.
        const listed = await trx`
          select play_id, user_id, facility_id, course_id, play_date, created_at_text
          from private.list_rescore_plays(${courseId}, ${afterAt}::text::timestamptz, ${afterId}::uuid, ${limit}::int)`;
        return listed.map((r) => ({
          playId: r.play_id as string, userId: r.user_id as string, facilityId: r.facility_id as string, courseId: r.course_id as string,
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
        // The raw submission (`queued_input`) is NOT listed. The drain reads it as the row's owner, inside the per-row transaction
        // (`Repo#evidence.readQueuedInput`), so raw coordinates leave the owner's transaction only to the owner. edge_system has no privilege on
        // app.evidence; `private.list_queued_catalog` returns exactly these columns, capped at 500 rows.
        const rows = await trx`select id, user_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, created_at from private.list_queued_catalog(${limit}::int)`;
        return rows.map((r) => ({
          id: r.id,
          userId: r.user_id,
          claimedFacilityId: r.claimed_facility_id,
          claimedCourseId: r.claimed_course_id,
          claimedCatalogVersion: r.claimed_catalog_version,
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
  // As edge_system through `private.hit_system_rate_limit`, which stores the bucket as `system:<key>`.
  const count = await openScopedTx("system", { expectedUid: null }, async (rateTrx) => {
    const rows = await rateTrx`select private.hit_system_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}::int) as count`;
    return Number(rows[0]?.count ?? 0);
  });
  if (count > max) return { ok: false, count, retryAfterSeconds: windowSeconds };
  return { ok: true, count };
}

/**
 * Edge role PR4b (E5, launch-blocking): the INDEPENDENT retention schedule. Before this, the fix-coordinate purge and the install-link tombstone
 * purge ran only inside a catalog import's drain pass, and the sign-in proof / revocation-queue purges only inside `signin-revocation-drain`, so a
 * quiet catalog (or an unscheduled drain) stopped retention. `retention-purge` runs the four promised classes (and, since 0040, the two hygiene classes), as `edge_system`, on its own schedule.
 * Edge role PR4c (0040) adds the two TTL hygiene purges that nothing ran, and bounds the two sign-in purges that were single DELETEs.
 *
 * Each step is a bounded, row-narrow definer that edge_system holds EXECUTE on (0040's owner-approved grant is on exactly the last two):
 *   fix_coords               `private.purge_fix_coords(30, 5000)`           removes only the `fixCoords` key from evidence rows, retention pinned to 7..30 days
 *   install_link_tombstones  `private.purge_install_link_tombstones(5000)`  24 months, the function's own constant; the policies repeat the cutoff
 *   signin_email_proofs      `private.purge_signin_email_proofs()`          proofs an hour past expiry, 5000 per call (the definer's own bound, 0040)
 *   signin_revocation_queue  `private.purge_signin_revocation_queue(30 d)`  finished (revoked / expired) rows older than 30 days, 5000 per call; never a pending one
 *   consumed_nonce           `private.purge_consumed_nonce()`               nonce tombstones 7 days past their source expiry, 5000 per call (the policy repeats the floor)
 *   rate_limit_buckets       `private.purge_rate_limit_buckets()`           windows older than 2 days (the kept `<uid>:me-delete:user` bucket included), 5000 per call
 * and, since 0054 (partner design 9, S1.5), the six partner classes, each the same shape (a constant LIMIT 5000 inside the definer, the floor repeated in its policy, EXECUTE for edge_system):
 *   partner_challenges       `private.purge_partner_challenges()`           used sign-in / reauth nonces an hour past use
 *   partner_sessions         `private.purge_partner_sessions()`             sessions 30 days past their expiry or revocation
 *   partner_credentials      `private.purge_partner_credentials()`          credentials revoked more than 180 days ago
 *   partner_invites          `private.purge_partner_invites()`              invites 90 days past their acceptance, revocation or expiry
 *   partner_enrolment_tokens `private.purge_partner_enrolment_tokens()`     enrolment tokens 90 days past their consumption, revocation or expiry
 *   partner_sign_in_failures `private.purge_partner_sign_in_failures()`     failure counters a day idle
 * The 72-hour EXPIRY of a pending queue row (which wipes its credential material) is NOT a purge and is not separate: it runs inside
 * `private.claim_signin_revocations`, i.e. inside `signin-revocation-drain`, whose schedule is therefore also a retention dependency.
 *
 * Every batch is its own short edge_system transaction that first takes a `pg_try_advisory_xact_lock` on its step: a concurrent run skips
 * (returns null) instead of waiting or deadlocking on the same rows, and two runs never double-count a batch. Safe to run concurrently, idempotent, bounded.
 * The catalog import's own pass over the same two purges (fix_coords, install_link_tombstones) takes the SAME try-lock (`tryRetentionStepLock`).
 */
const RETENTION_FIX_COORDS_DAYS = 30;
const RETENTION_SIGNIN_QUEUE_DAYS = 30;
const RETENTION_BATCH_ROWS = 5000;
/** The rows per call the four SQL-bounded purges remove (0040: a constant inside each definer, not a parameter). `RETENTION_BATCH_ROWS` above is the
 * default for the two purges that take a limit; both are 5000, and a test proves a full batch of each kind is exactly that many rows. */
export const RETENTION_DEFINER_BATCH_ROWS = 5000;

/** The advisory-lock key a step's batch try-locks (namespace 6). Exported so a test can hold a step's lock from another session and prove a concurrent run skips it. */
export function retentionStepLockKeys(name: RetentionStep["name"]): [number, number] {
  return advisoryLockKeys(6, `retention:${name}`);
}

/** Take a retention step's try-lock for the rest of THIS transaction. `false` = another run (the retention schedule, or the import's drain pass) is
 * doing that step's work right now: skip it, never wait. Shared by the retention steps and by the import's own purge calls so the two cannot overlap. */
async function tryRetentionStepLock(trx: TxSql, name: RetentionStep["name"]): Promise<boolean> {
  const [k1, k2] = retentionStepLockKeys(name);
  const got = await trx`select pg_try_advisory_xact_lock(${k1}, ${k2}) as got`;
  return got[0]?.got === true;
}

/** `batchRows` is the rows per batch for the two purges that take a limit (default 5000, the definers' own bound is 10000 / 100000). Only a test passes it, to
 * make "bounded per run" provable with a handful of rows instead of 50 000. The four other steps' bound is inside their definers (5000). */
export function retentionPurgeSteps(batchRows: number = RETENTION_BATCH_ROWS): RetentionStep[] {
  const step = (name: RetentionStep["name"], batchLimit: number | null, run: (trx: TxSql) => Promise<number>): RetentionStep => ({
    name,
    batchLimit,
    runBatch: () =>
      openScopedTx("system", { expectedUid: null }, async (trx): Promise<number | null> => {
        if (!(await tryRetentionStepLock(trx, name))) return null;
        return run(trx);
      }).catch((err) => {
        throw mapPgTimeoutError(err);
      }),
  });
  const n = (rows: ReadonlyArray<Record<string, unknown>>) => Number(rows[0]?.n ?? 0);
  const fixed = RETENTION_DEFINER_BATCH_ROWS;
  return [
    step("fix_coords", batchRows, async (trx) => n(await trx`select private.purge_fix_coords(${RETENTION_FIX_COORDS_DAYS}::int, ${batchRows}::int) as n`)),
    step("install_link_tombstones", batchRows, async (trx) => n(await trx`select private.purge_install_link_tombstones(${batchRows}::int) as n`)),
    step("signin_email_proofs", fixed, async (trx) => n(await trx`select private.purge_signin_email_proofs() as n`)),
    step("signin_revocation_queue", fixed, async (trx) => n(await trx`select private.purge_signin_revocation_queue(make_interval(days => ${RETENTION_SIGNIN_QUEUE_DAYS}::int)) as n`)),
    // 0040 (owner decision 2026-10-02): the two TTL hygiene purges. service_role-only until then; edge_system holds EXECUTE on exactly these two.
    step("consumed_nonce", fixed, async (trx) => n(await trx`select private.purge_consumed_nonce() as n`)),
    step("rate_limit_buckets", fixed, async (trx) => n(await trx`select private.purge_rate_limit_buckets() as n`)),
    // 0054 (partner design 9): the six partner purges, each bounded inside its definer
    step("partner_challenges", fixed, async (trx) => n(await trx`select private.purge_partner_challenges() as n`)),
    step("partner_sessions", fixed, async (trx) => n(await trx`select private.purge_partner_sessions() as n`)),
    step("partner_credentials", fixed, async (trx) => n(await trx`select private.purge_partner_credentials() as n`)),
    step("partner_invites", fixed, async (trx) => n(await trx`select private.purge_partner_invites() as n`)),
    step("partner_enrolment_tokens", fixed, async (trx) => n(await trx`select private.purge_partner_enrolment_tokens() as n`)),
    step("partner_sign_in_failures", fixed, async (trx) => n(await trx`select private.purge_partner_sign_in_failures() as n`)),
  ];
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

function buildRewardsRepo(trx: TxSql, uid: string): RewardsRepo {
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
      // edge_actor holds no UPDATE on offer_code / entitlement, and `SELECT ... FOR UPDATE` needs one. The lock is taken by
      // `private.lock_own_reward_for_actor(id)` instead (0033): a definer that does the same `FOR UPDATE` on the BOUND actor's row, and a row
      // lock lasts until the TRANSACTION ends whoever took it, so concurrent activations of one reward are serialised. (Dropping the lock
      // altogether, on the argument that `private.activate_*_for_actor` lock the row themselves, was tried and refuted by the integration
      // suite: the handler DECIDES from the state it reads here, BEFORE those functions lock, so a racing second request could turn an
      // already-issued code into held_review.)
      await trx`select private.lock_own_reward_for_actor(${id}::uuid)`;
      const codes = await trx`
        select oc.id, oc.state, oc.activated_device_id, oc.expires_at, oc.expiry_paused_at,
               (oc.rests_on_unattestable and oc.review_cleared_at is null) as rests_on_unattestable,
               coalesce(p.held_review, false) as play_held
        from app.offer_code oc
        left join app.play p on p.id = oc.play_id and p.user_id = oc.user_id
        where oc.id = ${id} and oc.user_id = ${uid}`;
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
      const ents = await trx`
        select e.id, e.state, e.activated_device_id,
               (e.rests_on_unattestable and e.review_cleared_at is null) as rests_on_unattestable,
               coalesce(p.held_review, false) as play_held
        from app.entitlement e
        left join app.play p on p.id = e.play_id and p.user_id = e.user_id
        where e.id = ${id} and e.user_id = ${uid}`;
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
        platform: (r.platform ?? null) as "ios" | "android" | null,
        attestKeyId: r.attest_key_id ?? null,
        // bigint arrives as a string from postgres.js.
        attestCounter: Number(r.attest_counter),
        attestPublicKey: r.attest_public_key ? new Uint8Array(r.attest_public_key) : null,
      };
    },

    async advanceAttestCounter(deviceId: string, keyId: string, counter: number): Promise<boolean> {
      // One atomic, monotonic statement: a replayed or racing counter updates 0
      // rows, whichever of two concurrent requests lost.
      // `attest_key_id = keyId` binds the advance to the key the assertion was VERIFIED against. `deviceAttestState`
      // reads the row without a lock, so a key replacement (app.register_attest_key: new key, counter reset to 0)
      // can commit between that read and this UPDATE; under READ COMMITTED the UPDATE then re-evaluates against the
      // NEW row. Without this predicate the retired key's counter (41) would be written onto the new key (its next
      // 41 assertions would then fail as replays) and the activation would be graded `attested` on a retired key.
      // With it, the replaced row no longer matches: 0 rows, and the handler fails closed. (edge_actor already holds SELECT on
      // app.device, which a WHERE on attest_key_id needs.)
      const rows = await trx`
        update app.device set attest_counter = ${counter}, last_seen = now()
        where id = ${deviceId} and user_id = ${uid} and attest_key_id = ${keyId} and attest_counter < ${counter}
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

    async hasAttestedVerdictOnDevice(deviceId: string): Promise<boolean> {
      // 0043: `first_attested_at` is stamped, once and never cleared, by a trigger the first time an `attested` verdict is written to
      // `integrity_last` (recordDeviceVerdict), so a LATER `failed` / `unattestable` verdict, which overwrites `integrity_last`, does not erase
      // the evidence. `integrity_last` is also read, so a row written before 0043 (which has no stamp) still counts.
      // Own device only (user_id): another account's device is not visible and reads false.
      const rows = await trx`
        select exists (
          select 1 from app.device
          where id = ${deviceId} and user_id = ${uid}
            and (first_attested_at is not null or integrity_last ->> 'grade' = 'attested')
        ) as attested`;
      return Boolean(rows[0]?.attested);
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
        // `private.activate_*_for_actor` (PR1b) run the SAME P3f functions as private_definer for the BOUND actor: there is no user
        // argument (the uid is the binding's), edge_actor cannot call `app.activate_*`, and the SQLSTATEs (P0002 / 42501 / 55000 / 23514)
        // are the P3f ones.
        if (input.kind === "offer_code") {
          const rows = await trx`select private.activate_offer_code_for_actor(${input.rewardId}::uuid, ${input.deviceId}::uuid, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`;
          return { state: rows[0]!.state as string };
        }
        const rows = await trx`select private.activate_entitlement_for_actor(${input.rewardId}::uuid, ${input.deviceId}::uuid, ${input.tokenHash}, ${input.decision}, ${detail}::jsonb) as state`;
        return { state: rows[0]!.state as string };
      } catch (err) {
        throw rewardsStateConflict(err);
      }
    },

    async recordInstallLink(deviceId: string, installLinkHash: string): Promise<void> {
      // One SQL function (0027 5g): stamps the link on the device row (first
      // writer wins) and writes the account's pseudonymous tombstone row, which
      // survives account deletion (N4). An invoker-rights function run as edge_actor (its INSERT is held to the actor's own device and key
      // by the L5 policy); the vault key is read inside a SECURITY DEFINER function, never here.
      await trx`select app.record_install_link(${uid}, ${deviceId}, ${installLinkHash})`;
    },

    async androidInstallSignals(deviceId: string) {
      // `app.device_link_signals` counts accounts ACROSS users, which edge_actor's own-row policies would silently turn into an undercount
      // (a fail-OPEN); `private.device_link_signals_for_actor` (PR1b) is the definer that does the cross-account read for the actor's OWN device.
      const rows = await trx`
        select s.accounts_on_install, s.voided_account_used_install,
               (d.install_link_hash is not null or d.attest_key_id is not null) as linkable
        from app.device d
        cross join lateral private.device_link_signals_for_actor(d.id) s
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
 *           GR_APPLE_DEVICECHECK_PRIVATE_KEY (PKCS#8 PEM: real line breaks, or one line with a literal \n for each),
 *           GR_APPLE_DEVICECHECK_ENV ("production" | "development")
 *   Google: GR_PLAY_PACKAGE_NAME, GR_PLAY_CERT_SHA256 (comma-separated base64url),
 *           GR_PLAY_SERVICE_ACCOUNT_EMAIL, GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY (PEM) */
export function loadRewardsAttestationConfig(): RewardsAttestationConfig {
  // Trimmed exactly as the App Attest and Sign in with Apple loaders trim (a trailing newline pasted with a secret must not make `production\n`
  // read as "not configured", nor leave whitespace inside an id). The PEM itself is passed through untouched (the shared parser, ../pem.ts,
  // tolerates surrounding whitespace and a one-line `\n`-escaped form); it only has to be non-blank here, as for Sign in with Apple.
  const teamId = (Deno.env.get("GR_APPLE_TEAM_ID") ?? "").trim();
  const bundleId = (Deno.env.get("GR_APPLE_BUNDLE_ID") ?? "").trim();
  const keyId = (Deno.env.get("GR_APPLE_DEVICECHECK_KEY_ID") ?? "").trim();
  const privateKeyPem = Deno.env.get("GR_APPLE_DEVICECHECK_PRIVATE_KEY") ?? "";
  const environment = (Deno.env.get("GR_APPLE_DEVICECHECK_ENV") ?? "").trim();
  const appleComplete =
    teamId !== "" && bundleId !== "" && !/\s/.test(teamId + bundleId) && keyId !== "" && privateKeyPem.trim() !== "" && (environment === "production" || environment === "development");

  return {
    apple: appleComplete ? { teamId, bundleId, keyId, privateKeyPem, environment: environment as "production" | "development" } : null,
    google: readPlayIntegrityConfigFromEnv(),
  };
}

/** The Play Integrity half of the configuration, shared by `rewards-activate` and `checkin-token` (one reader, so the two can never disagree
 * about what "configured" means): `null` unless EVERY value is present and non-empty. */
function readPlayIntegrityConfigFromEnv(): PlayIntegrityConfig | null {
  const packageName = Deno.env.get("GR_PLAY_PACKAGE_NAME") ?? "";
  const digests = (Deno.env.get("GR_PLAY_CERT_SHA256") ?? "").split(",").map((d) => d.trim()).filter((d) => d !== "");
  const serviceAccountEmail = Deno.env.get("GR_PLAY_SERVICE_ACCOUNT_EMAIL") ?? "";
  const serviceAccountPrivateKeyPem = Deno.env.get("GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY") ?? "";
  const googleComplete = packageName !== "" && digests.length > 0 && serviceAccountEmail !== "" && serviceAccountPrivateKeyPem !== "";
  return googleComplete ? { packageName, certificateSha256Digests: digests, serviceAccountEmail, serviceAccountPrivateKeyPem } : null;
}

/** The attestation VERIFICATION configuration for `checkin-token` (build plan §4.5 G3-08, §7.5). Verification only: no DeviceCheck credential is
 * read (the check-in side reads and sets no persistent bit), so the iOS half needs just the App Attest `rpId` and the Android half is the same
 * four Play Integrity values `rewards-activate` uses. `null` for a half means UNCONFIGURED: a request carrying that platform's attestation
 * material then fails closed with a 503, and a request carrying none is graded exactly as before.
 *   iOS:     GR_APPLE_TEAM_ID, GR_APPLE_BUNDLE_ID  (appId = `<team>.<bundle>`, the App Attest rpId; no whitespace)
 *   Android: GR_PLAY_PACKAGE_NAME, GR_PLAY_CERT_SHA256, GR_PLAY_SERVICE_ACCOUNT_EMAIL, GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY */
export function loadCheckinAttestationConfig(): VerificationConfig {
  const teamId = (Deno.env.get("GR_APPLE_TEAM_ID") ?? "").trim();
  const bundleId = (Deno.env.get("GR_APPLE_BUNDLE_ID") ?? "").trim();
  const appId = teamId !== "" && bundleId !== "" && !/\s/.test(teamId + bundleId) ? `${teamId}.${bundleId}` : null;
  return { appId, google: readPlayIntegrityConfigFromEnv() };
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
  // device for this user (another user's device and a nonexistent one are the same); 22023 = a malformed key /
  // non-iOS device (the verifier makes both unreachable).
  if (code === "55000") return Errors.conflict("key_already_registered", "this key is already registered on this device");
  if (code === "23514") return Errors.conflict("key_previously_retired", "this key was retired on this device and cannot be registered again");
  // P0002 is reachable only when the device vanished (or never was this caller's) between the handler's own-device read and
  // this call. The documented no-existence-oracle answer for a foreign or nonexistent device is the SAME 422 the handler gives
  // for an unusable challenge — never a 404 "no such device", which would tell a prober which ids exist.
  if (code === "P0002") return Errors.unprocessable("challenge_not_consumable", "this challenge could not be used (already used, expired, or not issued to this device)");
  if (code === "22023") return Errors.unprocessable("attestation_rejected", "the attestation could not be verified");
  return err;
}

function buildAttestKeyRepo(trx: TxSql, uid: string): AttestKeyRepo {
  return {
    async deviceKey(deviceId: string) {
      // Ownership is part of the WHERE clause: another user's id and a nonexistent id are the same empty result.
      const rows = await trx`select platform, attest_key_id from app.device where id = ${deviceId} and user_id = ${uid}`;
      const r = rows[0];
      if (!r) return null;
      return { platform: (r.platform ?? null) as "ios" | "android" | null, keyId: (r.attest_key_id as string | null) ?? null };
    },

    async register(input: { deviceId: string; keyId: string; publicKey: Uint8Array }): Promise<"registered" | "replaced"> {
      try {
        // One SQL function (0034): validates the key against its id, locks the caller's own device row, writes the key
        // (a reinstall's replacement restarts the counter, retires the old key) and audits it.
        // edge_actor cannot call `app.register_attest_key` (it names any user); `private.register_attest_key_for_actor` (0034) runs it as
        // private_definer for the BOUND actor (no user argument).
        const rows = await trx`select private.register_attest_key_for_actor(${input.deviceId}::uuid, ${input.keyId}, ${input.publicKey}) as result`;
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
import type { ClaimedRevocation, EmailOtpResult, EmailOtpVerifier, EmailProofInput, EmailProofMinter, LinkIdentityInput, OtpFailureCounter, OtpReservation, RevocationDb, RevocationJob, SigninMethodRow, SigninRepo, SigninSystemOps } from "./signin/types.ts";

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

/** True only when the request carries the project's service-role key as its bearer token (constant-time). The system functions (the revocation
 * drain, the retention purge) are maintenance work, called by a scheduler holding that key; Supabase's gateway check alone would also admit an anon
 * key. A comparison only: the key is never used to open a connection or a client here (see "THE SERVICE-ROLE KEY" above `adminClient`). */
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
  // 0039: the proof-bound link refused (no such proof, already used, expired, issued to another caller / identity / address, the address changed
  // hands, or the minter found no GoTrue sign-in to corroborate). One answer for all of them: which one it was is in the database log, not on the wire.
  if (code === "28000" && message.startsWith("email_proof_refused")) return Errors.conflict("email_proof_refused", "that email proof cannot be used; request a new code and try again");
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

/** The system operations (queue claim / complete / purge, the KEK by id, the OTP-failure counter). The queue functions are granted to edge_system
 * (and service_role, which nothing here uses), `get_signin_token_kek` to edge_actor and edge_system, and the OTP-failure CORES to service_role only
 * (0037): edge_actor reaches the counter through the `_for_actor` wrappers, which require a bound kind = 'user' actor. WHICH transaction runs them is
 * decided by `withSigninSystem` (queue; edge_system) and `signinOtpFailuresFor` (OTP counter; the calling actor) below. */
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
    // The OTP counter, through the `_for_actor` wrappers, which refuse unless a kind = 'user' actor is bound in this transaction (0037, L1): the
    // cores are not granted to edge_actor at all, so an unbound edge_actor connection cannot call them.
    async peekOtpFailures(emailHash): Promise<number> {
      const rows = await trx`select private.peek_signin_otp_failures_for_actor(${emailHash}) as n`;
      return Number(rows[0]?.n ?? 0);
    },
    async reserveOtpAttempt(emailHash): Promise<OtpReservation> {
      const rows = await trx`select o_attempts, o_window_start from private.reserve_signin_otp_attempt_for_actor(${emailHash})`;
      const w = rows[0]?.o_window_start;
      return { attempts: Number(rows[0]?.o_attempts ?? -1), windowStart: w instanceof Date ? w.toISOString() : String(w) };
    },
    async releaseOtpAttempt(emailHash, windowStart): Promise<void> {
      await trx`select private.release_signin_otp_attempt_for_actor(${emailHash}, ${windowStart}::timestamptz) as n`;
    },
    // 0039: granted to edge_system (and service_role); it acts on no account.
    async purgeEmailProofs(): Promise<number> {
      const rows = await trx`select private.purge_signin_email_proofs() as n`;
      return Number(rows[0]?.n ?? 0);
    },
  };
}

/** Per-user operations: the `_for_actor` wrappers (edge_actor, no uid argument: the bound actor of this transaction; a wrong uid cannot even be
 * expressed). The one operation with no direct form is linking an identity to ANOTHER account (the OTP-proven link). A definer that took the target as
 * an argument would be an "attach an identity to any account" primitive, so the target is the PROOF's (0039): the handler mints a single-use proof
 * after the OTP verifies (`signinEmailProofs`, edge_system, in its own transaction) and `linkIdentityWithProof` redeems it as the bound caller;
 * `linkIdentity` / `storeToken` refuse any account but the caller's (`mustBeSelf`). docs/security/edge-role-design.md §12. */
function buildSigninRepo(trx: TxSql, uid: string): SigninRepo {
  const guard = async <T>(op: () => Promise<T>): Promise<T> => {
    try {
      return await op();
    } catch (e) {
      throw signinDbError(e);
    }
  };
  const kekRows = async (kekId: string | null) =>
    (await trx`select o_kek_id, o_kek_b64 from private.get_signin_token_kek(${kekId}::text)`) as unknown as { o_kek_id: string; o_kek_b64: string }[];
  // The DIRECT path (a uid argument) never names another account: that is the proof-bound path's job. A handler that reaches this with a foreign
  // uid is a bug, and the answer is a refusal, not a link.
  const mustBeSelf = (target: string) => {
    if (target.toLowerCase() !== uid.toLowerCase()) throw new HttpError(403, "cross_account_link_requires_proof", "an identity is linked to another account only through a verified email proof");
  };
  return {
    listMethods: () =>
      guard(async () => {
        const rows = await trx`select o_provider, o_subject, o_email, o_is_private_relay, o_linked_at, o_has_token from private.signin_methods_for_actor()`;
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
        const rows = await trx`select private.signin_find_account_by_email_for_actor(${email}) as id`;
        return (rows[0]?.id as string | null | undefined) ?? null;
      }),

    linkIdentity: (targetUserId: string, input: LinkIdentityInput) =>
      guard(async () => {
        if (!SIGNIN_UUID_RE.test(targetUserId)) throw Errors.internal();
        mustBeSelf(targetUserId);
        const rows = await trx`select private.signin_link_identity_for_actor(${input.provider}, ${input.subject}, ${input.email}, ${input.emailVerified}, ${input.isPrivateRelay}) as created`;
        return Boolean(rows[0]?.created);
      }),

    linkIdentityWithProof: (proofId: string, input: LinkIdentityInput, envelope) =>
      guard(async () => {
        if (!SIGNIN_UUID_RE.test(proofId)) throw Errors.internal();
        // ONE definer call: it redeems the proof under the target's advisory lock, links the identity and stores the token for the PROOF's account.
        const rows = await trx`
          select private.signin_link_identity_with_proof_for_actor(
            ${proofId}::uuid, ${input.provider}, ${input.subject}, ${input.email}, ${input.emailVerified}, ${input.isPrivateRelay},
            ${envelope.ciphertext}::bytea, ${envelope.dekWrapped}::bytea, ${envelope.kekId}) as created`;
        return Boolean(rows[0]?.created);
      }),

    storeToken: (targetUserId: string, provider, envelope) =>
      guard(async () => {
        if (!SIGNIN_UUID_RE.test(targetUserId)) throw Errors.internal();
        mustBeSelf(targetUserId);
        // Uint8Array parameters, cast to bytea: postgres.js serialises them as bytea (never as text).
        await trx`select private.signin_store_token_for_actor(${provider}, ${envelope.ciphertext}::bytea, ${envelope.dekWrapped}::bytea, ${envelope.kekId})`;
      }),

    unlinkIdentity: (provider: string) =>
      guard(async () => {
        const rows = await trx`select o_queue_id from private.signin_unlink_identity_for_actor(${provider})`;
        return rows.map((r) => r.o_queue_id as string);
      }),

    enqueueRevocations: () =>
      guard(async () => {
        const rows = await trx`select o_queue_id, o_provider from private.signin_enqueue_revocations_for_actor()`;
        return rows.map((r): RevocationJob => ({ queueId: r.o_queue_id as string, provider: r.o_provider as string }));
      }),

    currentKek: () => readKek(() => kekRows(null)),
    kekById: (kekId: string) => readKek(() => kekRows(kekId)),
    system: buildSigninSystemOps(trx),
  };
}

/** The revocation-queue operations, each call its own short transaction, as **edge_system** through `openScopedTx("system", ...)`: the role 0035
 * granted claim / complete / purge / the KEK reader to (no actor is bound; edge_system has no privilege on any PII table, check 12). The OTP-failure
 * counter is NOT here: edge_system has no grant on it, so it runs as the caller's actor (`signinOtpFailuresFor`). */
function withSigninSystem<T>(op: (sys: SigninSystemOps) => Promise<T>): Promise<T> {
  return openScopedTx("system", { expectedUid: null }, (trx) => op(buildSigninSystemOps(trx))).catch((err) => {
    throw mapPgTimeoutError(err);
  });
}

/** The revocation queue, as the runner (_shared/signin/revocation.ts) needs it. Every call is its OWN short transaction: a vendor call is
 * never made while one is open. */
export const signinRevocationDb: RevocationDb = {
  claim: (ids, limit, leaseSeconds) => withSigninSystem((s) => s.claim(ids, limit, leaseSeconds)),
  complete: (id, outcome, errorCode, backoffSeconds) => withSigninSystem((s) => s.complete(id, outcome, errorCode, backoffSeconds)),
  kekById: (kekId) => withSigninSystem((s) => s.kekById(kekId)),
  purge: (olderThanDays) => withSigninSystem((s) => s.purge(olderThanDays)),
};

/** The OTP-proof failure counter (§4.7 item 8), run AS THE CALLER (the bound edge_actor, through the `_for_actor` wrappers: nothing wider is needed). `reserve` takes the attempt atomically and commits on its own, BEFORE the proof is
 * verified, so a failed proof (or a request that dies) always counts and N parallel proofs cannot all pass a read of the count; `release`
 * gives it back only for a proof that succeeded or never produced a verdict (security gate F3). */
export function signinOtpFailuresFor(actor: Actor): OtpFailureCounter {
  return {
    peek: (emailHash) => withOwnership(actor, (repo) => repo.signin.system.peekOtpFailures(emailHash)),
    reserve: async (emailHash) => {
      const r = await withOwnership(actor, (repo) => repo.signin.system.reserveOtpAttempt(emailHash));
      return r.attempts < 0 ? null : { used: r.attempts, windowStart: r.windowStart };
    },
    // The window the attempt was reserved in, not "the current one" (0037, L2).
    release: (emailHash, windowStart) => withOwnership(actor, (repo) => repo.signin.system.releaseOtpAttempt(emailHash, windowStart)),
  };
}

/** The minter of the single-use email-OTP link proof (0039 / 0041): `private.signin_record_email_proof`, run as **edge_signin_minter** in its OWN transaction
 * (`openScopedTx("signin_mint")`, no actor bound: the definer refuses inside an actor-bound transaction), committed before the link transaction that redeems the
 * proof. It is NOT `edge_system` (0041, L1): the drain, queue, import and retention lanes run as edge_system and can no longer mint; the minter role holds
 * EXECUTE on this one function and nothing else, and the privileged lint (privileged-mint-scope) lets only this function ask for the kind. The address and
 * the subject go in RAW: the database normalises and hashes them, with the expression the redemption uses (0041, L2: one rule, in one place), and checks
 * the address against the target's own `auth.users.email`, the target's GoTrue sign-in stamp and a fresh `auth.sessions` row of that id for the target (the
 * session verifyOtp created: the one secret an injected mint cannot know). */
export function signinEmailProofs(): EmailProofMinter {
  return {
    async record(input: EmailProofInput): Promise<string> {
      if (!SIGNIN_UUID_RE.test(input.sessionId)) throw Errors.conflict("email_proof_refused", "that email proof cannot be used; request a new code and try again");
      try {
        return await openScopedTx("signin_mint", { expectedUid: null }, async (trx) => {
          const rows = await trx`
            select private.signin_record_email_proof(${input.callerUserId}::uuid, ${input.targetUserId}::uuid, ${input.email}, ${input.provider}, ${input.subject}, ${input.sessionId}::uuid) as id`;
          const id = rows[0]?.id;
          if (typeof id !== "string" || !SIGNIN_UUID_RE.test(id)) throw Errors.internal();
          return id;
        });
      } catch (e) {
        // P0002 here is "no such caller / target account" (it vanished between the lookup and the mint): the same answer as any other refusal, not
        // signinDbError's "that sign-in method is not linked".
        if ((e as { code?: unknown } | null)?.code === "P0002") throw Errors.conflict("email_proof_refused", "that email proof cannot be used; request a new code and try again");
        throw signinDbError(e);
      }
    },
  };
}

/** Deletes email-OTP link proofs an hour past their expiry (0039): system work, run by the revocation drain next to the queue purge. */
export const purgeSigninEmailProofs = (): Promise<number> => withSigninSystem((s) => s.purgeEmailProofs());

/** Proof of mailbox control by an email OTP, through Supabase Auth's verifyOtp with the ANON key (the response's session is
 * discarded: this server never hands one to a client). A wrong or expired code is `{ ok: false }`; a transport or server failure
 * THROWS, so it is not counted against the address. `[unverified — training knowledge of GoTrue's verifyOtp error statuses]`. */
export interface OtpAuthClient {
  auth: {
    verifyOtp(args: { email: string; token: string; type: "email" }): Promise<{ data: { user?: { id?: string } | null; session?: { access_token?: string } | null } | null; error: { status?: number } | null }>;
    signOut(opts: { scope: "local" }): Promise<{ error: unknown }>;
  };
}

/** The `session_id` claim of a GoTrue access token (a JWT), or null. The token is read here only for the id of the session it belongs to: it was handed to this
 * process by GoTrue over TLS in the verifyOtp response, and the DATABASE is what verifies the id (the session must exist for the target and be fresh), so the
 * signature is not checked. `[unverified — training knowledge: GoTrue puts `session_id` in every access token it issues; its own /logout identifies the
 * session by that claim]`. Anything that is not a three-part JWT with a uuid `session_id` is null (the handler then refuses to mint). */
export function sessionIdOfAccessToken(token: unknown): string | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[1] === "") return null;
  try {
    const b64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    const claims = JSON.parse(atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="))) as { session_id?: unknown };
    return typeof claims.session_id === "string" && SIGNIN_UUID_RE.test(claims.session_id) ? claims.session_id.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Builds the verifier over a client factory (the real one below; a recording fake in the integration suite). verifyOtp ESTABLISHES a live GoTrue session for the
 * proven account on the client it is called on; this server never hands it to anyone. Since 0041 the proof is BOUND to that session (the minter checks it
 * exists, for the target, fresh), so a success returns its id (`sessionId`) and a `closeSession` that signs out EXACTLY that session (scope local, on the client
 * that holds it): the caller runs it after the mint, on every path. A sign-out that fails is logged (no secret in the line) and does not fail the proof: the
 * session is in memory only and never leaves this function (security gate F5). A response with no user is a failure that still signs the session out. */
export function makeEmailOtpVerifier(newClient: () => OtpAuthClient): EmailOtpVerifier {
  return {
    async verify(email: string, code: string): Promise<EmailOtpResult> {
      const client = newClient();
      const { data, error } = await client.auth.verifyOtp({ email, token: code, type: "email" });
      if (error) {
        const status = error.status;
        if (status === 400 || status === 401 || status === 403 || status === 404 || status === 422) return { ok: false };
        throw new Error("supabase auth verifyOtp failed");
      }
      const closeSession = async (): Promise<void> => {
        try {
          const out = await client.auth.signOut({ scope: "local" });
          if (out.error) console.warn(JSON.stringify({ event: "signin_otp_session_signout_failed" }));
        } catch {
          console.warn(JSON.stringify({ event: "signin_otp_session_signout_failed" }));
        }
      };
      const id = data?.user?.id;
      if (!id) {
        await closeSession();
        throw new Error("supabase auth verifyOtp returned no user");
      }
      return { ok: true, userId: id, sessionId: sessionIdOfAccessToken(data?.session?.access_token), closeSession };
    },
  };
}

export const supabaseEmailOtpVerifier: EmailOtpVerifier = makeEmailOtpVerifier(() => {
  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) throw new Error("privileged.ts: SUPABASE_URL/SUPABASE_ANON_KEY are not set in this environment");
  return createClient(url, anonKey, { auth: { autoRefreshToken: false, persistSession: false } }) as unknown as OtpAuthClient;
});
// ==== END O12 sign-in additions ==============================================

// ============================================================================
// Offline staff code (P4.2b-3a, migration 0045): the seed is DERIVED inside Postgres under a Vault key that never leaves it
// ============================================================================
// The provisioning operation is a `_for_actor` definer (edge_actor, the bound kind = 'user' actor; no user argument), so a wrong uid cannot even be expressed.
// `private.offline_seed_derive` (the only reader of the key) has no EXECUTE for anyone, edge_actor included. The staff lane's replay record
// (`private.offline_code_record_step_for_actor`) is NOT here any more: 0047 (X9) revoked it from edge_actor, because "this user holds a staff scope" is partner
// authority, not a player-lane capability. The primitive stays in the database; S3's partner-attest calls it from a `_for_partner` definer.

/** The SQLSTATEs 0045's provisioning definer raises, as the HTTP answers a client may see. 55000 is "the derivation key is not provisioned in Vault": a 503
 * with a stable code, and no message from the database (it would only name the secret). */
function offlineCodeDbError(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  if (code === "55000") return new HttpError(503, "offline_seed_unavailable", "offline codes are not available right now");
  if (code === "42501") return Errors.forbidden("forbidden");
  return mapPgTimeoutError(err);
}

function buildOfflineCodeRepo(trx: TxSql): Repo["offlineCode"] {
  return {
    async provisionSeed(deviceId: string, rotate: boolean): Promise<OfflineSeedProvision | null> {
      let rows;
      try {
        rows = await trx`select o_seed, o_seed_version, o_issued_at from private.offline_seed_for_actor(${deviceId}::uuid, ${rotate}::boolean)`;
      } catch (e) {
        throw offlineCodeDbError(e);
      }
      const r = rows[0];
      if (!r) return null;
      return {
        seed: toBytes(r.o_seed),
        seedVersion: Number(r.o_seed_version),
        issuedAt: r.o_issued_at instanceof Date ? r.o_issued_at.toISOString() : String(r.o_issued_at),
      };
    },
  };
}

// ============================================================================
// Course QR, the player lane (P5.1a S2a, migration 0046): the scan, the PIN gate, the co-signal intake and the public-key read
// ============================================================================
// Four `_for_actor` definers (edge_actor, the bound kind = 'user' actor; no user argument), so a wrong uid cannot even be expressed. `private.course_pin_derive` (the only reader
// of the PIN pepper) has no EXECUTE for anyone, edge_actor included: nothing in this file can obtain a PIN, only learn whether one was right.

/** The SQLSTATEs 0046's definers raise, as the HTTP answers a client may see. 55000 is "the PIN pepper is not provisioned in Vault": a 503 with a stable code and no message from
 * the database. 23505 is a lost race on the (user, trail, ref) uniqueness of a printed-QR scan: the same player scanning the same shop twice at once is a duplicate (409).
 * 22023 is a bad argument the Edge parser should have caught (a deploy skew, not a client error the caller can fix); 42501 is "no actor bound", a server bug. */
function markerScanDbError(err: unknown): unknown {
  const code = (err as { code?: unknown } | null)?.code;
  if (code === "55000") return new HttpError(503, "course_pin_unavailable", "marker purchases by printed QR are not available right now");
  if (code === "23505") return Errors.conflict("duplicate_scan", "you already recorded a purchase at this facility today");
  if (code === "22023") return Errors.unprocessable("invalid_scan", "the scan could not be recorded as sent");
  return mapPgTimeoutError(err);
}

const MARKER_SCAN_REFUSALS: ReadonlySet<string> = new Set([
  "no_facility",
  "no_programme",
  "variant_disabled",
  "qr_unknown",
  "qr_wrong_facility",
  "qr_used",
  "qr_expired",
  "qr_revoked",
  "pin_wrong",
  "duplicate",
  "cosignal_invalid",
  "cosignal_used",
  "review_account",
]);

const PURCHASE_STATUSES: ReadonlySet<string> = new Set(["valid", "pending", "held_review"]);
const CREDIT_STATUSES: ReadonlySet<string> = new Set(["credited", "pending", "held_review", "void"]);

function toDateOnly(v: unknown): string {
  return v instanceof Date ? v.toISOString().slice(0, 10) : String(v);
}

// deno-lint-ignore no-explicit-any
function toPurchaseView(r: any): MarkerPurchaseView {
  if (!PURCHASE_STATUSES.has(String(r.o_purchase_status)) || !CREDIT_STATUSES.has(String(r.o_credit_status ?? "void"))) {
    throw new Error("markerScan: the database returned an unexpected purchase or credit status");
  }
  return {
    purchaseId: String(r.o_purchase_id),
    trailId: String(r.o_trail_id),
    purchaseStatus: r.o_purchase_status as MarkerPurchaseView["purchaseStatus"],
    creditId: r.o_credit_id === null || r.o_credit_id === undefined ? null : String(r.o_credit_id),
    creditStatus: (r.o_credit_status ?? "void") as MarkerPurchaseView["creditStatus"],
  };
}

function buildMarkerScanRepo(trx: TxSql): Repo["markerScan"] {
  return {
    async publicKey(kid: string, purpose: "rotating_token" | "printed_qr"): Promise<CourseQrPublicKey | null> {
      let rows;
      try {
        rows = await trx`select o_public_key_b64url, o_revoked from private.course_qr_public_key_for_actor(${kid}::text, ${purpose}::text)`;
      } catch (e) {
        throw markerScanDbError(e);
      }
      const r = rows[0];
      if (!r) return null;
      return { publicKeyB64Url: String(r.o_public_key_b64url), revoked: r.o_revoked === true };
    },

    async attemptPin(input: { facilityId: string; pin: string; at: Date }): Promise<PinAttemptResult> {
      let rows;
      try {
        rows = await trx`select o_result, o_retry_after_seconds from private.course_pin_attempt_for_actor(${input.facilityId}::text, ${input.pin}::text, ${input.at.toISOString()}::timestamptz)`;
      } catch (e) {
        throw markerScanDbError(e);
      }
      const r = rows[0];
      const result = String(r?.o_result);
      if (result === "locked") return { result: "locked", retryAfterSeconds: r?.o_retry_after_seconds === null || r?.o_retry_after_seconds === undefined ? null : Number(r.o_retry_after_seconds) };
      if (result === "ok" || result === "wrong" || result === "no_facility" || result === "no_programme") return { result, retryAfterSeconds: null };
      throw new Error("markerScan.attemptPin: private.course_pin_attempt_for_actor returned an unexpected result");
    },

    async record(input: MarkerScanRecordInput): Promise<MarkerScanRecordResult> {
      let rows;
      try {
        rows = await trx`
          select o_result, o_purchase_id, o_trail_id, o_purchase_status, o_credit_id, o_credit_status, o_local_date
          from private.marker_scan_for_actor(
            ${input.facilityId}::text, ${input.variant}::text, ${input.nonceHash}::text, ${input.qrKid}::text, ${input.pin}::text, ${input.at.toISOString()}::timestamptz,
            ${input.cosignal?.grade ?? null}::text, ${input.cosignal?.fixId ?? null}::text, ${input.cosignal?.evidenceId ?? null}::uuid)
          order by o_trail_id`;
      } catch (e) {
        throw markerScanDbError(e);
      }
      const first = rows[0];
      const status = String(first?.o_result);
      if (status !== "accepted") {
        if (!MARKER_SCAN_REFUSALS.has(status)) throw new Error("markerScan.record: private.marker_scan_for_actor returned an unexpected result");
        return { status: status as MarkerScanRefusal };
      }
      return { status: "accepted", localDate: toDateOnly(first?.o_local_date), purchases: rows.map(toPurchaseView) };
    },

    async attachCosignal(input: MarkerCosignalAttachInput): Promise<MarkerCosignalAttachResult> {
      let rows;
      try {
        rows = await trx`
          select o_result, o_purchase_id, o_trail_id, o_purchase_status, o_credit_id, o_credit_status
          from private.marker_cosignal_attach_for_actor(
            ${input.facilityId}::text, ${input.at.toISOString()}::timestamptz, ${input.cosignal.grade}::text, ${input.cosignal.fixId}::text, ${input.cosignal.evidenceId}::uuid)
          order by o_trail_id`;
      } catch (e) {
        throw markerScanDbError(e);
      }
      const first = rows[0];
      const status = String(first?.o_result);
      if (status === "no_pending_purchase" || status === "cosignal_invalid" || status === "cosignal_used" || status === "review_account") return { status };
      if (status !== "attached") throw new Error("markerScan.attachCosignal: private.marker_cosignal_attach_for_actor returned an unexpected result");
      return { status: "attached", purchases: rows.map(toPurchaseView) };
    },
  };
}

// ============================================================================
// PARTNER LANE (S1.2): docs/security/partner-auth-design.md 4.2 / 4.4 / 4.5 / 8. BEGIN
// ============================================================================
// The partner (staff) lane's two kinds of transaction, and nothing else. The handler (`_shared/partner/session-handler.ts`, pure) sees only the PORTS in `_shared/partner/ports.ts`; this section is
// where they meet the database. No `console` appears in it (PA-11; supabase/tests/unit/partner-modules.test.ts scans everything between the BEGIN and END markers, and the partner modules).
//
//   withPartnerMint(op)        ONE transaction as `edge_partner_minter` (kind "partner_mint", no binding): the stateless sign-in challenge, the relying-party read, the credential lookup, the failure counter and
//                              the mint. It COMMITS whenever `op` returns, whatever status the database answered: every refusal is a status row, so the alarm rows, the burned nonce and the failure counter commit.
//   withPartnerSession(h, op)  ONE transaction as `edge_partner` (kind "partner"): `bind_partner_session(h)`, the post-bind assertion, then `_for_partner` definers only.
//   hitRateLimitForPartner     one hit of a per-member bucket, in its OWN short transaction (committed before any request transaction opens: the rule of `hitRateLimitForActor`).
// Errors are mapped here and nowhere else: 28000 from the binder is `PartnerSessionRefused` (the ONE 401), 42501 from a definer is `PartnerAuthorityRefused` (403), 55000 (no relying-party row, no Vault
// key: the challenge key or the PIN pepper) is `PartnerNotConfigured` (a bare 503), 23505 (a unique index: a GoTrue session that already proved another proof) is `PartnerConflict`, 22023 (a malformed argument,
// e.g. acting on oneself) is `PartnerInvalidArgument` (S1.5). Anything else propagates and rolls back.
//
// S1.5 (0054, partner-invites and partner-members): the minter transaction and the bound transaction each carry MORE methods (`PartnerInviteMintTx`, `PartnerInvitesTx` / `PartnerMembersTx`), not more kinds: `withPartnerMint`
// and `withPartnerSession` stay the ONE caller of their kinds (the lint's `privileged-mint-scope` allow-list), and `partnerDb.withInviteMint` / `withInvites` / `withMembers` are those same functions typed for the
// narrower port a handler is given.

/** The SQLSTATE of a postgres.js error, or "". */
function partnerPgCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "";
}

function mapPartnerDbError(err: unknown): never {
  const code = partnerPgCode(err);
  if (code === "28000") throw new PartnerSessionRefused();
  if (code === "42501") throw new PartnerAuthorityRefused();
  if (code === "55000") throw new PartnerNotConfigured();
  if (code === "23505") throw new PartnerConflict();
  if (code === "22023") throw new PartnerInvalidArgument();
  throw err;
}

const bytesOf = (v: unknown): Uint8Array => new Uint8Array(v as ArrayLike<number>);
const isoOrNull = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : null);
const textOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);

async function readPartnerRpConfig(trx: TxSql): Promise<RpConfig> {
  const rows = await trx`select o_rp_id, o_origin from private.partner_rp_config_read()`;
  const r = rows[0];
  if (typeof r?.o_rp_id !== "string" || typeof r?.o_origin !== "string") throw new PartnerNotConfigured();
  return { rpId: r.o_rp_id, origin: r.o_origin };
}

const INVITE_ACCEPT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "locked", "email_mismatch", "email_unconfirmed", "session_stale", "existing_member_sign_in", "recover_required"]);
const ENROLMENT_ACCEPT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "locked", "email_mismatch", "email_unconfirmed", "session_stale", "existing_member_sign_in", "refused"]);

/** The register challenge an accept definer issued (only on `ok`). */
function registerChallengeOf(r: Record<string, unknown>, fn: string): ChallengeIssue {
  if (r.o_nonce === null || r.o_nonce === undefined || r.o_exp === null || r.o_exp === undefined || r.o_mac === null || r.o_mac === undefined) throw new Error(`${fn} returned ok without a challenge`);
  return { nonce: bytesOf(r.o_nonce), exp: Number(r.o_exp), mac: bytesOf(r.o_mac) };
}

/** The invite and enrolment definers of 0054 (the minter lane, unbound). Every one is a `select private.*(...)` matching the migration's argument order. */
function buildPartnerInviteMintTx(trx: TxSql): PartnerInviteMintTx {
  return {
    rpConfig: () => readPartnerRpConfig(trx),
    async inviteEmailForToken(tokenHash: string): Promise<string | null> {
      const rows = await trx`select o_email from private.partner_invite_email_for_token(${tokenHash}::text)`;
      return textOrNull(rows[0]?.o_email);
    },
    async inviteAccept(tokenHash: string, verifiedUserId: string, gotrueSessionId: string): Promise<InviteAcceptResult> {
      const rows = await trx`
        select o_status, o_user_id::text as o_user_id, o_invite_id::text as o_invite_id, o_org_id::text as o_org_id, o_role::text as o_role, o_nonce, o_exp::text as o_exp, o_mac
        from private.partner_invite_accept(${tokenHash}::text, ${verifiedUserId}::uuid, ${gotrueSessionId}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !INVITE_ACCEPT_STATUSES.has(r.o_status)) throw new Error("partner_invite_accept returned no usable status");
      if (r.o_status !== "ok") return { status: r.o_status as InviteAcceptStatus, accepted: null };
      return {
        status: "ok",
        accepted: { userId: String(r.o_user_id), inviteId: String(r.o_invite_id), orgId: String(r.o_org_id), role: String(r.o_role), challenge: registerChallengeOf(r, "partner_invite_accept") },
      };
    },
    async enrolmentEmailForToken(tokenHash: string): Promise<string | null> {
      const rows = await trx`select o_email from private.partner_enrolment_token_email_for_token(${tokenHash}::text)`;
      return textOrNull(rows[0]?.o_email);
    },
    async enrolmentAccept(tokenHash: string, verifiedUserId: string, gotrueSessionId: string): Promise<EnrolmentAcceptResult> {
      const rows = await trx`
        select o_status, o_user_id::text as o_user_id, o_token_id::text as o_token_id, o_purpose, o_nonce, o_exp::text as o_exp, o_mac
        from private.partner_enrolment_token_accept(${tokenHash}::text, ${verifiedUserId}::uuid, ${gotrueSessionId}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !ENROLMENT_ACCEPT_STATUSES.has(r.o_status)) throw new Error("partner_enrolment_token_accept returned no usable status");
      if (r.o_status !== "ok") return { status: r.o_status as EnrolmentAcceptStatus, accepted: null };
      return {
        status: "ok",
        accepted: { userId: String(r.o_user_id), tokenId: String(r.o_token_id), purpose: String(r.o_purpose), challenge: registerChallengeOf(r, "partner_enrolment_token_accept") },
      };
    },
    async registerFirst(input: RegisterFirstInput): Promise<RegisterFirstResult> {
      const rows = await trx`
        select o_status, o_credential_id::text as o_credential_id, o_aal::int as o_aal, o_expires_at, o_enrolment_until
        from private.partner_credential_register_first(
          ${input.sessionTokenHash}::text, ${input.userId}::uuid, ${input.refKind}::smallint, ${input.refId}::uuid,
          ${input.nonce}::bytea, ${String(input.exp)}::bigint, ${input.mac}::bytea,
          ${input.attestationObject}::bytea, ${input.clientDataJson}::bytea, ${input.credentialId}::bytea, ${input.publicKey}::bytea, ${[...input.transports] as never}::text[])`;
      const r = rows[0];
      if (typeof r?.o_status !== "string") throw new Error("partner_credential_register_first returned no status");
      return {
        status: r.o_status,
        credentialId: textOrNull(r.o_credential_id),
        aal: r.o_aal === null || r.o_aal === undefined ? null : Number(r.o_aal),
        expiresAt: isoOrNull(r.o_expires_at),
        enrolmentUntil: isoOrNull(r.o_enrolment_until),
      };
    },
  };
}

function buildPartnerMintTx(trx: TxSql): PartnerMintTx & PartnerInviteMintTx {
  return {
    ...buildPartnerInviteMintTx(trx),
    async issueChallenge(): Promise<ChallengeIssue> {
      const rows = await trx`select o_nonce, o_exp::text as o_exp, o_mac from private.partner_challenge_issue_sign_in()`;
      const r = rows[0];
      if (r === undefined) throw new Error("partner_challenge_issue_sign_in returned no row");
      return { nonce: bytesOf(r.o_nonce), exp: Number(r.o_exp), mac: bytesOf(r.o_mac) };
    },
    async lookupCredential(credentialId: Uint8Array): Promise<CredentialLookup> {
      const rows = await trx`
        select o_status, o_credential_id::text as o_credential_id, o_user_id::text as o_user_id, o_alg::int as o_alg, o_public_key, o_sign_count::text as o_sign_count
        from private.partner_credential_lookup(${credentialId}::bytea)`;
      const r = rows[0];
      if (r?.o_status === "ok") {
        return { status: "ok", credential: { id: String(r.o_credential_id), userId: String(r.o_user_id), alg: Number(r.o_alg), publicKey: bytesOf(r.o_public_key), signCount: Number(r.o_sign_count) } };
      }
      return { status: r?.o_status === "cooldown" ? "cooldown" : "unknown" };
    },
    async recordFailure(credentialId: Uint8Array): Promise<"counted" | "cooldown" | "unknown"> {
      const rows = await trx`select o_status from private.partner_sign_in_failure_record(${credentialId}::bytea)`;
      const status = rows[0]?.o_status;
      return status === "counted" || status === "cooldown" ? status : "unknown";
    },
    async mint(input: MintInput): Promise<MintResult> {
      const rows = await trx`
        select o_status, o_aal::int as o_aal, o_expires_at
        from private.partner_session_mint(
          ${input.tokenHash}::text, ${input.credentialId}::bytea, ${input.nonce}::bytea, ${String(input.exp)}::bigint, ${input.mac}::bytea,
          ${input.authenticatorData}::bytea, ${input.clientDataJson}::bytea, ${input.signature}::bytea)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string") throw new Error("partner_session_mint returned no status");
      return { status: r.o_status, aal: r.o_aal === null || r.o_aal === undefined ? null : Number(r.o_aal), expiresAt: r.o_expires_at instanceof Date ? r.o_expires_at.toISOString() : null };
    },
  };
}

const PIN_CHECK_STATUSES: ReadonlySet<string> = new Set(["ok", "wrong", "locked", "retry_after", "unset", "must_change"]);
function isPinCheckStatus(v: unknown): v is PinCheckStatus {
  return typeof v === "string" && PIN_CHECK_STATUSES.has(v);
}
const PIN_WRITE_STATUSES: ReadonlySet<string> = new Set(["ok", "already_set", "no_pin", "must_change", "wrong", "locked", "retry_after", "unset"]);
function pinWriteResult(r: Record<string, unknown> | undefined, fn: string): PinWriteResult {
  const status = r?.o_status;
  if (typeof status !== "string" || !PIN_WRITE_STATUSES.has(status)) throw new Error(`${fn} returned no usable status`);
  return { status: status as PinWriteStatus, retryAfterSeconds: Number(r?.o_retry_after ?? 0) };
}
const TOTP_ENROL_STATUSES: ReadonlySet<string> = new Set(["ok", "already_confirmed"]);
const TOTP_CONFIRM_STATUSES: ReadonlySet<string> = new Set(["ok", "wrong", "locked", "unset", "already_confirmed", "wrong_session"]);
const TOTP_VERIFY_STATUSES: ReadonlySet<string> = new Set(["ok", "wrong", "locked", "unset", "unconfirmed", "retry_after"]);
const TOTP_RESET_STATUSES: ReadonlySet<string> = new Set(["ok", "unset"]);
function isTotpEnrolStatus(v: unknown): v is TotpEnrolStatus {
  return typeof v === "string" && TOTP_ENROL_STATUSES.has(v);
}
function isTotpConfirmStatus(v: unknown): v is TotpConfirmStatus {
  return typeof v === "string" && TOTP_CONFIRM_STATUSES.has(v);
}
function isTotpVerifyStatus(v: unknown): v is TotpVerifyStatus {
  return typeof v === "string" && TOTP_VERIFY_STATUSES.has(v);
}

function buildPartnerSessionTx(trx: TxSql): PartnerSessionTx {
  return {
    async whoami(): Promise<unknown> {
      const rows = await trx`select private.partner_whoami_for_partner() as info`;
      return rows[0]?.info ?? null;
    },
    async signOut(): Promise<void> {
      await trx`select private.partner_session_revoke_for_partner()`;
    },
    async lock(): Promise<void> {
      await trx`select private.partner_session_lock_for_partner()`;
    },
    async reauthOptions(): Promise<ChallengeIssue & { rp: RpConfig }> {
      const rows = await trx`select o_nonce, o_exp::text as o_exp, o_mac, o_rp_id, o_origin from private.partner_session_reauth_options_for_partner()`;
      const r = rows[0];
      if (r === undefined) throw new Error("partner_session_reauth_options_for_partner returned no row");
      return { nonce: bytesOf(r.o_nonce), exp: Number(r.o_exp), mac: bytesOf(r.o_mac), rp: { rpId: String(r.o_rp_id), origin: String(r.o_origin) } };
    },
    async reauthCredential(credentialId: Uint8Array): Promise<ReauthCredential | null> {
      const rows = await trx`
        select o_credential_id::text as o_credential_id, o_user_id::text as o_user_id, o_alg::int as o_alg, o_public_key, o_sign_count::text as o_sign_count, o_rp_id, o_origin
        from private.partner_session_reauth_credential_for_partner(${credentialId}::bytea)`;
      const r = rows[0];
      if (r === undefined) return null;
      return {
        id: String(r.o_credential_id),
        userId: String(r.o_user_id),
        alg: Number(r.o_alg),
        publicKey: bytesOf(r.o_public_key),
        signCount: Number(r.o_sign_count),
        rp: { rpId: String(r.o_rp_id), origin: String(r.o_origin) },
      };
    },
    async pinParams(): Promise<PinParams> {
      const rows = await trx`select o_status, o_salt, o_iterations::int as o_iterations, o_retry_after::int as o_retry_after from private.partner_pin_params_for_partner()`;
      const r = rows[0];
      if (r?.o_status === "ok") return { state: "ok", salt: bytesOf(r.o_salt), iterations: Number(r.o_iterations), retryAfterSeconds: Number(r.o_retry_after) };
      if (r?.o_status === "unset" || r?.o_status === "must_change" || r?.o_status === "locked") return { state: r.o_status };
      throw new Error("partner_pin_params_for_partner returned no usable status");
    },
    async pinVerify(derived: Uint8Array): Promise<PinVerifyResult> {
      const rows = await trx`select o_status, o_retry_after::int as o_retry_after, o_grant_until from private.partner_pin_verify_for_partner(${derived}::bytea)`;
      const r = rows[0];
      if (!isPinCheckStatus(r?.o_status)) throw new Error("partner_pin_verify_for_partner returned no usable status");
      return { status: r.o_status, retryAfterSeconds: Number(r.o_retry_after ?? 0), grantUntil: r.o_grant_until instanceof Date ? r.o_grant_until.toISOString() : null };
    },
    async pinSet(input: PinSetInput): Promise<PinWriteResult> {
      const rows = await trx`select o_status, o_retry_after::int as o_retry_after from private.partner_pin_set_for_partner(${input.derived}::bytea, ${input.salt}::bytea, ${input.iterations}::int)`;
      return pinWriteResult(rows[0], "partner_pin_set_for_partner");
    },
    async pinChange(input: PinChangeInput): Promise<PinWriteResult> {
      const rows = await trx`
        select o_status, o_retry_after::int as o_retry_after
        from private.partner_pin_change_for_partner(${input.current}::bytea, ${input.derived}::bytea, ${input.salt}::bytea, ${input.iterations}::int)`;
      return pinWriteResult(rows[0], "partner_pin_change_for_partner");
    },
    async otpTarget(): Promise<string | null> {
      const rows = await trx`select o_email from private.partner_session_otp_target_for_partner()`;
      const email = rows[0]?.o_email;
      return typeof email === "string" && email !== "" ? email : null;
    },
    async otpProof(gotrueSessionId: string): Promise<{ status: "ok" | "refused"; otpProofUntil: string | null }> {
      const rows = await trx`select o_status, o_otp_proof_until from private.partner_session_otp_proof_for_partner(${gotrueSessionId}::uuid)`;
      const r = rows[0];
      if (r?.o_status === "ok" && r.o_otp_proof_until instanceof Date) return { status: "ok", otpProofUntil: r.o_otp_proof_until.toISOString() };
      return { status: "refused", otpProofUntil: null };
    },
    async totpEnrol(): Promise<TotpEnrolResult> {
      const rows = await trx`
        select o_status, o_seed, o_seed_version::int as o_seed_version, o_issuer, o_period::int as o_period, o_digits::int as o_digits, o_algo
        from private.partner_totp_enrol_for_partner()`;
      const r = rows[0];
      if (!isTotpEnrolStatus(r?.o_status)) throw new Error("partner_totp_enrol_for_partner returned no usable status");
      if (r.o_status !== "ok") {
        return { status: r.o_status, seed: null, seedVersion: null, issuer: null, period: null, digits: null, algo: null };
      }
      return {
        status: "ok",
        seed: bytesOf(r.o_seed),
        seedVersion: Number(r.o_seed_version),
        issuer: String(r.o_issuer),
        period: Number(r.o_period),
        digits: Number(r.o_digits),
        algo: String(r.o_algo),
      };
    },
    async totpConfirm(code: string): Promise<TotpConfirmResult> {
      const rows = await trx`select o_status, o_retry_after::int as o_retry_after from private.partner_totp_confirm_for_partner(${code})`;
      const r = rows[0];
      if (!isTotpConfirmStatus(r?.o_status)) throw new Error("partner_totp_confirm_for_partner returned no usable status");
      return { status: r.o_status, retryAfterSeconds: Number(r.o_retry_after ?? 0) };
    },
    async totpVerify(code: string): Promise<TotpVerifyResult> {
      const rows = await trx`select o_status, o_retry_after::int as o_retry_after, o_mfa_until from private.partner_totp_verify_for_partner(${code})`;
      const r = rows[0];
      if (!isTotpVerifyStatus(r?.o_status)) throw new Error("partner_totp_verify_for_partner returned no usable status");
      return {
        status: r.o_status,
        retryAfterSeconds: Number(r.o_retry_after ?? 0),
        mfaUntil: r.o_mfa_until instanceof Date ? r.o_mfa_until.toISOString() : null,
      };
    },
    async totpReset(targetUid: string): Promise<TotpResetResult> {
      const rows = await trx`select o_status from private.partner_totp_reset_for_partner(${targetUid}::uuid)`;
      const status = rows[0]?.o_status;
      if (typeof status !== "string" || !TOTP_RESET_STATUSES.has(status)) throw new Error("partner_totp_reset_for_partner returned no usable status");
      return { status: status as TotpResetResult["status"] };
    },
    async reauth(input: ReauthInput): Promise<{ status: string; reauthUntil: string | null }> {
      const rows = await trx`
        select o_status, o_reauth_until
        from private.partner_session_reauth_for_partner(
          ${input.credentialId}::bytea, ${input.nonce}::bytea, ${String(input.exp)}::bigint, ${input.mac}::bytea,
          ${input.authenticatorData}::bytea, ${input.clientDataJson}::bytea, ${input.signature}::bytea)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string") throw new Error("partner_session_reauth_for_partner returned no status");
      return { status: r.o_status, reauthUntil: r.o_reauth_until instanceof Date ? r.o_reauth_until.toISOString() : null };
    },
  };
}

const INVITE_REVOKE_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "already_accepted", "already_revoked"]);
const INVITE_MEMBER_ACCEPT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "locked", "email_mismatch", "email_unconfirmed", "already_member"]);
const CREDENTIAL_REVOKE_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "already_revoked"]);

/** The invite definers of the bound lane (0054 7a to 7d). */
function buildPartnerInvitesTx(trx: TxSql): PartnerInvitesTx {
  return {
    async inviteCreate(orgId: string, role: InviteRole, inviteeEmail: string, tokenHash: string): Promise<InviteCreateResult> {
      const rows = await trx`
        select o_status, o_invite_id::text as o_invite_id, o_expires_at
        from private.partner_invite_create_for_partner(${orgId}::uuid, ${role}::app.partner_role, ${inviteeEmail}::text, ${tokenHash}::text)`;
      const r = rows[0];
      if (r?.o_status === "ok") {
        const expiresAt = isoOrNull(r.o_expires_at);
        if (typeof r.o_invite_id !== "string" || expiresAt === null) throw new Error("partner_invite_create_for_partner returned ok without an invite");
        return { status: "ok", inviteId: r.o_invite_id, expiresAt };
      }
      if (r?.o_status === "already_member") return { status: "already_member", inviteId: null, expiresAt: null };
      throw new Error("partner_invite_create_for_partner returned no usable status");
    },
    async inviteList(orgId: string | null): Promise<InviteView[]> {
      const rows = await trx`
        select o_id::text as o_id, o_org_id::text as o_org_id, o_role::text as o_role, o_facility_id, o_invitee_email, o_invited_by::text as o_invited_by,
               o_created_at, o_expires_at, o_accepted_at, o_revoked_at, o_attempts::int as o_attempts
        from private.partner_invite_list_for_partner(${orgId}::uuid)`;
      return rows.map((r) => ({
        id: String(r.o_id),
        orgId: String(r.o_org_id),
        role: String(r.o_role),
        facilityId: textOrNull(r.o_facility_id),
        inviteeEmail: String(r.o_invitee_email),
        invitedBy: String(r.o_invited_by),
        createdAt: String(isoOrNull(r.o_created_at)),
        expiresAt: String(isoOrNull(r.o_expires_at)),
        acceptedAt: isoOrNull(r.o_accepted_at),
        revokedAt: isoOrNull(r.o_revoked_at),
        attempts: Number(r.o_attempts),
      }));
    },
    async inviteRevoke(inviteId: string): Promise<InviteRevokeStatus> {
      const rows = await trx`select o_status from private.partner_invite_revoke_for_partner(${inviteId}::uuid)`;
      const status = rows[0]?.o_status;
      if (typeof status !== "string" || !INVITE_REVOKE_STATUSES.has(status)) throw new Error("partner_invite_revoke_for_partner returned no usable status");
      return status as InviteRevokeStatus;
    },
    async inviteAcceptMember(tokenHash: string): Promise<InviteMemberAcceptResult> {
      const rows = await trx`select o_status, o_org_id::text as o_org_id, o_role::text as o_role from private.partner_invite_accept_for_partner(${tokenHash}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !INVITE_MEMBER_ACCEPT_STATUSES.has(r.o_status)) throw new Error("partner_invite_accept_for_partner returned no usable status");
      return { status: r.o_status as InviteMemberAcceptStatus, orgId: textOrNull(r.o_org_id), role: textOrNull(r.o_role) };
    },
  };
}

/** The member and credential definers of the bound lane (0054 7e to 7l); `totpReset` is the session builder's (7m replaced its body, not its signature). */
function buildPartnerMembersTx(trx: TxSql): Omit<PartnerMembersTx, "totpReset"> {
  return {
    async memberRevoke(targetUserId: string, orgId: string): Promise<MemberRevokeStatus> {
      const rows = await trx`select o_status from private.partner_member_revoke_for_partner(${targetUserId}::uuid, ${orgId}::uuid)`;
      const status = rows[0]?.o_status;
      if (status !== "ok" && status !== "not_found") throw new Error("partner_member_revoke_for_partner returned no usable status");
      return status;
    },
    async memberRecover(targetUserId: string, tokenHash: string): Promise<MemberRecoverResult> {
      const rows = await trx`select o_status, o_token_id::text as o_token_id, o_expires_at from private.partner_member_recover_for_partner(${targetUserId}::uuid, ${tokenHash}::text)`;
      const r = rows[0];
      if (r?.o_status === "ok") {
        const expiresAt = isoOrNull(r.o_expires_at);
        if (typeof r.o_token_id !== "string" || expiresAt === null) throw new Error("partner_member_recover_for_partner returned ok without a token");
        return { status: "ok", tokenId: r.o_token_id, expiresAt };
      }
      if (r?.o_status === "no_email") return { status: "no_email", tokenId: null, expiresAt: null };
      throw new Error("partner_member_recover_for_partner returned no usable status");
    },
    async pinReset(targetUserId: string): Promise<PinResetStatus> {
      const rows = await trx`select o_status from private.partner_pin_reset_for_partner(${targetUserId}::uuid)`;
      const status = rows[0]?.o_status;
      if (status !== "ok" && status !== "unset") throw new Error("partner_pin_reset_for_partner returned no usable status");
      return status;
    },
    async orgSessionsRevokeAll(orgId: string, createdAfter: string | null): Promise<OrgRevokeAllResult> {
      const rows = await trx`
        select o_status, o_sessions::int as o_sessions, o_credentials::int as o_credentials
        from private.partner_org_sessions_revoke_for_partner(${orgId}::uuid, ${createdAfter}::timestamptz)`;
      const r = rows[0];
      const status = r?.o_status;
      if (status !== "ok" && status !== "not_found") throw new Error("partner_org_sessions_revoke_for_partner returned no usable status");
      return { status, sessions: Number(r?.o_sessions ?? 0), credentials: Number(r?.o_credentials ?? 0) };
    },
    async adminEnrolmentIssue(targetUserId: string, tokenHash: string): Promise<AdminEnrolmentResult> {
      const rows = await trx`select o_status, o_token_id::text as o_token_id, o_expires_at from private.partner_admin_enrolment_issue_for_partner(${targetUserId}::uuid, ${tokenHash}::text)`;
      const r = rows[0];
      const expiresAt = isoOrNull(r?.o_expires_at);
      if (r?.o_status !== "ok" || typeof r.o_token_id !== "string" || expiresAt === null) throw new Error("partner_admin_enrolment_issue_for_partner returned no usable row");
      return { tokenId: r.o_token_id, expiresAt };
    },
    async credentialOptions(): Promise<CredentialOptionsResult> {
      const rows = await trx`
        select o_status, o_nonce, o_exp::text as o_exp, o_mac, o_rp_id, o_origin, o_exclude
        from private.partner_credential_options_for_partner()`;
      const r = rows[0];
      if (r?.o_status === "too_many") return { status: "too_many" };
      if (r?.o_status !== "ok" || typeof r.o_rp_id !== "string" || typeof r.o_origin !== "string") throw new Error("partner_credential_options_for_partner returned no usable row");
      const exclude = Array.isArray(r.o_exclude) ? (r.o_exclude as unknown[]).map(bytesOf) : [];
      return {
        status: "ok",
        challenge: { nonce: bytesOf(r.o_nonce), exp: Number(r.o_exp), mac: bytesOf(r.o_mac) },
        rp: { rpId: r.o_rp_id, origin: r.o_origin },
        excludeCredentialIds: exclude,
      };
    },
    async credentialSubject(): Promise<CredentialSubject> {
      const who = await trx`select private.partner_whoami_for_partner() as info`;
      const userId = (who[0]?.info as { userId?: unknown } | null | undefined)?.userId;
      if (typeof userId !== "string") throw new Error("partner_whoami_for_partner returned no user");
      const mail = await trx`select o_email from private.partner_session_otp_target_for_partner()`;
      return { userId, email: textOrNull(mail[0]?.o_email) };
    },
    async credentialRegister(input: CredentialRegisterInput): Promise<{ status: string; credentialId: string | null }> {
      const rows = await trx`
        select o_status, o_credential_id::text as o_credential_id
        from private.partner_credential_register_for_partner(
          ${input.nonce}::bytea, ${String(input.exp)}::bigint, ${input.mac}::bytea,
          ${input.attestationObject}::bytea, ${input.clientDataJson}::bytea, ${input.credentialId}::bytea, ${input.publicKey}::bytea, ${[...input.transports] as never}::text[])`;
      const r = rows[0];
      if (typeof r?.o_status !== "string") throw new Error("partner_credential_register_for_partner returned no status");
      return { status: r.o_status, credentialId: textOrNull(r.o_credential_id) };
    },
    async credentialList(): Promise<CredentialView[]> {
      const rows = await trx`
        select o_id::text as o_id, o_label, o_note, o_created_at, o_last_used_at, o_revoked_at, o_backup_eligible, o_backup_state
        from private.partner_credential_list_for_partner()`;
      return rows.map((r) => ({
        id: String(r.o_id),
        label: String(r.o_label),
        note: textOrNull(r.o_note),
        createdAt: String(isoOrNull(r.o_created_at)),
        lastUsedAt: isoOrNull(r.o_last_used_at),
        revokedAt: isoOrNull(r.o_revoked_at),
        backupEligible: r.o_backup_eligible === true,
        backupState: r.o_backup_state === true,
      }));
    },
    async credentialRevoke(credentialId: string): Promise<CredentialRevokeStatus> {
      const rows = await trx`select o_status from private.partner_credential_revoke_for_partner(${credentialId}::uuid)`;
      const status = rows[0]?.o_status;
      if (typeof status !== "string" || !CREDENTIAL_REVOKE_STATUSES.has(status)) throw new Error("partner_credential_revoke_for_partner returned no usable status");
      return status as CredentialRevokeStatus;
    },
  };
}

/** The attest and read definers of 0056 (S3). `select private.*(...)` in the migration's argument order; every status is a returned row, so a refusal COMMITS (the failure counters live in it). */
const ATTEST_STATUSES: ReadonlySet<string> = new Set(["ok", "token_invalid", "replayed", "verification_failed", "rate_limited", "no_facility", "no_programme", "cold_start_cap"]);
function attestResultOf(r: Record<string, unknown> | undefined, fn: string): AttestResult {
  if (typeof r?.o_status !== "string" || !ATTEST_STATUSES.has(r.o_status)) throw new Error(`${fn} returned no usable status`);
  return { status: r.o_status as AttestStatus, attestationId: textOrNull(r.o_attestation_id), held: r.o_held === true };
}
function buildPartnerAttestTx(trx: TxSql): PartnerAttestTx {
  return {
    async attest(facilityId: string, kind: AttestKind, token: string): Promise<AttestResult> {
      const rows = await trx`select o_status, o_attestation_id::text as o_attestation_id, o_held from private.partner_attest_for_partner(${facilityId}::text, ${kind}::text, ${token}::uuid)`;
      return attestResultOf(rows[0], "partner_attest_for_partner");
    },
    async offlineAttest(facilityId: string, kind: AttestKind, handle: string, code: string): Promise<AttestResult> {
      const rows = await trx`
        select o_status, o_attestation_id::text as o_attestation_id, o_held
        from private.partner_offline_attest_for_partner(${facilityId}::text, ${kind}::text, ${handle}::text, ${code}::text)`;
      return attestResultOf(rows[0], "partner_offline_attest_for_partner");
    },
    async shiftLog(facilityId: string): Promise<ShiftLogRow[]> {
      const rows = await trx`
        select o_id::text as o_id, o_facility_id, o_created_at, o_kind::text as o_kind, o_player_handle, o_staff_handle
        from private.partner_shift_log_for_partner(${facilityId}::text)`;
      return rows.map((r) => ({
        id: String(r.o_id),
        facilityId: String(r.o_facility_id),
        createdAt: String(isoOrNull(r.o_created_at)),
        kind: String(r.o_kind),
        playerHandle: String(r.o_player_handle),
        staffHandle: String(r.o_staff_handle),
      }));
    },
    async staffActivity(facilityId: string, days: number): Promise<StaffActivityRow[]> {
      const rows = await trx`
        select o_staff_user_id::text as o_staff_user_id, o_facility_id, o_day::text as o_day, o_attests::int as o_attests, o_activations::int as o_activations, o_anomalies
        from private.partner_staff_activity_for_partner(${facilityId}::text, ${days}::int)`;
      return rows.map((r) => ({
        staffUserId: String(r.o_staff_user_id),
        facilityId: String(r.o_facility_id),
        day: String(r.o_day),
        attests: Number(r.o_attests),
        activations: Number(r.o_activations),
        anomalies: r.o_anomalies,
      }));
    },
  };
}

/** The review definers of 0057 (S4). Every status is a returned row, so a refusal COMMITS. */
const RESOLVE_HELD_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_held", "budget_short"]);
const QUEUE_KINDS: ReadonlySet<string> = new Set(["offer_code", "entitlement", "review_item"]);
function resolveHeldOf(r: Record<string, unknown> | undefined, fn: string): ResolveHeldResult {
  if (typeof r?.o_status !== "string" || !RESOLVE_HELD_STATUSES.has(r.o_status)) throw new Error(`${fn} returned no usable status`);
  return { status: r.o_status as ResolveHeldStatus, state: textOrNull(r.o_state) };
}
function buildPartnerReviewTx(trx: TxSql): PartnerReviewTx {
  return {
    async heldQueue(): Promise<HeldQueueRow[]> {
      const rows = await trx`
        select o_kind, o_id::text as o_id, o_subject_table, o_subject_id::text as o_subject_id, o_user_id::text as o_user_id,
               o_handle, o_facility_id, o_trail_id, o_hold_detail, o_reserved_amount, o_held_at, o_sla_breached, o_review_kind
        from private.partner_held_queue_for_partner()`;
      return rows.map((r) => {
        if (typeof r.o_kind !== "string" || !QUEUE_KINDS.has(r.o_kind)) throw new Error("partner_held_queue_for_partner returned an unknown kind");
        return {
          kind: r.o_kind as HeldQueueRow["kind"],
          id: String(r.o_id),
          subjectTable: String(r.o_subject_table),
          subjectId: String(r.o_subject_id),
          userId: textOrNull(r.o_user_id),
          handle: textOrNull(r.o_handle),
          facilityId: textOrNull(r.o_facility_id),
          trailId: textOrNull(r.o_trail_id),
          holdDetail: r.o_hold_detail ?? null,
          reservedAmount: r.o_reserved_amount === null || r.o_reserved_amount === undefined ? null : Number(r.o_reserved_amount),
          heldAt: isoOrNull(r.o_held_at),
          slaBreached: r.o_sla_breached === true,
          reviewKind: textOrNull(r.o_review_kind),
        };
      });
    },
    async reviewSla(): Promise<ReviewSlaSummary> {
      const rows = await trx`
        select o_held_offer_codes::int as o_held_offer_codes, o_held_entitlements::int as o_held_entitlements,
               o_open_review_items::int as o_open_review_items, o_sla_breached_rewards::int as o_sla_breached_rewards,
               o_sla_breached_review_items::int as o_sla_breached_review_items, o_sla_hours::int as o_sla_hours
        from private.partner_review_sla_for_partner()`;
      const r = rows[0];
      if (r === undefined) throw new Error("partner_review_sla_for_partner returned no row");
      return {
        heldOfferCodes: Number(r.o_held_offer_codes),
        heldEntitlements: Number(r.o_held_entitlements),
        openReviewItems: Number(r.o_open_review_items),
        slaBreachedRewards: Number(r.o_sla_breached_rewards),
        slaBreachedReviewItems: Number(r.o_sla_breached_review_items),
        slaHours: Number(r.o_sla_hours),
      };
    },
    async resolveHeldOfferCode(codeId: string, approve: boolean): Promise<ResolveHeldResult> {
      const rows = await trx`select o_status, o_state from private.partner_resolve_held_offer_code_for_partner(${codeId}::uuid, ${approve}::boolean)`;
      return resolveHeldOf(rows[0], "partner_resolve_held_offer_code_for_partner");
    },
    async resolveHeldEntitlement(entitlementId: string, approve: boolean): Promise<ResolveHeldResult> {
      const rows = await trx`select o_status, o_state from private.partner_resolve_held_entitlement_for_partner(${entitlementId}::uuid, ${approve}::boolean)`;
      return resolveHeldOf(rows[0], "partner_resolve_held_entitlement_for_partner");
    },
  };
}

/** The stock definers of 0058 (S5). Every status is a returned row, so a refusal COMMITS. */
const STOCK_MOVE_STATUSES: ReadonlySet<string> = new Set(["ok", "no_stock_row", "short", "over_cap"]);
function buildPartnerStockTx(trx: TxSql): PartnerStockTx {
  return {
    async stockRead(facilityId: string): Promise<StockRow[]> {
      const rows = await trx`
        select o_trail_id, o_on_hand::int as o_on_hand, o_low_threshold::int as o_low_threshold, o_status, o_last_counted_at
        from private.partner_stock_read_for_partner(${facilityId}::text)`;
      return rows.map((r) => ({
        trailId: String(r.o_trail_id),
        onHand: Number(r.o_on_hand),
        lowThreshold: Number(r.o_low_threshold),
        status: textOrNull(r.o_status),
        lastCountedAt: isoOrNull(r.o_last_counted_at),
      }));
    },
    async stockMove(facilityId: string, trailId: string, kind: StockMoveKind, qty: number, note: string | null): Promise<StockMoveResult> {
      const rows = await trx`
        select o_status, o_on_hand::int as o_on_hand, o_availability
        from private.partner_stock_move_for_partner(${facilityId}::text, ${trailId}::text, ${kind}::text, ${qty}::int, ${note}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !STOCK_MOVE_STATUSES.has(r.o_status)) throw new Error("partner_stock_move_for_partner returned no usable status");
      return { status: r.o_status as StockMoveStatus, onHand: r.o_on_hand === null || r.o_on_hand === undefined ? null : Number(r.o_on_hand), availability: textOrNull(r.o_availability) };
    },
  };
}

/** The programme / offers / sponsorships definers of 0059 (S6). Every status is a returned row, so a refusal COMMITS. */
const TRAIL_PROGRAMME_UPSERT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found"]);
const FACILITY_PROGRAMME_UPSERT_STATUSES: ReadonlySet<string> = new Set(["ok", "no_trail"]);
const OFFER_UPSERT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_draft", "bad_funder"]);
const OFFER_APPROVE_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_draft"]);
const OFFER_END_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_live"]);
const SPONSORSHIP_UPSERT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_draft", "bad_sponsor"]);
const SPONSORSHIP_APPROVE_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_draft", "stock_short"]);

const dateOnlyOrNull = (v: unknown): string | null => {
  if (v === null || v === undefined) return null;
  return v instanceof Date ? v.toISOString().slice(0, 10) : String(v).slice(0, 10);
};
const numOrNull = (v: unknown): number | null => {
  if (v === null || v === undefined) return null;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : null;
};
const boolOrNull = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);

function buildPartnerProgrammeTx(trx: TxSql): PartnerProgrammeTx {
  return {
    async trailRead(trailId: string): Promise<TrailProgrammeRow> {
      const rows = await trx`
        select o_status, o_trail_id, o_programme_status, o_marker_source, o_marker_requires_completion,
               o_special_marker_funded_by, o_special_marker_low_threshold::int as o_special_marker_low_threshold,
               o_web_player_flow, o_special_marker_sku, o_special_marker_sponsorship_id::text as o_special_marker_sponsorship_id,
               o_fee_model, o_fee_amount, o_starts_on, o_ends_on
        from private.partner_trail_programme_read_for_partner(${trailId}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || (r.o_status !== "ok" && r.o_status !== "not_found")) {
        throw new Error("partner_trail_programme_read_for_partner returned no usable status");
      }
      return {
        status: r.o_status as "ok" | "not_found",
        trailId: textOrNull(r.o_trail_id),
        programmeStatus: textOrNull(r.o_programme_status),
        markerSource: textOrNull(r.o_marker_source),
        markerRequiresCompletion: boolOrNull(r.o_marker_requires_completion),
        specialMarkerFundedBy: textOrNull(r.o_special_marker_funded_by),
        specialMarkerLowThreshold: r.o_special_marker_low_threshold === null || r.o_special_marker_low_threshold === undefined
          ? null
          : Number(r.o_special_marker_low_threshold),
        webPlayerFlow: boolOrNull(r.o_web_player_flow),
        specialMarkerSku: textOrNull(r.o_special_marker_sku),
        specialMarkerSponsorshipId: textOrNull(r.o_special_marker_sponsorship_id),
        feeModel: textOrNull(r.o_fee_model),
        feeAmount: numOrNull(r.o_fee_amount),
        startsOn: dateOnlyOrNull(r.o_starts_on),
        endsOn: dateOnlyOrNull(r.o_ends_on),
      };
    },
    async facilityList(trailId: string): Promise<FacilityProgrammeRow[]> {
      const rows = await trx`
        select o_facility_id, o_participation, o_stocks_markers, o_holds_special_marker, o_connectivity,
               o_staff_network, o_wifi_note, o_qr_mode, o_pin_epoch::int as o_pin_epoch
        from private.partner_facility_programme_list_for_partner(${trailId}::text)`;
      return rows.map((r) => ({
        facilityId: String(r.o_facility_id),
        participation: String(r.o_participation),
        stocksMarkers: Boolean(r.o_stocks_markers),
        holdsSpecialMarker: Boolean(r.o_holds_special_marker),
        connectivity: textOrNull(r.o_connectivity),
        staffNetwork: boolOrNull(r.o_staff_network),
        wifiNote: textOrNull(r.o_wifi_note),
        qrMode: String(r.o_qr_mode),
        pinEpoch: Number(r.o_pin_epoch),
      }));
    },
    async trailUpsert(
      trailId: string,
      status: string,
      markerSource: string,
      markerRequiresCompletion: boolean,
      specialMarkerFundedBy: string | null,
      specialMarkerLowThreshold: number,
      webPlayerFlow: boolean,
      specialMarkerSku: string | null,
      specialMarkerSponsorshipId: string | null,
      feeModel: string | null,
      feeAmount: number | null,
      startsOn: string | null,
      endsOn: string | null,
    ): Promise<TrailProgrammeUpsertStatus> {
      const rows = await trx`
        select o_status
        from private.partner_trail_programme_upsert_for_partner(
          ${trailId}::text, ${status}::text, ${markerSource}::text, ${markerRequiresCompletion}::boolean,
          ${specialMarkerFundedBy}::text, ${specialMarkerLowThreshold}::int, ${webPlayerFlow}::boolean,
          ${specialMarkerSku}::text, ${specialMarkerSponsorshipId}::uuid, ${feeModel}::text, ${feeAmount}::numeric,
          ${startsOn}::date, ${endsOn}::date)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !TRAIL_PROGRAMME_UPSERT_STATUSES.has(r.o_status)) {
        throw new Error("partner_trail_programme_upsert_for_partner returned no usable status");
      }
      return r.o_status as TrailProgrammeUpsertStatus;
    },
    async facilityUpsert(
      trailId: string,
      facilityId: string,
      participation: string,
      stocksMarkers: boolean | null,
      holdsSpecialMarker: boolean | null,
      connectivity: string | null,
      staffNetwork: boolean | null,
      wifiNote: string | null,
      qrMode: string,
    ): Promise<FacilityProgrammeUpsertStatus> {
      const rows = await trx`
        select o_status
        from private.partner_facility_programme_upsert_for_partner(
          ${trailId}::text, ${facilityId}::text, ${participation}::text, ${stocksMarkers}::boolean,
          ${holdsSpecialMarker}::boolean, ${connectivity}::text, ${staffNetwork}::boolean, ${wifiNote}::text, ${qrMode}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !FACILITY_PROGRAMME_UPSERT_STATUSES.has(r.o_status)) {
        throw new Error("partner_facility_programme_upsert_for_partner returned no usable status");
      }
      return r.o_status as FacilityProgrammeUpsertStatus;
    },
    async operatorRollup(trailId: string): Promise<OperatorRollupRow[]> {
      const rows = await trx`
        select o_trail_id, o_month, o_metric, o_value, o_cohort_n::int as o_cohort_n
        from private.partner_operator_rollup_for_partner(${trailId}::text)`;
      return rows.map((r) => ({
        trailId: String(r.o_trail_id),
        month: dateOnlyOrNull(r.o_month) ?? String(r.o_month),
        metric: String(r.o_metric),
        value: Number(r.o_value),
        cohortN: Number(r.o_cohort_n),
      }));
    },
    async sponsorRollup(sponsorshipId: string): Promise<SponsorRollupRow[]> {
      const rows = await trx`
        select o_sponsorship_id::text as o_sponsorship_id, o_month, o_metric, o_value, o_cohort_n::int as o_cohort_n
        from private.partner_sponsor_rollup_for_partner(${sponsorshipId}::uuid)`;
      return rows.map((r) => ({
        sponsorshipId: String(r.o_sponsorship_id),
        month: dateOnlyOrNull(r.o_month) ?? String(r.o_month),
        metric: String(r.o_metric),
        value: Number(r.o_value),
        cohortN: Number(r.o_cohort_n),
      }));
    },
  };
}

function buildPartnerOffersAdminTx(trx: TxSql): PartnerOffersAdminTx {
  return {
    async listOffers(trailId: string): Promise<OfferAdminRow[]> {
      const rows = await trx`
        select o_id::text as o_id, o_terms_id, o_trail_id, o_facility_id, o_eligibility, o_funder,
               o_sponsorship_id::text as o_sponsorship_id, o_budget_cap, o_budget_used, o_budget_reserved,
               o_max_redemptions::int as o_max_redemptions, o_face_value, o_valid_from, o_valid_to, o_status
        from private.partner_offers_list_for_partner(${trailId}::text)`;
      return rows.map((r) => ({
        id: String(r.o_id),
        termsId: textOrNull(r.o_terms_id),
        trailId: String(r.o_trail_id),
        facilityId: String(r.o_facility_id),
        eligibility: r.o_eligibility,
        funder: String(r.o_funder),
        sponsorshipId: textOrNull(r.o_sponsorship_id),
        budgetCap: Number(r.o_budget_cap),
        budgetUsed: Number(r.o_budget_used),
        budgetReserved: Number(r.o_budget_reserved),
        maxRedemptions: r.o_max_redemptions === null || r.o_max_redemptions === undefined ? null : Number(r.o_max_redemptions),
        faceValue: Number(r.o_face_value),
        validFrom: dateOnlyOrNull(r.o_valid_from) ?? String(r.o_valid_from),
        validTo: dateOnlyOrNull(r.o_valid_to) ?? String(r.o_valid_to),
        status: String(r.o_status),
      }));
    },
    async upsertOffer(
      id: string | null,
      trailId: string,
      facilityId: string,
      eligibility: unknown,
      funder: string,
      sponsorshipId: string | null,
      budgetCap: number,
      maxRedemptions: number | null,
      faceValue: number,
      validFrom: string,
      validTo: string,
    ): Promise<OfferUpsertResult> {
      const rows = await trx`
        select o_status, o_id::text as o_id
        from private.partner_offer_upsert_for_partner(
          ${id}::uuid, ${trailId}::text, ${facilityId}::text, ${trx.json(eligibility as never)}::jsonb, ${funder}::text,
          ${sponsorshipId}::uuid, ${budgetCap}::numeric, ${maxRedemptions}::int, ${faceValue}::numeric,
          ${validFrom}::date, ${validTo}::date)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !OFFER_UPSERT_STATUSES.has(r.o_status)) {
        throw new Error("partner_offer_upsert_for_partner returned no usable status");
      }
      return { status: r.o_status as OfferUpsertStatus, id: textOrNull(r.o_id) };
    },
    async approveOffer(id: string): Promise<OfferApproveStatus> {
      const rows = await trx`select o_status from private.partner_offer_approve_for_partner(${id}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !OFFER_APPROVE_STATUSES.has(r.o_status)) {
        throw new Error("partner_offer_approve_for_partner returned no usable status");
      }
      return r.o_status as OfferApproveStatus;
    },
    async endOffer(id: string): Promise<OfferEndStatus> {
      const rows = await trx`select o_status from private.partner_offer_end_for_partner(${id}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !OFFER_END_STATUSES.has(r.o_status)) {
        throw new Error("partner_offer_end_for_partner returned no usable status");
      }
      return r.o_status as OfferEndStatus;
    },
  };
}

function buildPartnerSponsorshipsTx(trx: TxSql): PartnerSponsorshipsTx {
  return {
    async listSponsorships(trailId: string): Promise<SponsorshipRow[]> {
      const rows = await trx`
        select o_id::text as o_id, o_sponsor_org_id::text as o_sponsor_org_id, o_trail_id, o_category, o_scope,
               o_attribution_name, o_attribution_asset, o_placement_fee, o_starts_on, o_ends_on,
               o_operator_approved_at, o_status
        from private.partner_sponsorships_list_for_partner(${trailId}::text)`;
      return rows.map((r) => ({
        id: String(r.o_id),
        sponsorOrgId: String(r.o_sponsor_org_id),
        trailId: String(r.o_trail_id),
        category: String(r.o_category),
        scope: String(r.o_scope),
        attributionName: String(r.o_attribution_name),
        attributionAsset: textOrNull(r.o_attribution_asset),
        placementFee: numOrNull(r.o_placement_fee),
        startsOn: dateOnlyOrNull(r.o_starts_on),
        endsOn: dateOnlyOrNull(r.o_ends_on),
        operatorApprovedAt: isoOrNull(r.o_operator_approved_at),
        status: String(r.o_status),
      }));
    },
    async upsertSponsorship(
      id: string | null,
      sponsorOrgId: string,
      trailId: string,
      category: string,
      scope: string,
      attributionName: string,
      attributionAsset: string | null,
      placementFee: number | null,
      startsOn: string | null,
      endsOn: string | null,
    ): Promise<SponsorshipUpsertResult> {
      const rows = await trx`
        select o_status, o_id::text as o_id
        from private.partner_sponsorship_upsert_for_partner(
          ${id}::uuid, ${sponsorOrgId}::uuid, ${trailId}::text, ${category}::text, ${scope}::text,
          ${attributionName}::text, ${attributionAsset}::text, ${placementFee}::numeric, ${startsOn}::date, ${endsOn}::date)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !SPONSORSHIP_UPSERT_STATUSES.has(r.o_status)) {
        throw new Error("partner_sponsorship_upsert_for_partner returned no usable status");
      }
      return { status: r.o_status as SponsorshipUpsertStatus, id: textOrNull(r.o_id) };
    },
    async approveSponsorship(id: string): Promise<SponsorshipApproveStatus> {
      const rows = await trx`select o_status from private.partner_sponsorship_approve_for_partner(${id}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !SPONSORSHIP_APPROVE_STATUSES.has(r.o_status)) {
        throw new Error("partner_sponsorship_approve_for_partner returned no usable status");
      }
      return r.o_status as SponsorshipApproveStatus;
    },
  };
}

/** The hand-over definers of 0058 (S5). Every status is a returned row, so a refusal COMMITS; the token hash is the only form of a hand-over token that reaches the database. */
const HANDOVER_MINT_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_redeemable", "wrong_facility", "no_stock_row", "token_exists"]);
const REDEEM_STATUSES: ReadonlySet<string> = new Set([
  "ok",
  "not_found",
  "not_redeemable",
  "wrong_facility",
  "token_invalid",
  "wrong_player",
  "replayed",
  "no_stock_row",
  "out_of_stock",
  "no_facility",
  "cold_start_cap",
  "no_programme",
]);
const VOUCHER_STATUSES: ReadonlySet<string> = new Set(["ok", "not_found", "not_redeemable", "no_stock_row"]);
const OFFER_REDEEM_STATUSES: ReadonlySet<string> = new Set([
  "ok",
  "not_found",
  "not_issued",
  "expired",
  "wrong_facility",
  "token_invalid",
  "wrong_player",
  "replayed",
  "no_facility",
  "cold_start_cap",
  "budget_short",
  "name_unconfirmed",
  "verification_failed",
  "rate_limited",
]);
function buildPartnerOffersRedeemTx(trx: TxSql): PartnerOffersRedeemTx {
  return {
    async offersQueue(facilityId: string): Promise<OfferQueueRow[]> {
      const rows = await trx`
        select o_offer_code_id::text as o_offer_code_id, o_offer_id::text as o_offer_id, o_player_handle, o_expires_at, o_face_value
        from private.partner_offers_queue_for_partner(${facilityId}::text)`;
      return rows.map((r) => ({
        offerCodeId: String(r.o_offer_code_id),
        offerId: String(r.o_offer_id),
        playerHandle: textOrNull(r.o_player_handle),
        expiresAt: isoOrNull(r.o_expires_at),
        faceValue: numOrNull(r.o_face_value),
      }));
    },
    async redeemOffer(facilityId: string, offerCodeId: string, method: OfferRedeemMethod, credential: string): Promise<OfferRedeemResult> {
      const rows = await trx`
        select o_status, o_attestation_id::text as o_attestation_id
        from private.partner_offers_redeem_for_partner(${facilityId}::text, ${offerCodeId}::uuid, ${method}::text, ${credential}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !OFFER_REDEEM_STATUSES.has(r.o_status)) {
        throw new Error("partner_offers_redeem_for_partner returned no usable status");
      }
      return { status: r.o_status as OfferRedeemStatus, attestationId: textOrNull(r.o_attestation_id) };
    },
    async redeemOfferOffline(
      facilityId: string,
      offerCodeId: string,
      handle: string,
      code: string,
      nameConfirmed: boolean,
    ): Promise<OfferRedeemResult> {
      const rows = await trx`
        select o_status, o_attestation_id::text as o_attestation_id
        from private.partner_offers_redeem_offline_for_partner(
          ${facilityId}::text, ${offerCodeId}::uuid, ${handle}::text, ${code}::text, ${nameConfirmed}::boolean)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !OFFER_REDEEM_STATUSES.has(r.o_status)) {
        throw new Error("partner_offers_redeem_offline_for_partner returned no usable status");
      }
      return { status: r.o_status as OfferRedeemStatus, attestationId: textOrNull(r.o_attestation_id) };
    },
  };
}

const SETTLEMENT_EXPORT_STATUSES: ReadonlySet<string> = new Set(["ok", "empty"]);
function buildPartnerSettlementExportTx(trx: TxSql): PartnerSettlementExportTx {
  return {
    async settlementExport(trailId: string, month: string): Promise<SettlementExportResult> {
      const rows = await trx`
        select o_status, o_facility_id, o_month, o_funder, o_sponsorship_id::text as o_sponsorship_id,
               o_redemptions, o_offline_count, o_unconfirmed_count, o_face_value_total
        from private.partner_settlement_export_for_partner(${trailId}::text, ${month}::date)`;
      const status = rows[0]?.o_status;
      if (typeof status !== "string" || !SETTLEMENT_EXPORT_STATUSES.has(status)) {
        throw new Error("partner_settlement_export_for_partner returned no usable status");
      }
      if (status === "empty") return { status: "empty", lines: [] };
      const lines: SettlementLine[] = rows
        .filter((r) => r.o_status === "ok" && typeof r.o_facility_id === "string")
        .map((r) => ({
          facilityId: String(r.o_facility_id),
          month: dateOnlyOrNull(r.o_month) ?? month,
          funder: String(r.o_funder),
          sponsorshipId: textOrNull(r.o_sponsorship_id),
          redemptions: Number(r.o_redemptions ?? 0),
          offlineCount: Number(r.o_offline_count ?? 0),
          unconfirmedCount: Number(r.o_unconfirmed_count ?? 0),
          faceValueTotal: numOrNull(r.o_face_value_total) ?? 0,
        }));
      return { status: "ok", lines };
    },
  };
}

/**
 * Storage port for the private `exports` bucket (AT(17)): upload + createSignedUrl via the service-role client; purge lists and deletes objects older than a cutoff.
 * The only place outside a partner binding that may touch `storage.objects` for settlement files.
 */
export const exportsStorage: ExportsStoragePort = {
  async putSigned(path, body, contentType, expiresInSeconds) {
    const client = adminClient();
    const { error: upErr } = await client.storage.from("exports").upload(path, body, { contentType, upsert: true });
    if (upErr) throw new Error(`exportsStorage.putSigned: upload failed: ${upErr.message}`);
    const { data, error: signErr } = await client.storage.from("exports").createSignedUrl(path, expiresInSeconds);
    if (signErr || !data?.signedUrl) throw new Error(`exportsStorage.putSigned: createSignedUrl failed: ${signErr?.message ?? "no url"}`);
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
    return { path, signedUrl: data.signedUrl, expiresAt };
  },
  async purgeOlderThan(olderThanMs) {
    const client = adminClient();
    const cutoffIso = new Date(olderThanMs).toISOString();
    let removed = 0;
    // Walk top-level prefixes under the bucket (settlement/…); Storage list is shallow, so recurse one level of folders.
    const queue: string[] = [""];
    while (queue.length > 0) {
      const prefix = queue.shift()!;
      const { data, error } = await client.storage.from("exports").list(prefix === "" ? undefined : prefix, { limit: 1000 });
      if (error) throw new Error(`exportsStorage.purgeOlderThan: list failed: ${error.message}`);
      if (!data || data.length === 0) continue;
      const toDelete: string[] = [];
      for (const item of data) {
        const full = prefix === "" ? item.name : `${prefix}/${item.name}`;
        // Folders have id null and no metadata; files have created_at.
        if (item.id === null && !item.metadata) {
          queue.push(full);
          continue;
        }
        const created = item.created_at ?? (item.metadata as { created_at?: string } | null)?.created_at;
        if (typeof created === "string" && created < cutoffIso) toDelete.push(full);
      }
      if (toDelete.length > 0) {
        const { error: delErr } = await client.storage.from("exports").remove(toDelete);
        if (delErr) throw new Error(`exportsStorage.purgeOlderThan: remove failed: ${delErr.message}`);
        removed += toDelete.length;
      }
    }
    return removed;
  },
};

function buildPartnerEntitlementsTx(trx: TxSql): PartnerEntitlementsTx {
  return {
    async collectQueue(facilityId: string): Promise<EntitlementQueueRow[]> {
      const rows = await trx`
        select o_entitlement_id::text as o_entitlement_id, o_trail_id, o_state, o_player_handle, o_activated_at, o_voucher_issued_at
        from private.partner_entitlement_queue_for_partner(${facilityId}::text)`;
      return rows.map((r) => ({
        entitlementId: String(r.o_entitlement_id),
        trailId: String(r.o_trail_id),
        state: String(r.o_state),
        playerHandle: textOrNull(r.o_player_handle),
        activatedAt: isoOrNull(r.o_activated_at),
        voucherIssuedAt: isoOrNull(r.o_voucher_issued_at),
      }));
    },
    async mintHandover(facilityId: string, entitlementId: string, tokenHash: string): Promise<HandoverMintResult> {
      const rows = await trx`
        select o_status, o_expires_at
        from private.partner_handover_mint_for_partner(${facilityId}::text, ${entitlementId}::uuid, ${tokenHash}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !HANDOVER_MINT_STATUSES.has(r.o_status)) throw new Error("partner_handover_mint_for_partner returned no usable status");
      return { status: r.o_status as HandoverMintStatus, expiresAt: isoOrNull(r.o_expires_at) };
    },
    async redeem(facilityId: string, entitlementId: string, method: RedeemMethod, credential: string): Promise<RedeemResult> {
      const rows = await trx`
        select o_status, o_attestation_id::text as o_attestation_id, o_movement, o_availability
        from private.partner_entitlement_redeem_for_partner(${facilityId}::text, ${entitlementId}::uuid, ${method}::text, ${credential}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !REDEEM_STATUSES.has(r.o_status)) throw new Error("partner_entitlement_redeem_for_partner returned no usable status");
      return { status: r.o_status as RedeemStatus, attestationId: textOrNull(r.o_attestation_id), movement: textOrNull(r.o_movement), availability: textOrNull(r.o_availability) };
    },
    async voucher(facilityId: string, entitlementId: string): Promise<VoucherResult> {
      const rows = await trx`
        select o_status, o_voucher_issued_at
        from private.partner_entitlement_voucher_for_partner(${facilityId}::text, ${entitlementId}::uuid)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !VOUCHER_STATUSES.has(r.o_status)) throw new Error("partner_entitlement_voucher_for_partner returned no usable status");
      return { status: r.o_status as VoucherStatus, voucherIssuedAt: isoOrNull(r.o_voucher_issued_at) };
    },
  };
}

const COURSE_PIN_SHOW_STATUSES: ReadonlySet<string> = new Set(["ok", "no_facility", "no_programme"]);
const COURSE_QR_REFRESH_STATES: ReadonlySet<string> = new Set(["live", "used", "expired", "unknown"]);
const COURSE_QR_PRINT_WRITE_STATUSES: ReadonlySet<string> = new Set(["ok", "no_facility", "kid_mismatch", "key_mismatch", "key_revoked"]);

/** The course-QR staff definers of the bound lane (0055). Every one is a `select private.*(...)` matching the migration's argument order; the signing key (`o_signing_key`) is read into a local and returned to the one caller that signs. */
function buildCourseQrTx(trx: TxSql): CourseQrTx {
  return {
    async pinShow(facilityId: string): Promise<CoursePinShowResult> {
      const rows = await trx`
        select o_status, o_pin, o_local_date::text as o_local_date, o_valid_until, o_pin_epoch::int as o_pin_epoch
        from private.course_pin_show_for_partner(${facilityId}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !COURSE_PIN_SHOW_STATUSES.has(r.o_status)) throw new Error("course_pin_show_for_partner returned no usable status");
      if (r.o_status === "no_facility") return { status: "no_facility" };
      if (r.o_status === "no_programme") return { status: "no_programme" };
      const validUntil = isoOrNull(r.o_valid_until);
      if (typeof r.o_pin !== "string" || typeof r.o_local_date !== "string" || validUntil === null) throw new Error("course_pin_show_for_partner returned ok without a PIN");
      return { status: "ok", dailyPin: r.o_pin, localDate: r.o_local_date, validUntil, pinEpoch: Number(r.o_pin_epoch) };
    },
    async pinRotate(facilityId: string): Promise<CoursePinRotateResult> {
      const rows = await trx`select o_status, o_pin_epoch::int as o_pin_epoch from private.course_pin_rotate_for_partner(${facilityId}::text)`;
      const r = rows[0];
      if (r?.o_status === "ok") return { status: "ok", pinEpoch: Number(r.o_pin_epoch) };
      if (r?.o_status === "no_programme") return { status: "no_programme" };
      throw new Error("course_pin_rotate_for_partner returned no usable status");
    },
    async mint(facilityId: string, nonceHash: string): Promise<CourseQrMintResult> {
      const rows = await trx`
        select o_status, o_kid, o_signing_key, o_public_key, o_issued_at::text as o_issued_at, o_expires_at::text as o_expires_at
        from private.course_qr_mint_for_partner(${facilityId}::text, ${nonceHash}::text)`;
      const r = rows[0];
      if (r?.o_status === "no_programme") return { status: "no_programme" };
      if (r?.o_status !== "ok" || typeof r.o_kid !== "string" || typeof r.o_signing_key !== "string" || typeof r.o_public_key !== "string") throw new Error("course_qr_mint_for_partner returned no usable row");
      return { status: "ok", kid: r.o_kid, signingKey: r.o_signing_key, publicKey: r.o_public_key, issuedAt: Number(r.o_issued_at), expiresAt: Number(r.o_expires_at) };
    },
    async refresh(facilityId: string, nonceHash: string): Promise<CourseQrRefreshResult> {
      const rows = await trx`select o_state, o_seconds_left::int as o_seconds_left from private.course_qr_refresh_for_partner(${facilityId}::text, ${nonceHash}::text)`;
      const r = rows[0];
      if (typeof r?.o_state !== "string" || !COURSE_QR_REFRESH_STATES.has(r.o_state)) throw new Error("course_qr_refresh_for_partner returned no usable state");
      return { state: r.o_state as CourseQrRefreshResult["state"], secondsLeft: Number(r.o_seconds_left) };
    },
    async printKey(facilityId: string): Promise<CourseQrPrintKeyResult> {
      const rows = await trx`select o_status, o_kid, o_signing_key, o_public_key, o_slug from private.course_qr_print_key_for_partner(${facilityId}::text)`;
      const r = rows[0];
      if (r?.o_status === "no_facility") return { status: "no_facility" };
      if (r?.o_status === "key_revoked") return { status: "key_revoked" };
      if (r?.o_status !== "ok" || typeof r.o_kid !== "string" || typeof r.o_signing_key !== "string" || typeof r.o_slug !== "string") throw new Error("course_qr_print_key_for_partner returned no usable row");
      return { status: "ok", kid: r.o_kid, signingKey: r.o_signing_key, publicKey: textOrNull(r.o_public_key), slug: r.o_slug };
    },
    async printWrite(facilityId: string, qrKid: string, sig: string, publicKey: string): Promise<CourseQrPrintWriteResult> {
      const rows = await trx`select o_status, o_changed from private.course_qr_print_write_for_partner(${facilityId}::text, ${qrKid}::text, ${sig}::text, ${publicKey}::text)`;
      const r = rows[0];
      if (typeof r?.o_status !== "string" || !COURSE_QR_PRINT_WRITE_STATUSES.has(r.o_status)) throw new Error("course_qr_print_write_for_partner returned no usable status");
      return { status: r.o_status as CourseQrPrintWriteResult["status"], changed: r.o_changed === true };
    },
    async printRead(facilityId: string): Promise<CourseQrPrintReadResult> {
      const rows = await trx`select o_status, o_qr_kid, o_sig, o_printed_at, o_revoked_at from private.course_qr_print_read_for_partner(${facilityId}::text)`;
      const r = rows[0];
      if (r?.o_status === "no_facility") return { status: "no_facility" };
      if (r?.o_status === "not_printed") return { status: "not_printed" };
      const printedAt = isoOrNull(r?.o_printed_at);
      if (r?.o_status !== "ok" || typeof r.o_qr_kid !== "string" || typeof r.o_sig !== "string" || printedAt === null) throw new Error("course_qr_print_read_for_partner returned no usable row");
      return { status: "ok", qrKid: r.o_qr_kid, sig: r.o_sig, printedAt, revokedAt: isoOrNull(r.o_revoked_at) };
    },
  };
}

/** The partner sign-in minter's transaction (kind "partner_mint": the ONE caller of that kind, the lint's `privileged-mint-scope` rule keeps it so). */
export async function withPartnerMint<T>(op: (m: PartnerMintTx & PartnerInviteMintTx) => Promise<T>): Promise<T> {
  try {
    return await openScopedTx("partner_mint", { expectedUid: null }, (trx) => op(buildPartnerMintTx(trx)));
  } catch (err) {
    return mapPartnerDbError(err);
  }
}

const PARTNER_TOKEN_HASH = /^[0-9a-f]{64}$/;

/** A transaction as `edge_partner`, bound to the session whose token hash this is. A malformed hash is refused without a database round trip, with the same error as an unknown one. */
export async function withPartnerSession<T>(
  tokenHash: string,
  op: (
    s: PartnerSessionTx & PartnerInvitesTx & PartnerMembersTx & PartnerAttestTx & PartnerReviewTx & PartnerStockTx & PartnerEntitlementsTx & PartnerProgrammeTx & PartnerOffersAdminTx & PartnerSponsorshipsTx & PartnerOffersRedeemTx & PartnerSettlementExportTx & CourseQrTx,
  ) => Promise<T>,
): Promise<T> {
  if (!PARTNER_TOKEN_HASH.test(tokenHash)) throw new PartnerSessionRefused();
  try {
    return await openScopedTx("partner", partnerBind(tokenHash), (trx) =>
      op({
        ...buildPartnerSessionTx(trx),
        ...buildPartnerInvitesTx(trx),
        ...buildPartnerMembersTx(trx),
        ...buildPartnerAttestTx(trx),
        ...buildPartnerReviewTx(trx),
        ...buildPartnerStockTx(trx),
        ...buildPartnerEntitlementsTx(trx),
        ...buildPartnerProgrammeTx(trx),
        ...buildPartnerOffersAdminTx(trx),
        ...buildPartnerSponsorshipsTx(trx),
        ...buildPartnerOffersRedeemTx(trx),
        ...buildPartnerSettlementExportTx(trx),
        ...buildCourseQrTx(trx),
      }),
    );
  } catch (err) {
    return mapPartnerDbError(err);
  }
}

/** One hit of `private.hit_partner_rate_limit` in its OWN short transaction, committed before the request's own transaction opens; the decision is made here from the returned count (the database never raises over the cap, 0020). */
export async function hitRateLimitForPartner(tokenHash: string, bucketKey: string, windowSeconds: number, max: number): Promise<{ ok: boolean; retryAfterSeconds: number }> {
  if (!PARTNER_TOKEN_HASH.test(tokenHash)) throw new PartnerSessionRefused();
  let count: number;
  try {
    count = await openScopedTx("partner", partnerBind(tokenHash), async (trx) => {
      const rows = await trx`select private.hit_partner_rate_limit(${bucketKey}, ${windowSeconds + " seconds"}::interval, ${max}::int) as count`;
      return Number(rows[0]?.count ?? 0);
    });
  } catch (err) {
    return mapPartnerDbError(err);
  }
  return count > max ? { ok: false, retryAfterSeconds: windowSeconds } : { ok: true, retryAfterSeconds: 0 };
}

/** One hit of a SYSTEM bucket (partner design 8: before authentication nothing is bound, so the buckets keyed on the invite token and the target mailbox are `edge_system` buckets), in its OWN short transaction. */
async function hitSystemRateLimitForPartner(bucketKey: string, windowSeconds: number, max: number): Promise<{ ok: boolean; retryAfterSeconds: number }> {
  const r = await hitSystemRateLimit(bucketKey, windowSeconds, max);
  return r.ok ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: r.retryAfterSeconds ?? windowSeconds };
}

/** The partner database port the `partner-session`, `partner-invites` and `partner-members` entrypoints hand the pure handlers. */
export const partnerDb: PartnerDb = {
  withMint: withPartnerMint,
  withInviteMint: withPartnerMint,
  withSession: withPartnerSession,
  withInvites: withPartnerSession,
  withMembers: withPartnerSession,
  withAttest: withPartnerSession,
  withReview: withPartnerSession,
  withStock: withPartnerSession,
  withEntitlements: withPartnerSession,
  withProgramme: withPartnerSession,
  withOffersAdmin: withPartnerSession,
  withSponsorships: withPartnerSession,
  withOffersRedeem: withPartnerSession,
  withSettlementExport: withPartnerSession,
  hitRateLimit: hitRateLimitForPartner,
  hitSystemRateLimit: hitSystemRateLimitForPartner,
};

/** The database port the `course-qr` and `qr-print` entrypoints hand the pure handlers (S2b, 0055): the same bound transaction as `partnerDb.withSession`, typed for the course-QR definers. */
export const courseQrDb: CourseQrDb = {
  withCourseQr: withPartnerSession,
  hitRateLimit: hitRateLimitForPartner,
};

/**
 * The origin of the universal links a course QR carries (`https://golfraven.<tld>/q/m#<token>`, `/q/f/<slug>#<kid>.<sig>`): `GR_COURSE_QR_LINK_ORIGIN`, an exact https origin. Unset: null (the responses then carry
 * no link; the token and the signature are the same). Malformed: throws, at boot, rather than print a link nobody meant.
 */
export function loadCourseQrLinkOrigin(): string | null {
  return parseAllowedOrigin(Deno.env.get("GR_COURSE_QR_LINK_ORIGIN"));
}

/** The anon-key Auth client's one call the partner lane needs to SEND a one-time code: the email OTP. A proof and an enrolment token go to an account that already exists (`shouldCreateUser` false); only an INVITE may create the account of the address it names. */
export interface OtpSendClient {
  auth: { signInWithOtp(args: { email: string; options: { shouldCreateUser: boolean } }): Promise<{ error: { status?: number } | null }> };
}

/** Builds the sender over a client factory (the real one below; a recording fake in the integration suite). A failure THROWS (the handler decides what to say: nothing about the account or the mailer is ever shown). */
export function makePartnerEmailOtpSender(newClient: () => OtpSendClient, shouldCreateUser: boolean = false): (email: string) => Promise<void> {
  return async (email: string): Promise<void> => {
    const { error } = await newClient().auth.signInWithOtp({ email, options: { shouldCreateUser } });
    if (error) throw new Error("supabase auth signInWithOtp failed");
  };
}

function newPartnerOtpSendClient(): OtpSendClient {
  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) throw new Error("privileged.ts: SUPABASE_URL/SUPABASE_ANON_KEY are not set in this environment");
  return createClient(url, anonKey, { auth: { autoRefreshToken: false, persistSession: false } }) as unknown as OtpSendClient;
}

const sendPartnerEmailOtp = makePartnerEmailOtpSender(newPartnerOtpSendClient);
const sendPartnerInviteEmailOtp = makePartnerEmailOtpSender(newPartnerOtpSendClient, true);

/** Builds the proof's email-OTP port over a sender and a verifier (the real ones below; recording fakes in the integration suite). */
export function makePartnerEmailOtp(send: (email: string) => Promise<void>, verifier: { verify(email: string, code: string): ReturnType<EmailOtpPort["verify"]> }): EmailOtpPort {
  return { send, verify: (email, code) => verifier.verify(email, code) };
}

/** The partner proof's email OTP: GoTrue with the ANON key, as the player flow does it (E19). The code is mailed to the member's OWN address only (the handler takes it from the database, never from the client). */
export const partnerEmailOtp: EmailOtpPort = makePartnerEmailOtp(sendPartnerEmailOtp, supabaseEmailOtpVerifier);

/**
 * The email OTP of an INVITE (6.1 branch N): the same GoTrue call, but the invitee has no account yet, so the account of the address the invite names is created by the send. The address is the invite row's (the handler
 * takes it from the database, never from the client), so a token holder cannot cause an account to be created for an address of their choosing. The enrolment-token OTP is `partnerEmailOtp`: that person exists.
 */
export const partnerInviteEmailOtp: EmailOtpPort = makePartnerEmailOtp(sendPartnerInviteEmailOtp, supabaseEmailOtpVerifier);

/**
 * The ONE origin the partner lane allows (partner design 4.6): `GR_PARTNER_ORIGIN`, an exact https origin. It lives in the environment, not in `app.partner_rp_config`, because `OPTIONS` must answer
 * without opening a database connection (PA-10). The handler compares it with `partner_rp_config.origin` on every database path and answers 503 on a mismatch, so the two copies cannot drift apart.
 * Unset: null (the lane then refuses every request that carries an Origin, and every database path answers 503). Malformed: throws, at boot, rather than run with an origin nobody meant.
 */
export function loadPartnerCorsOrigin(): string | null {
  return parseAllowedOrigin(Deno.env.get("GR_PARTNER_ORIGIN"));
}
// ============================================================================
// PARTNER LANE (S1.2) END
// ============================================================================
