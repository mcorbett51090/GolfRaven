// supabase/tests/unit/course-qr-fakes.ts
//
// An in-memory `CourseQrDb` for the S2b handler suites (course-qr-handler.test.ts, qr-print-handler.test.ts): the SEMANTICS of the 0055 definers that the handlers depend on, not their SQL (that is
// supabase/tests/matrix/33_course_qr_staff.sql, and supabase/tests/integration/course-qr.deno.test.ts runs the real thing). What it models, because a handler test that did not would pass over a broken seam:
//   * a transaction is a SNAPSHOT: `withCourseQr` copies the state, and a throw inside the callback RESTORES it (so a refused mint gives the PIN grant back and leaves no token row, as Postgres does);
//   * an A1 mint consumes the single-use PIN grant and writes a token row, and a missing grant or scope is `PartnerAuthorityRefused` (42501);
//   * the Vault seed and the registered public key come from `state`, exactly as the definer releases them (the seed is on the mint result and nowhere else);
//   * a refresh is a read of the person's OWN token and never advances `lastSeenAt` (PA-26).
// Everything here is test-only; nothing under supabase/functions imports it.

import { base64UrlEncode } from "../../functions/_shared/course-qr/format.ts";
import { publicKeyOfSeed } from "../../functions/_shared/partner/course-qr-signer.ts";
import {
  type CourseQrDb,
  type CourseQrMintResult,
  type CourseQrPrintKeyResult,
  type CourseQrPrintReadResult,
  type CourseQrPrintWriteResult,
  type CourseQrRefreshResult,
  type CourseQrTx,
  PartnerAuthorityRefused,
  PartnerSessionRefused,
} from "../../functions/_shared/partner/ports.ts";

export const FACILITY = "fac_x";
export const OTHER_FACILITY = "fac_y";

export interface TokenRow {
  nonceHash: string;
  facilityId: string;
  issuedAt: number;
  usedAt: number | null;
}

export interface CourseQrState {
  /** The facilities the bound person has scope at (staff or manager for the course-qr routes; operator or admin for qr-print). */
  scope: Set<string>;
  /** A single-use PIN grant (class A1). */
  grant: boolean;
  /** Is there a passkey window and a fresh PIN (class A2)? */
  a2: boolean;
  /** aal 2 and a fresh TOTP (class A3). */
  a3: boolean;
  /** The programme answers (`no_programme`) for a facility. */
  programme: boolean;
  /** The Vault secrets and the registered key. */
  rotatingSeed: string;
  rotatingKid: string;
  rotatingPublicKey: string | null;
  printedSeed: string;
  printedKid: string;
  printedPublicKey: string | null;
  printedKeyRevoked: boolean;
  /** The facility's printed QR. */
  printed: { kid: string; sig: string; printedAt: string; revokedAt: string | null } | null;
  tokens: TokenRow[];
  lastSeenAt: number;
  bindRefused: boolean;
  rateLimitOk: boolean;
  slug: string;
  nowS: number;
}

export interface CourseQrWorld {
  readonly db: CourseQrDb;
  readonly state: CourseQrState;
  /** Every port call in order (`db.hitRateLimit`, `db.withCourseQr`, and the transaction's methods). */
  readonly calls: string[];
  readonly transactions: { committed: boolean }[];
  readonly rateLimitHits: { bucket: string; windowSeconds: number; max: number }[];
  /** The seeds (what the Vault would hold) and their public keys, for the tests' own verification. */
  readonly keys: { rotatingPublic: string; printedPublic: string };
}

export async function makeSeed(): Promise<string> {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

export async function makeCourseQrWorld(over: Partial<CourseQrState> = {}): Promise<CourseQrWorld> {
  const rotatingSeed = await makeSeed();
  const printedSeed = await makeSeed();
  const rotatingPublic = await publicKeyOfSeed(rotatingSeed);
  const printedPublic = await publicKeyOfSeed(printedSeed);
  const state: CourseQrState = {
    scope: new Set([FACILITY]),
    grant: true,
    a2: true,
    a3: true,
    programme: true,
    rotatingSeed,
    rotatingKid: "kidrot1",
    rotatingPublicKey: rotatingPublic,
    printedSeed,
    printedKid: "kidprt1",
    printedPublicKey: null,
    printedKeyRevoked: false,
    printed: null,
    tokens: [],
    lastSeenAt: 1_000,
    bindRefused: false,
    rateLimitOk: true,
    slug: "facility-x",
    nowS: 1_900_000_000,
    ...over,
  };
  const calls: string[] = [];
  const transactions: { committed: boolean }[] = [];
  const rateLimitHits: { bucket: string; windowSeconds: number; max: number }[] = [];

  const scope = (facilityId: string): void => {
    if (!state.scope.has(facilityId)) throw new PartnerAuthorityRefused();
  };

  const tx: CourseQrTx = {
    async pinShow(facilityId) {
      calls.push("tx.pinShow");
      scope(facilityId);
      state.lastSeenAt = state.nowS; // an A0 call is interactive: it advances idle
      if (!state.programme) return { status: "no_programme" };
      return { status: "ok", dailyPin: "4821", localDate: "2030-01-01", validUntil: "2030-01-02T06:00:00.000Z", pinEpoch: 0 };
    },
    async pinRotate(facilityId) {
      calls.push("tx.pinRotate");
      scope(facilityId);
      if (!state.a2) throw new PartnerAuthorityRefused();
      state.a2 = false;
      if (!state.programme) return { status: "no_programme" };
      return { status: "ok", pinEpoch: 1 };
    },
    async mint(facilityId, nonceHash): Promise<CourseQrMintResult> {
      calls.push("tx.mint");
      scope(facilityId);
      if (!state.grant) throw new PartnerAuthorityRefused();
      state.grant = false;
      state.lastSeenAt = state.nowS;
      if (!state.programme) return { status: "no_programme" };
      if (state.rotatingPublicKey === null) throw new PartnerAuthorityRefused();
      state.tokens.push({ nonceHash, facilityId, issuedAt: state.nowS, usedAt: null });
      return { status: "ok", kid: state.rotatingKid, signingKey: state.rotatingSeed, publicKey: state.rotatingPublicKey, issuedAt: state.nowS, expiresAt: state.nowS + 120 };
    },
    async refresh(facilityId, nonceHash): Promise<CourseQrRefreshResult> {
      calls.push("tx.refresh");
      scope(facilityId);
      // A0_KEEPALIVE: never touches lastSeenAt, never writes
      const t = state.tokens.find((x) => x.nonceHash === nonceHash && x.facilityId === facilityId);
      if (t === undefined) return { state: "unknown", secondsLeft: 0 };
      if (t.usedAt !== null) return { state: "used", secondsLeft: 0 };
      const left = 120 - (state.nowS - t.issuedAt);
      return left <= 0 ? { state: "expired", secondsLeft: 0 } : { state: "live", secondsLeft: left };
    },
    async printKey(facilityId): Promise<CourseQrPrintKeyResult> {
      calls.push("tx.printKey");
      scope(facilityId);
      if (!state.a3) throw new PartnerAuthorityRefused();
      if (state.printedKeyRevoked) return { status: "key_revoked" };
      return { status: "ok", kid: state.printedKid, signingKey: state.printedSeed, publicKey: state.printedPublicKey, slug: state.slug };
    },
    async printWrite(facilityId, qrKid, sig, publicKey): Promise<CourseQrPrintWriteResult> {
      calls.push("tx.printWrite");
      scope(facilityId);
      if (!state.a3) throw new PartnerAuthorityRefused();
      if (qrKid !== state.printedKid) return { status: "kid_mismatch", changed: false };
      if (state.printedPublicKey !== null && state.printedPublicKey !== publicKey) return { status: "key_mismatch", changed: false };
      if (state.printedKeyRevoked) return { status: "key_revoked", changed: false };
      state.printedPublicKey = publicKey;
      if (state.printed !== null && state.printed.kid === qrKid && state.printed.sig === sig && state.printed.revokedAt === null) return { status: "ok", changed: false };
      state.printed = { kid: qrKid, sig, printedAt: "2030-01-01T12:00:00.000Z", revokedAt: null };
      return { status: "ok", changed: true };
    },
    async printRead(facilityId): Promise<CourseQrPrintReadResult> {
      calls.push("tx.printRead");
      scope(facilityId);
      if (state.printed === null) return { status: "not_printed" };
      return { status: "ok", qrKid: state.printed.kid, sig: state.printed.sig, printedAt: state.printed.printedAt, revokedAt: state.printed.revokedAt };
    },
  };

  const db: CourseQrDb = {
    async withCourseQr(_hash, op) {
      calls.push("db.withCourseQr");
      if (state.bindRefused) throw new PartnerSessionRefused();
      // a transaction is a snapshot: a throw restores it
      const snapshot = { ...state, scope: new Set(state.scope), tokens: state.tokens.map((t) => ({ ...t })), printed: state.printed === null ? null : { ...state.printed } };
      try {
        const r = await op(tx);
        transactions.push({ committed: true });
        return r;
      } catch (err) {
        Object.assign(state, snapshot);
        transactions.push({ committed: false });
        throw err;
      }
    },
    async hitRateLimit(_hash, bucket, windowSeconds, max) {
      calls.push("db.hitRateLimit");
      rateLimitHits.push({ bucket, windowSeconds, max });
      if (state.bindRefused) throw new PartnerSessionRefused();
      return state.rateLimitOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: 3600 };
    },
  };

  return { db, state, calls, transactions, rateLimitHits, keys: { rotatingPublic, printedPublic } };
}
