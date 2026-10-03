// supabase/tests/unit/fake-signin-repo.ts
//
// In-memory implementations of `SigninRepo` and `RevocationDb` for the pure sign-in handlers. They MIRROR the semantics of
// the 0035 definers (private.signin_link_identity / signin_store_token / signin_unlink_identity / signin_enqueue_revocations /
// claim_signin_revocations / complete_signin_revocation) — same refusals, same SQLSTATE-to-HTTP mapping, same idempotency — and
// the Deno integration suite (supabase/tests/integration/signin-methods.deno.test.ts) runs the SAME scenarios against the real
// SQL, which is what keeps this fake honest. State hangs off the shared `FakeState` through a WeakMap, so fake-repo.ts needs
// nothing beyond mounting `signin` and calling `deleteSigninRows` from its own deleteMyData.

import { Errors, HttpError } from "../../functions/_shared/http.ts";
import type { Envelope, Kek } from "../../functions/_shared/signin/envelope.ts";
import { sha256Hex, toHex } from "../../functions/_shared/signin/bytes.ts";
import { NotConfiguredError } from "../../functions/_shared/signin/errors.ts";
import type { ClaimedRevocation, EmailProofInput, EmailProofMinter, LinkIdentityInput, RevocationDb, RevocationJob, SigninMethodRow, SigninRepo } from "../../functions/_shared/signin/types.ts";
import type { FakeState } from "./fake-repo.ts";

export interface FakeIdentity {
  userId: string;
  provider: string;
  subject: string;
  email: string | null;
  isPrivateRelay: boolean;
  linkedAt: string;
}
export interface FakeToken {
  userId: string;
  provider: string;
  envelope: Envelope;
}
export interface FakeQueueRow {
  id: string;
  provider: string;
  source: string;
  fingerprint: string;
  envelope: Envelope | null;
  status: "pending" | "revoked" | "expired";
  attempts: number;
  lastError: string | null;
  nextAttemptAtMs: number;
  expiresAtMs: number;
}
/** A row of private.signin_email_proof (0039): the hashes, never the address or the subject. */
export interface FakeProof {
  id: string;
  callerUserId: string;
  targetUserId: string;
  provider: string;
  emailHash: string;
  subHash: string;
  /** The GoTrue session the proof is bound to (0041, (b)). */
  sessionId: string;
  expiresAtMs: number;
  consumed: boolean;
}
/** A row of auth.sessions: who it belongs to and when GoTrue created it, in ms. */
export interface FakeSession {
  userId: string;
  createdMs: number;
}
export interface SigninFake {
  identities: FakeIdentity[];
  /** private.signin_email_proof (0039). */
  proofs: FakeProof[];
  /** auth.users.last_sign_in_at (GoTrue's stamp), per user id, in ms. The minter refuses unless it is within 60 s of the fake clock. */
  lastSignInMs: Map<string, number>;
  /** auth.sessions (0041): the sessions verifyOtp created and that nobody has signed out yet, by id. */
  sessions: Map<string, FakeSession>;
  /** lower-cased email -> user id (auth.users.email). */
  accounts: Map<string, string>;
  tokens: FakeToken[];
  queue: FakeQueueRow[];
  /** kek id -> key, in creation order (the last is the newest). */
  keks: Map<string, Uint8Array>;
  /** Every database-affecting call in order, for ordering assertions ("enqueue before delete"). */
  calls: string[];
  nextId: number;
  /** Fail the next call of this name with this error (one shot). */
  failNext: Map<string, unknown>;
  otpFailures: Map<string, number>;
}

const fakes = new WeakMap<FakeState, SigninFake>();

export function signinFake(state: FakeState): SigninFake {
  let f = fakes.get(state);
  if (!f) {
    f = { identities: [], proofs: [], lastSignInMs: new Map(), sessions: new Map(), accounts: new Map(), tokens: [], queue: [], keks: new Map(), calls: [], nextId: 1, failNext: new Map(), otpFailures: new Map() };
    fakes.set(state, f);
  }
  return f;
}

export function addAccount(state: FakeState, userId: string, email: string, extraProviders: Array<{ provider: string; subject: string }> = []): void {
  const f = signinFake(state);
  f.accounts.set(email.toLowerCase(), userId);
  f.identities.push({ userId, provider: "email", subject: email.toLowerCase(), email: email.toLowerCase(), isPrivateRelay: false, linkedAt: state.now.toISOString() });
  for (const p of extraProviders) f.identities.push({ userId, provider: p.provider, subject: p.subject, email: email.toLowerCase(), isPrivateRelay: false, linkedAt: state.now.toISOString() });
}

export function addKek(state: FakeState, kekId: string): Kek {
  const key = crypto.getRandomValues(new Uint8Array(32));
  signinFake(state).keks.set(kekId, key);
  return { kekId, key };
}

/** What private.delete_my_data does to the user's grant rows (and ONLY to them: the queue is untouched, by design) and, since 0039, to the proofs
 * the account is a party to. */
export function deleteSigninRows(state: FakeState, userId: string): void {
  const f = signinFake(state);
  f.calls.push(`delete_my_data:${userId}`);
  f.tokens = f.tokens.filter((t) => t.userId !== userId);
  f.proofs = f.proofs.filter((p) => p.callerUserId !== userId && p.targetUserId !== userId);
}

/** GoTrue stamps auth.users.last_sign_in_at when verifyOtp issues its session; a test calls this the way the real verifier's side effect would. */
export function stampSignIn(state: FakeState, userId: string, atMs: number = state.now.getTime()): void {
  signinFake(state).lastSignInMs.set(userId, atMs);
}

/** What verifyOtp leaves behind besides the stamp: a live GoTrue session of the proven account (auth.sessions), returned by id. */
export function addSession(state: FakeState, userId: string, atMs: number = state.now.getTime()): string {
  const f = signinFake(state);
  const id = `00000000-0000-4000-a000-${String(f.nextId++).padStart(12, "0")}`;
  f.sessions.set(id, { userId, createdMs: atMs });
  return id;
}

const fingerprint = (e: Envelope) => toHex(e.ciphertext);

function maybeFail(f: SigninFake, name: string): void {
  const e = f.failNext.get(name);
  if (e !== undefined) {
    f.failNext.delete(name);
    throw e;
  }
}

function enqueueInternal(state: FakeState, userId: string, provider: string | null, source: string): RevocationJob[] {
  const f = signinFake(state);
  const jobs: RevocationJob[] = [];
  for (const t of f.tokens.filter((x) => x.userId === userId && (provider === null || x.provider === provider))) {
    const fp = fingerprint(t.envelope);
    let row = f.queue.find((q) => q.provider === t.provider && q.fingerprint === fp);
    if (!row) {
      row = { id: `00000000-0000-4000-8000-${String(f.nextId++).padStart(12, "0")}`, provider: t.provider, source, fingerprint: fp, envelope: t.envelope, status: "pending", attempts: 0, lastError: null, nextAttemptAtMs: state.now.getTime(), expiresAtMs: state.now.getTime() + 72 * 3600_000 };
      f.queue.push(row);
    }
    if (row.status === "pending") jobs.push({ queueId: row.id, provider: row.provider });
  }
  return jobs;
}

/** The database's ONE normalisation (0041, L2): lower(btrim(x)), btrim stripping SPACES only. The fake mirrors it so a unit test cannot pass on JavaScript's wider trim(). */
const normEmail = (e: string) => e.replace(/^ +/, "").replace(/ +$/, "").toLowerCase();

/** Mirrors private.signin_record_email_proof (0039 / 0041): the address must match the TARGET's own (the database's lower(btrim())), the target must have signed in
 * within 60 s, AND a session with the given id must exist for the target, created within 60 s and not already used by a proof; caller and target differ. It runs in
 * its own transaction as edge_signin_minter, so it is not a SigninRepo method. */
export function makeFakeEmailProofs(state: FakeState): EmailProofMinter {
  const f = signinFake(state);
  const refused = () => Errors.conflict("email_proof_refused", "that email proof cannot be used; request a new code and try again");
  return {
    async record(input: EmailProofInput): Promise<string> {
      f.calls.push(`proof.record:${input.callerUserId}->${input.targetUserId}`);
      maybeFail(f, "proof.record");
      if (input.callerUserId === input.targetUserId) throw Errors.internal();
      const targetEmail = [...f.accounts.entries()].find(([, id]) => id === input.targetUserId)?.[0] ?? null;
      if (targetEmail === null || normEmail(targetEmail) !== normEmail(input.email)) throw refused();
      const last = f.lastSignInMs.get(input.targetUserId);
      if (last === undefined || Math.abs(state.now.getTime() - last) > 60_000) throw refused();
      const session = f.sessions.get(input.sessionId);
      if (!session || session.userId !== input.targetUserId || Math.abs(state.now.getTime() - session.createdMs) > 60_000) throw refused();
      if (f.proofs.some((p) => p.sessionId === input.sessionId)) throw refused();
      const id = `00000000-0000-4000-9000-${String(f.nextId++).padStart(12, "0")}`;
      f.proofs.push({
        id,
        callerUserId: input.callerUserId,
        targetUserId: input.targetUserId,
        provider: input.provider,
        emailHash: await sha256Hex(normEmail(input.email)),
        subHash: await sha256Hex(`${input.provider}:${input.subject}`),
        sessionId: input.sessionId,
        expiresAtMs: state.now.getTime() + 5 * 60_000,
        consumed: false,
      });
      return id;
    },
  };
}

export function makeFakeSigninRepo(state: FakeState, uid: string): SigninRepo {
  const f = signinFake(state);
  const methodsOf = (u: string): SigninMethodRow[] =>
    f.identities
      .filter((i) => i.userId === u)
      .map((i) => ({ provider: i.provider, subject: i.subject, email: i.email, isPrivateRelay: i.isPrivateRelay, linkedAt: i.linkedAt, hasToken: f.tokens.some((t) => t.userId === u && t.provider === i.provider) }));
  const newestKek = (): Kek => {
    const entries = [...f.keks.entries()];
    const last = entries[entries.length - 1];
    if (!last) throw new NotConfiguredError("kek_missing");
    return { kekId: last[0], key: last[1] };
  };
  /** The direct core path (private.signin_link_identity) on `target`, shared by linkIdentity and the proof-bound link. */
  const linkCore = (target: string, input: LinkIdentityInput): boolean => {
    const owner = f.identities.find((i) => i.provider === input.provider && i.subject === input.subject);
    if (owner) {
      if (owner.userId === target) return false;
      throw Errors.conflict("identity_conflict", "that sign-in identity is already linked to another account");
    }
    if (f.identities.some((i) => i.userId === target && i.provider === input.provider)) {
      throw Errors.conflict("provider_already_linked", "this account already has a different identity linked for that provider");
    }
    f.identities.push({ userId: target, provider: input.provider, subject: input.subject, email: input.email, isPrivateRelay: input.isPrivateRelay, linkedAt: state.now.toISOString() });
    return true;
  };
  const storeCore = (target: string, provider: string, envelope: Envelope): void => {
    if (!f.identities.some((i) => i.userId === target && i.provider === provider)) throw Errors.notFound("that sign-in method is not linked");
    const existing = f.tokens.find((t) => t.userId === target && t.provider === provider);
    if (existing && fingerprint(existing.envelope) !== fingerprint(envelope)) enqueueInternal(state, target, provider, "replaced");
    f.tokens = f.tokens.filter((t) => !(t.userId === target && t.provider === provider));
    f.tokens.push({ userId: target, provider, envelope });
  };
  /** Direct (uid-taking) writes: only the caller's own account, as privileged.ts#mustBeSelf. */
  const mustBeSelf = (target: string) => {
    if (target !== uid) throw new HttpError(403, "cross_account_link_requires_proof", "an identity is linked to another account only through a verified email proof");
  };
  return {
    async listMethods() {
      f.calls.push("listMethods");
      maybeFail(f, "listMethods");
      return methodsOf(uid);
    },
    async findAccountByEmail(email) {
      f.calls.push("findAccountByEmail");
      return f.accounts.get(email.trim().toLowerCase()) ?? null;
    },
    async linkIdentity(target: string, input: LinkIdentityInput) {
      f.calls.push(`linkIdentity:${target}`);
      maybeFail(f, "linkIdentity");
      mustBeSelf(target);
      return linkCore(target, input);
    },
    async storeToken(target, provider, envelope) {
      f.calls.push(`storeToken:${target}`);
      maybeFail(f, "storeToken");
      mustBeSelf(target);
      storeCore(target, provider, envelope);
    },
    /** Mirrors private.signin_link_identity_with_proof_for_actor (0039): redeems the proof (unconsumed, unexpired, issued to THIS caller, for this
     * provider / subject hash / address hash, the target's address still the proven one) and links + stores for the PROOF's target, never `uid`. */
    async linkIdentityWithProof(proofId, input, envelope) {
      f.calls.push(`linkIdentityWithProof:${proofId}`);
      maybeFail(f, "linkIdentityWithProof");
      const refused = () => Errors.conflict("email_proof_refused", "that email proof cannot be used; request a new code and try again");
      const proof = f.proofs.find((p) => p.id === proofId);
      if (!proof || proof.consumed || proof.expiresAtMs <= state.now.getTime() || proof.callerUserId !== uid) throw refused();
      if (!input.emailVerified || input.isPrivateRelay || input.email === null) throw Errors.internal();
      if (proof.provider !== input.provider || proof.subHash !== (await sha256Hex(`${input.provider}:${input.subject}`))) throw refused();
      const emailHash = await sha256Hex(normEmail(input.email));
      if (proof.emailHash !== emailHash) throw refused();
      const targetEmail = [...f.accounts.entries()].find(([, id]) => id === proof.targetUserId)?.[0] ?? null;
      if (targetEmail === null || (await sha256Hex(normEmail(targetEmail))) !== emailHash) throw refused();
      // one transaction: a refusal below leaves the proof unconsumed (the definer's exception rolls the UPDATE back)
      const snapshot = { identities: [...f.identities], tokens: [...f.tokens], queue: f.queue.map((q) => ({ ...q })) };
      try {
        proof.consumed = true;
        const created = linkCore(proof.targetUserId, input);
        storeCore(proof.targetUserId, input.provider, envelope);
        return created;
      } catch (e) {
        proof.consumed = false;
        f.identities = snapshot.identities;
        f.tokens = snapshot.tokens;
        f.queue = snapshot.queue;
        throw e;
      }
    },
    async unlinkIdentity(provider) {
      f.calls.push(`unlinkIdentity:${provider}`);
      maybeFail(f, "unlinkIdentity");
      if (!f.identities.some((i) => i.userId === uid && i.provider === provider)) throw Errors.notFound("that sign-in method is not linked");
      const providers = new Set(f.identities.filter((i) => i.userId === uid).map((i) => i.provider));
      if (providers.size <= 1) throw Errors.unprocessable("last_sign_in_method", "the only remaining sign-in method cannot be unlinked");
      const jobs = enqueueInternal(state, uid, provider, "unlink");
      f.tokens = f.tokens.filter((t) => !(t.userId === uid && t.provider === provider));
      f.identities = f.identities.filter((i) => !(i.userId === uid && i.provider === provider));
      return jobs.map((j) => j.queueId);
    },
    async enqueueRevocations() {
      f.calls.push("enqueueRevocations");
      maybeFail(f, "enqueueRevocations");
      return enqueueInternal(state, uid, null, "account_delete");
    },
    async currentKek() {
      f.calls.push("currentKek");
      return newestKek();
    },
    async kekById(kekId) {
      const key = f.keks.get(kekId);
      if (!key) throw new NotConfiguredError("kek_missing");
      return { kekId, key };
    },
    system: {
      ...makeFakeRevocationDb(state),
      async peekOtpFailures(h) {
        return f.otpFailures.get(h) ?? 0;
      },
      async reserveOtpAttempt(h) {
        const n = f.otpFailures.get(h) ?? 0;
        const windowStart = "2030-01-01T00:00:00.000Z";
        if (n >= 5) return { attempts: -1, windowStart };
        f.otpFailures.set(h, n + 1);
        return { attempts: n + 1, windowStart };
      },
      async releaseOtpAttempt(h, _windowStart) {
        f.otpFailures.set(h, Math.max(0, (f.otpFailures.get(h) ?? 0) - 1));
      },
      async purgeEmailProofs() {
        const before = f.proofs.length;
        f.proofs = f.proofs.filter((p) => p.expiresAtMs >= state.now.getTime() - 3600_000);
        return before - f.proofs.length;
      },
    },
  };
}

export function makeFakeRevocationDb(state: FakeState): RevocationDb {
  const f = signinFake(state);
  return {
    async claim(ids, limit, leaseSeconds): Promise<ClaimedRevocation[]> {
      f.calls.push("claim");
      maybeFail(f, "claim");
      const now = state.now.getTime();
      for (const q of f.queue) if (q.status === "pending" && q.expiresAtMs <= now) Object.assign(q, { status: "expired", envelope: null, lastError: q.lastError ?? "expired_unrevoked" });
      const due = f.queue.filter((q) => q.status === "pending" && q.nextAttemptAtMs <= now && (ids === null || ids.includes(q.id))).slice(0, limit);
      for (const q of due) q.nextAttemptAtMs = now + leaseSeconds * 1000;
      return due.map((q) => ({ id: q.id, provider: q.provider, envelope: q.envelope!, attempts: q.attempts, expiresAt: new Date(q.expiresAtMs).toISOString() }));
    },
    async complete(id, outcome, errorCode, backoffSeconds) {
      f.calls.push(`complete:${outcome}`);
      maybeFail(f, "complete");
      const q = f.queue.find((r) => r.id === id);
      if (!q) throw new Error("no such queue row");
      if (q.status !== "pending") return q.status;
      q.attempts += 1;
      if (outcome === "revoked") {
        Object.assign(q, { status: "revoked", envelope: null, lastError: null });
        return "revoked";
      }
      q.lastError = errorCode && /^[a-z0-9_:.-]{1,64}$/.test(errorCode) ? errorCode : "unclassified";
      q.nextAttemptAtMs = state.now.getTime() + Math.min(Math.max(backoffSeconds, 30), 21600) * 1000;
      return "pending";
    },
    async kekById(kekId) {
      const key = f.keks.get(kekId);
      if (!key) throw new NotConfiguredError("kek_missing");
      return { kekId, key };
    },
    async purge() {
      return 0;
    },
  };
}
