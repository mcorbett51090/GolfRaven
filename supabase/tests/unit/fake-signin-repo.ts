// supabase/tests/unit/fake-signin-repo.ts
//
// In-memory implementations of `SigninRepo` and `RevocationDb` for the pure sign-in handlers. They MIRROR the semantics of
// the 0035 definers (private.signin_link_identity / signin_store_token / signin_unlink_identity / signin_enqueue_revocations /
// claim_signin_revocations / complete_signin_revocation) — same refusals, same SQLSTATE-to-HTTP mapping, same idempotency — and
// the Deno integration suite (supabase/tests/integration/signin-methods.deno.test.ts) runs the SAME scenarios against the real
// SQL, which is what keeps this fake honest. State hangs off the shared `FakeState` through a WeakMap, so fake-repo.ts needs
// nothing beyond mounting `signin` and calling `deleteSigninRows` from its own deleteMyData.

import { Errors } from "../../functions/_shared/http.ts";
import type { Envelope, Kek } from "../../functions/_shared/signin/envelope.ts";
import { toHex } from "../../functions/_shared/signin/bytes.ts";
import { NotConfiguredError } from "../../functions/_shared/signin/errors.ts";
import type { ClaimedRevocation, LinkIdentityInput, RevocationDb, RevocationJob, SigninMethodRow, SigninRepo } from "../../functions/_shared/signin/types.ts";
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
export interface SigninFake {
  identities: FakeIdentity[];
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
    f = { identities: [], accounts: new Map(), tokens: [], queue: [], keks: new Map(), calls: [], nextId: 1, failNext: new Map(), otpFailures: new Map() };
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

/** What private.delete_my_data does to the user's grant rows (and ONLY to them: the queue is untouched, by design). */
export function deleteSigninRows(state: FakeState, userId: string): void {
  const f = signinFake(state);
  f.calls.push(`delete_my_data:${userId}`);
  f.tokens = f.tokens.filter((t) => t.userId !== userId);
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

export function makeFakeSigninRepo(state: FakeState, uid: string, opts: { crossAccountLink?: boolean } = {}): SigninRepo {
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
  return {
    crossAccountLink: opts.crossAccountLink ?? true,
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
    },
    async storeToken(target, provider, envelope) {
      f.calls.push(`storeToken:${target}`);
      maybeFail(f, "storeToken");
      if (!f.identities.some((i) => i.userId === target && i.provider === provider)) throw Errors.notFound("that sign-in method is not linked");
      const existing = f.tokens.find((t) => t.userId === target && t.provider === provider);
      if (existing && fingerprint(existing.envelope) !== fingerprint(envelope)) enqueueInternal(state, target, provider, "replaced");
      f.tokens = f.tokens.filter((t) => !(t.userId === target && t.provider === provider));
      f.tokens.push({ userId: target, provider, envelope });
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
      async recordOtpFailure(h) {
        const n = (f.otpFailures.get(h) ?? 0) + 1;
        f.otpFailures.set(h, n);
        return n;
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
