// The revocation runner (revocation.ts) and the DELETE /v1/me orchestration (delete-orchestrator.ts), against the fake queue.

import { describe, expect, it } from "vitest";
import { EnvelopeError, NotConfiguredError, VendorUnavailableError } from "../../functions/_shared/signin/errors.ts";
import { backoffSeconds, MAX_BACKOFF_SECONDS, runRevocations, runRevocationsBestEffort, toErrorCode, type RevocationDeps } from "../../functions/_shared/signin/revocation.ts";
import { encryptToken } from "../../functions/_shared/signin/envelope.ts";
import { orchestrateMeDelete } from "../../functions/_shared/me/delete-orchestrator.ts";
import type { GoogleRevokePort } from "../../functions/_shared/signin/types.ts";
import { makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.ts";
import { addAccount, addKek, makeFakeRevocationDb, signinFake } from "./fake-signin-repo.ts";

const ALICE = "aaaaaaaa-0000-4000-8000-000000000001";
const BOB = "bbbbbbbb-0000-4000-8000-000000000002";

interface H {
  state: FakeState;
  deps: RevocationDeps;
  apple: { revoked: string[]; error: unknown; seenGrantRowsAtRevoke: number[] };
  google: { revoked: string[]; error: unknown };
  log: Array<Record<string, unknown>>;
}

async function harness(): Promise<H> {
  const state = makeFakeState();
  const kek = addKek(state, "k1");
  addAccount(state, ALICE, "alice@example.test", [{ provider: "apple", subject: "a-alice" }, { provider: "google", subject: "g-alice" }]);
  addAccount(state, BOB, "bob@example.test", [{ provider: "apple", subject: "a-bob" }]);
  const f = signinFake(state);
  f.tokens.push({ userId: ALICE, provider: "apple", envelope: await encryptToken("r.apple-alice", "apple", kek) });
  f.tokens.push({ userId: ALICE, provider: "google", envelope: await encryptToken("g.google-alice", "google", kek) });
  f.tokens.push({ userId: BOB, provider: "apple", envelope: await encryptToken("r.apple-bob", "apple", kek) });
  const apple: H["apple"] = { revoked: [], error: null, seenGrantRowsAtRevoke: [] };
  const google: H["google"] = { revoked: [], error: null };
  const log: H["log"] = [];
  const googlePort: GoogleRevokePort = {
    async revokeToken(t) {
      google.revoked.push(t);
      if (google.error) throw google.error;
    },
  };
  const deps: RevocationDeps = {
    db: makeFakeRevocationDb(state),
    apple: {
      async revokeRefreshToken(t) {
        apple.revoked.push(t);
        apple.seenGrantRowsAtRevoke.push(f.tokens.filter((x) => x.userId === ALICE).length);
        if (apple.error) throw apple.error;
      },
    },
    google: googlePort,
    log: (e) => log.push(e),
  };
  return { state, deps, apple, google, log };
}

const aliceRepo = (h: H) => makeFakeRepo(h.state, ALICE);

describe("toErrorCode / backoff", () => {
  it("reduces every error to the queue's alphabet and never carries free text", () => {
    expect(toErrorCode(new VendorUnavailableError("revoke_5xx"))).toBe("revoke_5xx");
    expect(toErrorCode(new NotConfiguredError("apple_siwa_key"))).toBe("not_configured_apple_siwa_key");
    expect(toErrorCode(new EnvelopeError("authentication_failed"))).toBe("envelope_authentication_failed");
    expect(toErrorCode(new Error("Bearer ey.SECRET with spaces"))).toBe("unexpected");
    expect(toErrorCode(new VendorUnavailableError("Weird Code! With Spaces"))).toMatch(/^[a-z0-9_:.-]{1,64}$/);
    expect(toErrorCode(new VendorUnavailableError("x".repeat(200))).length).toBe(64);
  });

  it("backs off 1 min, 2, 4 ... capped at 6 h", () => {
    expect([0, 1, 2, 3].map(backoffSeconds)).toEqual([60, 120, 240, 480]);
    expect(backoffSeconds(40)).toBe(MAX_BACKOFF_SECONDS);
    expect(backoffSeconds(-5)).toBe(60);
  });
});

describe("runRevocations", () => {
  it("revokes each queued grant at ITS provider with the DECRYPTED token, closes the row and wipes its material", async () => {
    const h = await harness();
    await aliceRepo(h).signin.enqueueRevocations();
    const out = await runRevocations(h.deps, {});
    expect(out.map((o) => [o.provider, o.status]).sort()).toEqual([["apple", "revoked"], ["google", "revoked"]]);
    expect(h.apple.revoked).toEqual(["r.apple-alice"]);
    expect(h.google.revoked).toEqual(["g.google-alice"]);
    const q = signinFake(h.state).queue;
    expect(q.every((r) => r.status === "revoked" && r.envelope === null)).toBe(true);
    expect(JSON.stringify(h.log)).not.toContain("apple-alice");
    expect(JSON.stringify(h.log)).not.toContain("google-alice");
  });

  it("never touches a grant that was not queued (Bob's)", async () => {
    const h = await harness();
    await aliceRepo(h).signin.enqueueRevocations();
    await runRevocations(h.deps, {});
    expect(h.apple.revoked).not.toContain("r.apple-bob");
  });

  it("a provider failure is recorded as a short code, the row stays pending with a backed-off next attempt, and the outcome says queued_for_retry", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    await aliceRepo(h).signin.enqueueRevocations();
    const out = await runRevocations(h.deps, {});
    expect(out.find((o) => o.provider === "apple")).toEqual({ queueId: expect.any(String), provider: "apple", status: "queued_for_retry", error: "revoke_5xx" });
    const row = signinFake(h.state).queue.find((r) => r.provider === "apple")!;
    expect(row).toMatchObject({ status: "pending", attempts: 1, lastError: "revoke_5xx" });
    expect(row.nextAttemptAtMs).toBe(h.state.now.getTime() + 60_000);
    expect(row.envelope).not.toBeNull();
    expect(h.log.find((e) => e.provider === "apple")).toMatchObject({ event: "signin_revocation", outcome: "retry", attempts: 1, error: "revoke_5xx" });
  });

  it("the retry happens on a LATER run once the backoff has passed, and succeeds (retried for 72 h)", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    await aliceRepo(h).signin.enqueueRevocations();
    await runRevocations(h.deps, {});
    expect(await runRevocations(h.deps, {})).toHaveLength(0); // inside the backoff / lease: nothing is due
    h.apple.error = null;
    h.state.now = new Date(h.state.now.getTime() + 3 * 3600_000);
    const out = await runRevocations(h.deps, {});
    expect(out.map((o) => [o.provider, o.status])).toEqual([["apple", "revoked"]]);
    expect(h.apple.revoked).toEqual(["r.apple-alice", "r.apple-alice"]);
  });

  it("after 72 h an unrevoked row is expired, its credential material wiped, and it is never attempted again", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    await aliceRepo(h).signin.enqueueRevocations();
    await runRevocations(h.deps, {});
    h.state.now = new Date(h.state.now.getTime() + 73 * 3600_000);
    h.apple.revoked.length = 0;
    expect(await runRevocations(h.deps, {})).toHaveLength(0);
    expect(h.apple.revoked).toHaveLength(0);
    const row = signinFake(h.state).queue.find((r) => r.provider === "apple")!;
    expect(row).toMatchObject({ status: "expired", envelope: null, lastError: "revoke_5xx" });
  });

  it("Apple UNCONFIGURED: the attempt is recorded as not_configured_apple and the row stays pending (never marked revoked)", async () => {
    const h = await harness();
    h.deps.apple = null;
    await aliceRepo(h).signin.enqueueRevocations();
    const out = await runRevocations(h.deps, {});
    expect(out.find((o) => o.provider === "apple")).toMatchObject({ status: "queued_for_retry", error: "not_configured_apple" });
    expect(signinFake(h.state).queue.find((r) => r.provider === "apple")!.status).toBe("pending");
    expect(out.find((o) => o.provider === "google")!.status).toBe("revoked"); // one provider's gap does not stall the other
  });

  it("the Vault KEK gone, or the wrong KEK: recorded, never revoked, never thrown", async () => {
    const h = await harness();
    await aliceRepo(h).signin.enqueueRevocations();
    signinFake(h.state).keks.clear();
    const gone = await runRevocations(h.deps, {});
    expect(gone.every((o) => o.status === "queued_for_retry" && o.error === "not_configured_kek_missing")).toBe(true);
    // wrong key under the same id
    const f = signinFake(h.state);
    f.keks.set("k1", crypto.getRandomValues(new Uint8Array(32)));
    h.state.now = new Date(h.state.now.getTime() + 3 * 3600_000);
    const wrong = await runRevocations(h.deps, {});
    expect(wrong.every((o) => o.error === "envelope_authentication_failed")).toBe(true);
    expect(h.apple.revoked).toHaveLength(0);
  });

  it("if the bookkeeping write fails after the provider was told, the outcome is the truthful 'not recorded' and a later run repeats it harmlessly", async () => {
    const h = await harness();
    await aliceRepo(h).signin.enqueueRevocations();
    signinFake(h.state).failNext.set("complete", new Error("db unwell"));
    const out = await runRevocations(h.deps, {});
    expect(out.filter((o) => o.status === "queued_for_retry")).toHaveLength(1);
    expect(h.apple.revoked.length + h.google.revoked.length).toBe(2);
  });

  it("only the named ids are attempted when ids are given", async () => {
    const h = await harness();
    const jobs = await aliceRepo(h).signin.enqueueRevocations();
    const only = jobs.find((j) => j.provider === "google")!;
    const out = await runRevocations(h.deps, { ids: [only.queueId] });
    expect(out.map((o) => o.provider)).toEqual(["google"]);
    expect(h.apple.revoked).toEqual([]);
  });
});

describe("runRevocationsBestEffort never throws", () => {
  it("a claim failure becomes queued_for_retry for every job, and is logged", async () => {
    const h = await harness();
    const jobs = await aliceRepo(h).signin.enqueueRevocations();
    signinFake(h.state).failNext.set("claim", new Error("db down"));
    const out = await runRevocationsBestEffort(h.deps, jobs);
    expect(out).toHaveLength(2);
    expect(out.every((o) => o.status === "queued_for_retry" && o.error === "not_attempted")).toBe(true);
    expect(h.log.some((e) => e.outcome === "claim_failed")).toBe(true);
  });

  it("no jobs: no database call at all", async () => {
    const h = await harness();
    expect(await runRevocationsBestEffort(h.deps, [])).toEqual([]);
    expect(signinFake(h.state).calls).not.toContain("claim");
  });
});

describe("DELETE /v1/me orchestration (queue, revoke, then delete)", () => {
  function deleteDeps(h: H) {
    return { withRepo: <T>(op: (r: ReturnType<typeof makeFakeRepo>) => Promise<T>) => op(makeFakeRepo(h.state, ALICE)), revocation: h.deps };
  }

  it("revokes BOTH grants at the providers with the right tokens BEFORE the provider rows are deleted, then deletes", async () => {
    const h = await harness();
    const out = await orchestrateMeDelete(deleteDeps(h));
    expect(h.apple.revoked).toEqual(["r.apple-alice"]);
    expect(h.google.revoked).toEqual(["g.google-alice"]);
    // at the moment Apple was called, Alice's grant rows still existed (revocation precedes deletion)
    expect(h.apple.seenGrantRowsAtRevoke).toEqual([2]);
    const calls = signinFake(h.state).calls;
    expect(calls.indexOf("enqueueRevocations")).toBeLessThan(calls.indexOf("claim"));
    expect(calls.indexOf("claim")).toBeLessThan(calls.indexOf(`delete_my_data:${ALICE}`));
    expect(signinFake(h.state).tokens.filter((t) => t.userId === ALICE)).toHaveLength(0);
    expect(signinFake(h.state).tokens.filter((t) => t.userId === BOB)).toHaveLength(1);
    expect(out.userId).toBe(ALICE);
    expect(out.signinProvidersRevoked.map((o) => [o.provider, o.status]).sort()).toEqual([["apple", "revoked"], ["google", "revoked"]]);
  });

  it("F6: a grant stored AFTER the first enqueue (a link racing the deletion) is queued inside the delete transaction and revoked, never deleted unqueued", async () => {
    const h = await harness();
    const f = signinFake(h.state);
    f.tokens = f.tokens.filter((t) => !(t.userId === ALICE && t.provider === "google"));
    const realApple = h.deps.apple!;
    let injected = false;
    h.deps.apple = {
      async revokeRefreshToken(t) {
        await realApple.revokeRefreshToken(t);
        if (!injected) {
          injected = true; // the racing link: a Google grant stored while Apple was being told
          f.tokens.push({ userId: ALICE, provider: "google", envelope: await encryptToken("g.late-grant", "google", { kekId: "k1", key: f.keks.get("k1")! }) });
        }
      },
    };
    const out = await orchestrateMeDelete(deleteDeps(h));
    expect(h.google.revoked).toEqual(["g.late-grant"]);
    expect(f.tokens.filter((t) => t.userId === ALICE)).toHaveLength(0);
    expect(out.signinProvidersRevoked.map((o) => [o.provider, o.status]).sort()).toEqual([["apple", "revoked"], ["google", "revoked"]]);
    const calls = f.calls;
    const deleteAt = calls.indexOf(`delete_my_data:${ALICE}`);
    expect(calls.slice(0, deleteAt).filter((c) => c === "enqueueRevocations")).toHaveLength(2); // the second one is in the delete transaction
  });

  it("a FAILED revocation never blocks the deletion: the account is deleted, the grant stays queued with its envelope, and the error is logged", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    const out = await orchestrateMeDelete(deleteDeps(h));
    expect(h.state.deletedUsers.has(ALICE)).toBe(true);
    expect(signinFake(h.state).tokens.filter((t) => t.userId === ALICE)).toHaveLength(0);
    const apple = signinFake(h.state).queue.find((q) => q.provider === "apple")!;
    expect(apple.status).toBe("pending");
    expect(apple.envelope).not.toBeNull(); // the retry has what it needs although the grant row is gone
    expect(out.signinProvidersRevoked.find((o) => o.provider === "apple")).toMatchObject({ status: "queued_for_retry", error: "revoke_5xx" });
    expect(h.log.some((e) => e.event === "signin_revocation" && e.outcome === "retry" && e.provider === "apple")).toBe(true);
  });

  it("the retry (a later drain run) then revokes the grant of the ALREADY-DELETED account", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    await orchestrateMeDelete(deleteDeps(h));
    h.apple.error = null;
    h.state.now = new Date(h.state.now.getTime() + 2 * 3600_000);
    const out = await runRevocations(h.deps, {});
    expect(out.map((o) => [o.provider, o.status])).toEqual([["apple", "revoked"]]);
    expect(h.apple.revoked.at(-1)).toBe("r.apple-alice");
  });

  it("Apple unconfigured (no key) never blocks deletion either: queued as not_configured_apple", async () => {
    const h = await harness();
    h.deps.apple = null;
    const out = await orchestrateMeDelete(deleteDeps(h));
    expect(h.state.deletedUsers.has(ALICE)).toBe(true);
    expect(out.signinProvidersRevoked.find((o) => o.provider === "apple")).toMatchObject({ status: "queued_for_retry", error: "not_configured_apple" });
  });

  it("an account with no stored grant deletes without any revocation attempt", async () => {
    const h = await harness();
    signinFake(h.state).tokens = [];
    const out = await orchestrateMeDelete(deleteDeps(h));
    expect(out.signinProvidersRevoked).toEqual([]);
    expect(signinFake(h.state).calls).not.toContain("claim");
    expect(h.state.deletedUsers.has(ALICE)).toBe(true);
  });

  it("a retry of the whole request after partial failure completes and adds no second queue row (idempotent)", async () => {
    const h = await harness();
    h.apple.error = new VendorUnavailableError("revoke_5xx");
    // first attempt dies AFTER enqueue + revoke attempts, before the delete commits
    const f = signinFake(h.state);
    const jobs = await aliceRepo(h).signin.enqueueRevocations();
    await runRevocationsBestEffort(h.deps, jobs);
    const rowsBefore = f.queue.length;
    await orchestrateMeDelete(deleteDeps(h));
    expect(f.queue).toHaveLength(rowsBefore);
    expect(h.state.deletedUsers.has(ALICE)).toBe(true);
    // and a SECOND full retry on the already-deleted account is a clean no-op
    const again = await orchestrateMeDelete(deleteDeps(h));
    expect(again.signinProvidersRevoked).toEqual([]);
  });

  it("if the ENQUEUE itself fails (a database error, not a revocation failure) nothing is deleted and the error surfaces", async () => {
    const h = await harness();
    signinFake(h.state).failNext.set("enqueueRevocations", new Error("db down"));
    await expect(orchestrateMeDelete(deleteDeps(h))).rejects.toThrow("db down");
    expect(h.state.deletedUsers.has(ALICE)).toBe(false);
    expect(signinFake(h.state).tokens.filter((t) => t.userId === ALICE)).toHaveLength(2);
  });
});
