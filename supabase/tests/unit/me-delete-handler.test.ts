// supabase/tests/unit/me-delete-handler.test.ts
//
// Unit tests for _shared/me/delete-handler.ts against the in-memory fake
// Repo (fake-repo.ts) — the pure-logic half of `DELETE /v1/me` (real-DB
// coverage, including private.delete_my_data itself, lives in
// supabase/tests/integration/me-handlers.deno.test.ts).

import { describe, expect, it } from "vitest";
import { handleMeDelete } from "../../functions/_shared/me/delete-handler.js";
import { makeFakeRepo, makeFakeState } from "./fake-repo.js";

describe("handleMeDelete", () => {
  it("calls Repo#me.deleteMyData() and returns its result", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleMeDelete(repo);
    expect(result.userId).toBe("user-a");
    expect(state.deletedUsers.has("user-a")).toBe(true);
  });

  it("removes the actor's own evidence/device/push_token rows (AT 6: 'removes all personal rows... deletes push tokens')", async () => {
    const state = makeFakeState();
    const repoA = makeFakeRepo(state, "user-a");
    await repoA.device.ensureOwn("dev-a", "ios");
    await repoA.pushToken.upsert("dev-a", "ExponentPushToken[a]");
    await repoA.evidence.insertIdempotent({
      sourceRef: "sr-a",
      inputHash: "hash-a",
      source: "self_report",
      facilityId: "fac_x",
      courseId: null,
      startedAt: null,
      endedAt: null,
      localDate: "2026-06-01",
      summary: {},
      integrity: {},
      cosignal: {},
      attestationGrade: "unattestable",
      matcherVersion: null,
      catalogVersion: 1,
      status: "accepted",
      deviceId: "dev-a",
    });

    await handleMeDelete(repoA);

    expect([...state.evidence.values()].some((r) => r.userId === "user-a")).toBe(false);
    expect([...state.devices.values()].some((r) => r.userId === "user-a")).toBe(false);
    expect([...state.pushTokens.values()].some((r) => r.userId === "user-a")).toBe(false);
  });

  it("never touches a different actor's rows (cross-user isolation)", async () => {
    const state = makeFakeState();
    const repoA = makeFakeRepo(state, "user-a");
    const repoB = makeFakeRepo(state, "user-b");
    await repoA.device.ensureOwn("dev-a", "ios");
    await repoB.device.ensureOwn("dev-b", "ios");
    await repoB.pushToken.upsert("dev-b", "ExponentPushToken[b]");

    await handleMeDelete(repoA);

    expect([...state.devices.values()].some((r) => r.userId === "user-b")).toBe(true);
    expect([...state.pushTokens.values()].some((r) => r.userId === "user-b")).toBe(true);
  });

  it("is idempotent: a second call for an already-deleted actor does not throw and still reports success", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await repo.device.ensureOwn("dev-a", "ios");

    const first = await handleMeDelete(repo);
    expect(first.userId).toBe("user-a");

    const second = await handleMeDelete(repo);
    expect(second.userId).toBe("user-a");
  });

  it("reads connector providers BEFORE deletion and returns a deferred outcome for each (the P8 seam); the sign-in outcomes are the ones the orchestrator passed in (O12)", async () => {
    const state = makeFakeState({
      signinProviders: new Map([["user-a", ["apple", "google"]]]),
      connectorProviders: new Map([["user-a", ["ghin"]]]),
    });
    const repo = makeFakeRepo(state, "user-a");
    const signin = [
      { queueId: "q1", provider: "apple", status: "revoked" as const },
      { queueId: "q2", provider: "google", status: "queued_for_retry" as const, error: "revoke_5xx" },
    ];

    const result = await handleMeDelete(repo, signin);

    // handled by delete-orchestrator.ts BEFORE this handler runs: passed through verbatim, never recomputed or deferred here
    expect(result.signinProvidersRevoked).toEqual(signin);
    expect(result.connectorsRevoked).toHaveLength(1);
    expect(result.connectorsRevoked[0].provider).toBe("ghin");
    expect(result.connectorsRevoked[0].deferred).toBe(true);
  });

  it("without an orchestrator outcome (a direct call) the sign-in outcome list is empty, not a fabricated 'deferred' marker", async () => {
    const state = makeFakeState({ signinProviders: new Map([["user-a", ["apple"]]]) });
    const result = await handleMeDelete(makeFakeRepo(state, "user-a"));
    expect(result.signinProvidersRevoked).toEqual([]);
  });

  it("returns no revocation outcomes for an actor with no provider grants", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleMeDelete(repo);
    expect(result.signinProvidersRevoked).toEqual([]);
    expect(result.connectorsRevoked).toEqual([]);
  });
});
