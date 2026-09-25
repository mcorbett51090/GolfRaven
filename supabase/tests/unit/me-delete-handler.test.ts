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

  it("reads signin/connector providers BEFORE deletion and returns a deferred revocation outcome for each (the P4/P8 seam)", async () => {
    const state = makeFakeState({
      signinProviders: new Map([["user-a", ["apple", "google"]]]),
      connectorProviders: new Map([["user-a", ["ghin"]]]),
    });
    const repo = makeFakeRepo(state, "user-a");

    const result = await handleMeDelete(repo);

    expect(result.signinProvidersRevoked).toHaveLength(2);
    expect(result.signinProvidersRevoked.map((r) => r.provider).sort()).toEqual(["apple", "google"]);
    expect(result.signinProvidersRevoked.every((r) => r.deferred === true && r.revoked === false)).toBe(true);
    expect(result.connectorsRevoked).toHaveLength(1);
    expect(result.connectorsRevoked[0].provider).toBe("ghin");
    expect(result.connectorsRevoked[0].deferred).toBe(true);
  });

  it("returns no revocation outcomes for an actor with no provider grants", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleMeDelete(repo);
    expect(result.signinProvidersRevoked).toEqual([]);
    expect(result.connectorsRevoked).toEqual([]);
  });
});
