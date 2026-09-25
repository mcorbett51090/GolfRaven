// supabase/tests/unit/me-export-handler.test.ts
//
// Unit tests for _shared/me/export-handler.ts against the in-memory fake
// Repo — real-DB coverage (private.export_my_data itself, the registry
// -driven table set) lives in supabase/tests/matrix/14_me_export.sql and
// supabase/tests/integration/me-handlers.deno.test.ts.

import { describe, expect, it } from "vitest";
import { handleMeExport } from "../../functions/_shared/me/export-handler.js";
import { makeFakeRepo, makeFakeState } from "./fake-repo.js";

describe("handleMeExport", () => {
  it("returns the actor's own data, wrapped in an envelope with generatedAt/userId", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await repo.device.ensureOwn("dev-a", "ios");
    await repo.pushToken.upsert("dev-a", "ExponentPushToken[a]");

    const result = await handleMeExport(repo, "user-a");

    expect(result.userId).toBe("user-a");
    expect(typeof result.generatedAt).toBe("string");
    const device = result.data.device as Array<Record<string, unknown>>;
    expect(device.some((r) => r.id === "dev-a")).toBe(true);
    const pushToken = result.data.push_token as Array<Record<string, unknown>>;
    expect(pushToken.some((r) => r.deviceId === "dev-a")).toBe(true);
  });

  it("never includes another actor's rows", async () => {
    const state = makeFakeState();
    const repoA = makeFakeRepo(state, "user-a");
    const repoB = makeFakeRepo(state, "user-b");
    await repoB.device.ensureOwn("dev-b", "ios");

    const resultA = await handleMeExport(repoA, "user-a");
    const deviceA = resultA.data.device as Array<Record<string, unknown>>;
    expect(deviceA.some((r) => r.id === "dev-b")).toBe(false);
  });

  it("returns an empty (but present) array for a table the actor has no rows in", async () => {
    // makeFakeState()'s own default fixture seeds ONE device for
    // "user-a" (fake-repo.ts's own doc) — evidence/push_token have no
    // such default, so those are the tables this test checks are empty
    // arrays (present as keys, never omitted) rather than device.
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleMeExport(repo, "user-a");
    expect(result.data.evidence).toEqual([]);
    expect(result.data.push_token).toEqual([]);
  });
});
