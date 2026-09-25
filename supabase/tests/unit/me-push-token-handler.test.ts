// supabase/tests/unit/me-push-token-handler.test.ts
//
// Unit tests for _shared/me/push-token-handler.ts against the in-memory
// fake Repo — real-DB coverage (the ON CONFLICT upsert, the real
// app.push_token PK) lives in supabase/tests/integration/me-handlers.deno.test.ts.

import { describe, expect, it } from "vitest";
import { handlePushTokenRequest } from "../../functions/_shared/me/push-token-handler.js";
import { makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { HttpError } from "../../functions/_shared/http.js";

describe("handlePushTokenRequest", () => {
  it("registers a token for a new device", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handlePushTokenRequest({ deviceId: "dev-new", expoToken: "ExponentPushToken[abc]", platform: "ios" }, repo);
    expect(result.deviceId).toBe("dev-new");
    expect(state.pushTokens.get("user-a:dev-new")?.expoToken).toBe("ExponentPushToken[abc]");
  });

  it("replaces the token on re-registration (reinstall) — 'register or update'", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await handlePushTokenRequest({ deviceId: "dev-a", expoToken: "ExponentPushToken[first]" }, repo);
    await handlePushTokenRequest({ deviceId: "dev-a", expoToken: "ExponentPushToken[second]" }, repo);
    expect(state.pushTokens.size).toBe(1);
    expect(state.pushTokens.get("user-a:dev-a")?.expoToken).toBe("ExponentPushToken[second]");
  });

  it("rejects an empty expoToken", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    await expect(handlePushTokenRequest({ deviceId: "dev-a", expoToken: "" }, repo)).rejects.toThrow(HttpError);
  });

  it("rejects an expoToken over the length bound", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    const tooLong = "x".repeat(513);
    await expect(handlePushTokenRequest({ deviceId: "dev-a", expoToken: tooLong }, repo)).rejects.toThrow(HttpError);
  });

  it("rejects a non-printable-ASCII expoToken", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    await expect(handlePushTokenRequest({ deviceId: "dev-a", expoToken: "abc\x00def" }, repo)).rejects.toThrow(HttpError);
  });

  it("enforces the device cap (MAX_DEVICES_PER_USER) BEFORE creating a new device row — cap the number of tokens per user", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    for (let i = 0; i < 20; i++) await repo.device.ensureOwn(`dev-${i}`, "ios");

    let caught: unknown;
    try {
      await handlePushTokenRequest({ deviceId: "dev-21st", expoToken: "ExponentPushToken[cap]" }, repo);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).code).toBe("device_limit_exceeded");
    expect(state.devices.has("dev-21st")).toBe(false); // the rejected request must never create the device row it's about to reject
    expect(state.pushTokens.has("user-a:dev-21st")).toBe(false);
  });

  it("does NOT re-check the cap when re-registering a token for an ALREADY-owned device, even at the cap", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    for (let i = 0; i < 20; i++) await repo.device.ensureOwn(`dev-${i}`, "ios");

    // dev-0 already exists — updating its token must succeed even though
    // the account is already at the device cap.
    const result = await handlePushTokenRequest({ deviceId: "dev-0", expoToken: "ExponentPushToken[updated]" }, repo);
    expect(result.deviceId).toBe("dev-0");
  });
});
