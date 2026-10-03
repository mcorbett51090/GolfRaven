/**
 * The REAL `@supabase/auth-js` 2.65.0 (`src/auth/supabase-auth.ts`) against a fake GoTrue, in Node. What this proves: the calls the app makes
 * (OTP request, OTP verify, native id-token exchange with the RAW nonce, refresh, logout), that the session — access AND refresh token — lands in
 * the SECURE store under one key and nowhere else, that restore/refresh work from that store alone, and the error mapping.
 * What it does not prove: that a real GoTrue answers like this fake, or anything about React Native / Hermes.
 */
import { describe, expect, it } from "vitest";
import { createSupabaseAuth, mapAuthError } from "../src/auth/supabase-auth";
import { AuthError } from "../src/auth";
import { BrokenSecureStore, MemorySecureStore, SESSION_STORAGE_KEY } from "../src/secure";
import { createFakeGoTrue, sessionBody, type FakeGoTrue } from "./support/gotrue";

const URL_ = "https://proj.supabase.co";
// A PUBLIC-shaped placeholder; the fake ignores it. Not a real key.
const ANON = "sb_publishable_test_placeholder_key_000000";

function make(over: { store?: MemorySecureStore; gotrue?: FakeGoTrue } = {}) {
  const store = over.store ?? new MemorySecureStore();
  const gotrue = over.gotrue ?? createFakeGoTrue();
  const auth = createSupabaseAuth({ url: URL_, anonKey: ANON, storage: store, fetch: gotrue.fetch, refreshBudgetMs: 150, fetchTimeoutMs: 2000 });
  return { auth, store, gotrue };
}

describe("email OTP through auth-js", () => {
  it("requestEmailCode: POST /auth/v1/otp with the address and create_user; the anon key is sent as apikey, no session needed", async () => {
    const { auth, gotrue } = make();
    await auth.requestEmailCode("alice@example.test", { createUser: true });
    await auth.requestEmailCode("bob@example.test", { createUser: false });
    const [a, b] = gotrue.calls;
    expect(a).toMatchObject({ method: "POST", path: "/auth/v1/otp", body: { email: "alice@example.test", create_user: true } });
    expect(b).toMatchObject({ body: { email: "bob@example.test", create_user: false } });
    expect(a!.headers["apikey"]).toBe(ANON);
    expect(auth.current()).toBeNull(); // requesting a code (even the cross-account proof) never signs anyone in
  });

  it("verifyEmailCode: POST /verify { type: email, email, token } => a session, persisted to the secure store", async () => {
    const { auth, store, gotrue } = make();
    const s = await auth.verifyEmailCode("alice@example.test", "123456");
    expect(s).toEqual({ userId: "11111111-2222-4333-8444-555555555555", provider: "email", stub: false });
    expect(gotrue.calls.at(-1)).toMatchObject({ path: "/auth/v1/verify", body: { type: "email", email: "alice@example.test", token: "123456" } });
    expect(auth.current()).toEqual(s);
    expect(await auth.getAccessToken()).toBe("access-1");
    // the session, with its refresh token, is in the secure store
    const stored = JSON.parse((await store.get(SESSION_STORAGE_KEY))!) as { access_token: string; refresh_token: string };
    expect(stored).toMatchObject({ access_token: "access-1", refresh_token: "refresh-1" });
  });
});

describe("the session lives in the SECURE STORE only", () => {
  it("after sign-in the store holds exactly one key, and no other storage was available to be used", async () => {
    // Node has no localStorage/AsyncStorage; if auth-js had used one it would have thrown or the test would find it here.
    expect((globalThis as { localStorage?: unknown }).localStorage).toBeUndefined();
    const { auth, store } = make();
    await auth.verifyEmailCode("alice@example.test", "123456");
    expect(store.keys()).toEqual([SESSION_STORAGE_KEY]);
    expect(store.dump()).toContain("refresh-1");
  });

  it("a second client over the SAME secure store restores the session with no network call (this is how the app restarts)", async () => {
    const first = make();
    await first.auth.verifyEmailCode("alice@example.test", "123456");
    const second = make({ store: first.store });
    expect(second.auth.current()).toBeNull();
    const restored = await second.auth.restore();
    expect(restored).toMatchObject({ userId: "11111111-2222-4333-8444-555555555555" });
    expect(second.gotrue.calls).toEqual([]); // still fresh: no refresh needed
  });

  it("if the store cannot be read the app is simply signed out (and nothing throws)", async () => {
    const auth = createSupabaseAuth({ url: URL_, anonKey: ANON, storage: new BrokenSecureStore(), fetch: createFakeGoTrue().fetch });
    expect(await auth.restore()).toBeNull();
  });

  it("signOut revokes at the server (scope local) and removes the session from the store; clearLocalSession does the same with NO request", async () => {
    const a = make();
    await a.auth.verifyEmailCode("alice@example.test", "123456");
    await a.auth.signOut();
    expect(a.gotrue.calls.at(-1)).toMatchObject({ method: "POST", path: "/auth/v1/logout", query: { scope: "local" } });
    expect(a.store.keys()).toEqual([]);
    expect(a.auth.current()).toBeNull();

    const b = make();
    await b.auth.verifyEmailCode("alice@example.test", "123456");
    const before = b.gotrue.calls.length;
    await b.auth.clearLocalSession();
    expect(b.gotrue.calls).toHaveLength(before);
    expect(b.store.keys()).toEqual([]);
    expect(b.auth.current()).toBeNull();
  });

  it("signOut removes the local session even when the server is unreachable", async () => {
    const a = make();
    await a.auth.verifyEmailCode("alice@example.test", "123456");
    a.gotrue.override = () => {
      throw new TypeError("offline");
    };
    await a.auth.signOut();
    expect(a.store.keys()).toEqual([]);
  });
});

describe("native sign-in: the id token and the RAW nonce go to Auth", () => {
  it("signInWithIdToken: POST /token?grant_type=id_token { provider, id_token, nonce }", async () => {
    const { auth, gotrue, store } = make();
    const s = await auth.signInWithIdToken({ provider: "apple", idToken: "h.p.s", nonce: "raw-nonce-0123456789012345678901234567890123" });
    expect(s).toMatchObject({ provider: "apple", stub: false });
    expect(gotrue.calls.at(-1)).toMatchObject({ path: "/auth/v1/token", query: { grant_type: "id_token" }, body: { provider: "apple", id_token: "h.p.s", nonce: "raw-nonce-0123456789012345678901234567890123" } });
    expect(store.keys()).toEqual([SESSION_STORAGE_KEY]);
  });
});

describe("refresh on demand (no background timer)", () => {
  it("an expired access token is refreshed with the stored refresh token and the new session is persisted", async () => {
    const gotrue = createFakeGoTrue();
    gotrue.expiresIn = 1; // issued already (almost) expired
    const { auth, store } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.expiresIn = 3600;
    const token = await auth.getAccessToken();
    expect(token).toBe("access-2");
    expect(gotrue.calls.at(-1)).toMatchObject({ path: "/auth/v1/token", query: { grant_type: "refresh_token" }, body: { refresh_token: "refresh-1" } });
    expect(JSON.parse((await store.get(SESSION_STORAGE_KEY))!)).toMatchObject({ access_token: "access-2", refresh_token: "refresh-2" });
  });

  it("a fresh token is returned without any request; forceRefresh refreshes regardless (after a 401)", async () => {
    const { auth, gotrue } = make();
    await auth.verifyEmailCode("alice@example.test", "123456");
    const n = gotrue.calls.length;
    expect(await auth.getAccessToken()).toBe("access-1");
    expect(gotrue.calls).toHaveLength(n);
    expect(await auth.getAccessToken({ forceRefresh: true })).toBe("access-2");
    expect(gotrue.calls.at(-1)).toMatchObject({ query: { grant_type: "refresh_token" } });
  });

  it("a token that expires within the margin is refreshed BEFORE use (auth-js 2.65.0 itself only refreshes an already-expired one)", async () => {
    const gotrue = createFakeGoTrue();
    gotrue.expiresIn = 30; // < the 60 s margin
    const { auth } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.expiresIn = 3600;
    expect(await auth.getAccessToken()).toBe("access-2");
  });

  it("offline with a token that has not expired yet: the current token is used rather than failing; a forced refresh (after a 401) still fails", async () => {
    const gotrue = createFakeGoTrue();
    gotrue.expiresIn = 30;
    const { auth } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.override = (c) => {
      if (c.query["grant_type"] === "refresh_token") throw new TypeError("Network request failed");
      return null;
    };
    expect(await auth.getAccessToken()).toBe("access-1");
    await expect(auth.getAccessToken({ forceRefresh: true })).rejects.toMatchObject({ kind: "network" });
  });

  it("signed out: no token, and no request", async () => {
    const { auth, gotrue } = make();
    expect(await auth.getAccessToken()).toBeNull();
    expect(gotrue.calls).toEqual([]);
  });

  it("a refresh the server REFUSES (revoked / reused refresh token) yields no token and the session is dropped", async () => {
    const gotrue = createFakeGoTrue();
    const { auth, store } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.override = (c) => (c.query["grant_type"] === "refresh_token" ? new Response(JSON.stringify({ code: 400, error_code: "refresh_token_not_found", msg: "Invalid Refresh Token: Refresh Token Not Found" }), { status: 400, headers: { "content-type": "application/json" } }) : null);
    expect(await auth.getAccessToken({ forceRefresh: true })).toBeNull();
    expect(store.keys()).toEqual([]);
    expect(auth.current()).toBeNull();
  });

  it("a refresh that cannot REACH the server throws a network error and KEEPS the session (offline is not signed out)", async () => {
    const gotrue = createFakeGoTrue();
    const { auth, store } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.override = (c) => {
      if (c.query["grant_type"] === "refresh_token") throw new TypeError("Network request failed");
      return null;
    };
    await expect(auth.getAccessToken({ forceRefresh: true })).rejects.toMatchObject({ name: "AuthError", kind: "network" });
    expect(store.keys()).toEqual([SESSION_STORAGE_KEY]);
  });
});

describe("error mapping", () => {
  const body = (status: number, extra: Record<string, unknown>) => new Response(JSON.stringify({ code: status, ...extra }), { status, headers: { "content-type": "application/json" } });
  it.each([
    ["wrong or expired code (403 otp_expired)", body(403, { error_code: "otp_expired", msg: "Token has expired or is invalid" }), "invalid_credentials"],
    ["a refused code (422)", body(422, { error_code: "validation_failed", msg: "x" }), "invalid_credentials"],
    ["rate limited (429)", body(429, { error_code: "over_email_send_rate_limit", msg: "x" }), "rate_limited"],
    ["no such account for a proof code (422 otp_disabled)", body(422, { error_code: "otp_disabled", msg: "Signups not allowed for otp" }), "unknown_user"],
    ["server error (502)", new Response("<html>bad gateway</html>", { status: 502 }), "network"],
  ])("%s => %s", async (_name, response, kind) => {
    const { auth, gotrue } = make();
    gotrue.override = () => response.clone();
    await expect(auth.verifyEmailCode("a@example.test", "123456")).rejects.toMatchObject({ name: "AuthError", kind });
  });

  it("a transport failure is a network error and never a 'wrong code'", async () => {
    const { auth, gotrue } = make();
    gotrue.override = () => {
      throw new TypeError("Network request failed");
    };
    await expect(auth.verifyEmailCode("a@example.test", "123456")).rejects.toMatchObject({ kind: "network" });
    expect(auth.current()).toBeNull();
  });

  it("a request that never answers is aborted at the timeout and reported as a network error", async () => {
    const gotrue = createFakeGoTrue();
    gotrue.override = () => null;
    const store = new MemorySecureStore();
    const hang: typeof fetch = (_input, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    const auth = createSupabaseAuth({ url: URL_, anonKey: ANON, storage: store, fetch: hang, fetchTimeoutMs: 30 });
    await expect(auth.requestEmailCode("a@example.test", { createUser: true })).rejects.toMatchObject({ kind: "network" });
  });

  it("mapAuthError passes our own errors through and defaults to 'other'", () => {
    const e = new AuthError("rate_limited");
    expect(mapAuthError(e)).toBe(e);
    expect(mapAuthError(new Error("boom")).kind).toBe("other");
    expect(mapAuthError(null).kind).toBe("other");
  });
});

describe("subscribe", () => {
  it("is told about sign-in and sign-out", async () => {
    const { auth } = make();
    const seen: (string | null)[] = [];
    const off = auth.subscribe((s) => seen.push(s?.userId ?? null));
    await auth.verifyEmailCode("alice@example.test", "123456");
    await auth.signOut();
    off();
    await auth.verifyEmailCode("alice@example.test", "123456");
    expect(seen).toEqual(["11111111-2222-4333-8444-555555555555", null]);
  });
});

describe("getAccessToken({ forUserId }): a token is only ever handed out for the user it belongs to (the outbox's owner binding)", () => {
  const ALICE = "11111111-2222-4333-8444-555555555555";

  it("the signed-in user's own id gets the token; any other id, or no session, gets null", async () => {
    const { auth } = make();
    expect(await auth.getAccessToken({ forUserId: ALICE })).toBeNull(); // signed out
    await auth.verifyEmailCode("alice@example.test", "123456");
    expect(await auth.getAccessToken({ forUserId: ALICE })).toBe("access-1");
    expect(await auth.getAccessToken({ forUserId: "99999999-2222-4333-8444-555555555555" })).toBeNull();
    expect(await auth.getAccessToken()).toBe("access-1"); // no forUserId: unchanged behaviour
  });

  it("another user's token is never returned, and no refresh is spent on a user who does not match", async () => {
    const { auth, gotrue } = make();
    await auth.verifyEmailCode("alice@example.test", "123456");
    const n = gotrue.calls.length;
    expect(await auth.getAccessToken({ forUserId: "someone-else", forceRefresh: true })).toBeNull();
    expect(gotrue.calls).toHaveLength(n);
  });

  it("a refresh that comes back as a DIFFERENT user is not handed to the caller", async () => {
    const gotrue = createFakeGoTrue();
    gotrue.expiresIn = 1; // already about to expire, so the next call refreshes
    const { auth } = make({ gotrue });
    await auth.verifyEmailCode("alice@example.test", "123456");
    gotrue.override = (call) => {
      if (call.path !== "/auth/v1/token") return null;
      const body = sessionBody(2, "email", 3600) as { user: { id: string } };
      body.user.id = "99999999-2222-4333-8444-555555555555";
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    };
    expect(await auth.getAccessToken({ forUserId: ALICE })).toBeNull();
  });

  it("after sign-out, the previous user's id gets null", async () => {
    const { auth } = make();
    await auth.verifyEmailCode("alice@example.test", "123456");
    await auth.signOut();
    expect(await auth.getAccessToken({ forUserId: ALICE })).toBeNull();
  });
});
