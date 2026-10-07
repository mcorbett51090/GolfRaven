/**
 * The SPA against the REAL `partner-session` handler (supabase/functions/_shared/partner/session-handler.ts) with in-memory ports and real ES256
 * assertions (support/fake-partner-server.ts). What these cells prove is that the requests this client builds are ACCEPTED by the server's own
 * Origin check, preflight, media-type rule, bearer rule and strict body parser, and that every refusal the server makes is mapped as designed.
 * The browser itself (CSP, a real authenticator, real storage) is the Playwright suite.
 */
import { describe, expect, it } from "vitest";
import { isPartnerApiError, PartnerApiError } from "../src/api/errors";
import { reauthWithPasskey } from "../src/auth/reauth";
import { signInWithPasskey } from "../src/auth/sign-in";
import { WebAuthnFailure } from "../src/webauthn/assertion";
import { PAGE_ORIGIN, makeWorld } from "./support/world";

const apiErr = async (p: Promise<unknown>): Promise<PartnerApiError> => {
  try {
    await p;
  } catch (e) {
    if (isPartnerApiError(e)) return e;
    throw e;
  }
  throw new Error("expected a PartnerApiError");
};

describe("sign-in against the real handler", () => {
  it("options, a real assertion, verify, then GET session: the server accepts every request the client builds", async () => {
    const w = makeWorld();
    const grant = await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
    expect(grant.aal).toBe(1);
    expect(w.api.hasSession()).toBe(true);
    expect(w.server.sessions()).toHaveLength(1);
    const who = await w.api.session();
    expect(who.memberships[0]!.role).toBe("staff");
    // the authenticator was asked for exactly the server's ceremony
    const pk = w.auth.requests[0]!.publicKey!;
    expect(pk.userVerification).toBe("required");
    expect(pk.allowCredentials).toEqual([]);
    expect(pk.rpId).toBe("partners.example.test");
  });

  it("what the SERVER received: exact media type on every request, an Origin, a Bearer only on session routes, and no cookie ever", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
    await w.api.session();
    await w.api.lock();
    const logged = w.server.log.filter((r) => r.method !== "OPTIONS");
    expect(logged.map((r) => `${r.method} ${r.path.split("/").pop()}`)).toEqual(["POST options", "POST verify", "GET session", "POST lock"]);
    for (const r of logged) {
      expect(r.contentType, r.path).toBe("application/json");
      expect(r.origin, r.path).toBe(PAGE_ORIGIN);
      expect(r.cookie, r.path).toBeNull();
    }
    expect(logged[0]!.authorization).toBeNull();
    expect(logged[1]!.authorization).toBeNull();
    expect(logged[2]!.authorization).toBe(`Bearer ${w.server.issuedTokens[0]}`);
    expect(logged[3]!.authorization).toBe(`Bearer ${w.server.issuedTokens[0]}`);
    // and the preflights the browser would send were all answered
    expect(w.server.log.filter((r) => r.method === "OPTIONS").length).toBe(4);
  });

  it("the token never appears in anything the server could log except the Authorization header: not in a URL, not in a body", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
    await w.api.session();
    await w.api.lock();
    const token = w.server.issuedTokens[0]!;
    for (const r of w.server.log) {
      expect(r.path).not.toContain(token);
      expect(r.body).not.toContain(token);
      expect(r.referer).toBeNull();
    }
  });

  const wrongAssertions: Array<[string, (w: ReturnType<typeof makeWorld>) => void]> = [
    ["a wrong origin in clientDataJSON", (w) => (w.auth.knobs.origin = "https://evil.example.test")],
    ["a wrong RP ID hash", (w) => (w.auth.knobs.rpId = "evil.example.test")],
    ["no user verification (UP only)", (w) => (w.auth.knobs.flags = 0x01)],
    ["no user presence (UV only)", (w) => (w.auth.knobs.flags = 0x04)],
    ["a different challenge", (w) => (w.auth.knobs.challenge = new Uint8Array(32).fill(5))],
    ["a user handle that is not the credential's person", (w) => (w.auth.knobs.userHandle = new Uint8Array(16).fill(1))],
  ];
  it.each(wrongAssertions)("%s is the server's ONE uniform 401, and the client holds no session", async (_name, tamper) => {
    const w = makeWorld();
    tamper(w);
    const e = await apiErr(signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true }));
    expect(e.kind).toBe("unauthenticated");
    expect(e.status).toBe(401);
    expect(w.api.hasSession()).toBe(false);
    expect(w.server.sessions()).toEqual([]);
  });

  it("a replayed assertion (same challenge token, same credential) is refused", async () => {
    const w = makeWorld();
    const ch = await w.api.signInOptions();
    const { getAssertion } = await import("../src/webauthn/assertion");
    const credential = await getAssertion({ credentials: w.auth.credentials, supported: true }, ch.options);
    await w.api.verify({ challengeToken: ch.challengeToken, credential });
    const second = w.newClient();
    expect((await apiErr(second.verify({ challengeToken: ch.challengeToken, credential }))).kind).toBe("unauthenticated");
    expect(w.server.sessions()).toHaveLength(1);
  });

  it("the person cancelling the prompt is a WebAuthnFailure('cancelled') and never reaches verify", async () => {
    const w = makeWorld();
    w.auth.failNextWith = "NotAllowedError";
    await expect(signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true })).rejects.toBeInstanceOf(WebAuthnFailure);
    expect(w.server.log.some((r) => r.path.endsWith("/verify"))).toBe(false);
  });

  it("a page served from another origin cannot sign in at all: the preflight fails and the client sees a network error", async () => {
    const w = makeWorld({ pageOrigin: "https://evil.example.test" });
    expect((await apiErr(w.api.signInOptions())).kind).toBe("network");
    expect(w.server.log.filter((r) => r.method !== "OPTIONS")).toEqual([]);
  });

  it("a deploy fault on options is a 503, mapped to 'unavailable'", async () => {
    const w = makeWorld();
    w.server.state.unavailable = true;
    expect((await apiErr(w.api.signInOptions())).kind).toBe("unavailable");
  });
});

describe("session routes against the real handler", () => {
  async function signedIn(over: Parameters<typeof makeWorld>[0] = {}) {
    const w = makeWorld(over);
    await signInWithPasskey(w.api, { credentials: w.auth.credentials, supported: true });
    return w;
  }

  it("GET session reports the roles and the assurance the server computed", async () => {
    const w = await signedIn({ whoami: { aal: 1, requiredAal: 2, isAdmin: true, memberships: [{ orgId: "o", role: "operator", facilityIds: [], trailIds: ["t1", "t2"] }] } });
    const who = await w.api.session();
    expect(who).toMatchObject({ aal: 1, requiredAal: 2, isAdmin: true });
    expect(who.memberships[0]!.trailIds).toEqual(["t1", "t2"]);
  });

  it("sign-out revokes the session ON THE SERVER, and the old token is then refused", async () => {
    const w = await signedIn();
    const token = w.server.issuedTokens[0]!;
    await w.api.signOut();
    expect(w.server.state.signOutCalls).toBe(1);
    expect(w.api.hasSession()).toBe(false);
    const raw = await w.server.handler(new Request("https://api.example.test/functions/v1/partner-session/session", { headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } }));
    expect(raw.status).toBe(401);
  });

  it("lock tells the server, wipes the client, and leaves the server session alive (it ends by idle expiry; sign-out is the revoke)", async () => {
    const w = await signedIn();
    await w.api.lock();
    expect(w.server.state.lockCalls).toBe(1);
    expect(w.api.hasSession()).toBe(false);
    expect(w.server.state.revokedSessions.size).toBe(0);
    // with nothing held the client makes no further request
    const before = w.server.log.length;
    await apiErr(w.api.session());
    expect(w.server.log.length).toBe(before);
  });

  it("a session the server has killed is a 401 on the next call, and the client wipes its token", async () => {
    const w = await signedIn();
    w.server.killAllSessions();
    const reasons: string[] = [];
    w.api.onSessionEnded((r) => reasons.push(r));
    expect((await apiErr(w.api.session())).kind).toBe("unauthenticated");
    expect(w.api.hasSession()).toBe(false);
    expect(reasons).toEqual(["expired"]);
  });

  it("a request carrying a text/plain look-alike media type is a 415 at the server (the rule the client's exact header exists to meet)", async () => {
    const w = await signedIn();
    const res = await w.server.handler(new Request("https://api.example.test/functions/v1/partner-session/options", { method: "POST", headers: { "content-type": "text/plain; x=application/json", origin: PAGE_ORIGIN }, body: "{}" }));
    expect(res.status).toBe(415);
  });
});

describe("reauth helper against the real handler", () => {
  const deps = (w: ReturnType<typeof makeWorld>) => ({ credentials: w.auth.credentials, supported: true });

  it("options, a fresh assertion, reauth: the server opens the window and GET session shows it", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, deps(w));
    const r = await reauthWithPasskey(w.api, deps(w));
    expect(Date.parse(r.reauthUntil)).toBeGreaterThan(Date.now());
    expect((await w.api.session()).stepUp.reauthUntil).toBe(r.reauthUntil);
    expect(w.auth.requests).toHaveLength(2);
    const calls = w.server.log.filter((l) => l.method !== "OPTIONS").map((l) => l.path.split("/partner-session/")[1]);
    expect(calls).toEqual(["options", "verify", "reauth/options", "reauth", "session"]);
  });

  it("needs a session: without one it makes no request and is 'unauthenticated'", async () => {
    const w = makeWorld();
    expect((await apiErr(reauthWithPasskey(w.api, deps(w)))).kind).toBe("unauthenticated");
    expect(w.server.log).toEqual([]);
  });

  it("a refused assertion is 403 reauth_refused and the session SURVIVES", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, deps(w));
    w.auth.knobs.challenge = new Uint8Array(32).fill(9);
    const e = await apiErr(reauthWithPasskey(w.api, deps(w)));
    expect(e.kind).toBe("reauth_refused");
    expect(e.status).toBe(403);
    expect(w.api.hasSession()).toBe(true);
    w.auth.knobs = {};
    expect((await w.api.session()).aal).toBe(1);
  });

  it("a dead session is 401 and the token is wiped", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, deps(w));
    w.server.killAllSessions();
    expect((await apiErr(reauthWithPasskey(w.api, deps(w)))).kind).toBe("unauthenticated");
    expect(w.api.hasSession()).toBe(false);
  });

  it("the rate limit is a 429; Retry-After is NOT readable across origins (the S1.2 server exposes no headers), so retryAfterSeconds is null", async () => {
    const w = makeWorld();
    await signInWithPasskey(w.api, deps(w));
    w.server.state.reauthLimit = 0;
    const e = await apiErr(reauthWithPasskey(w.api, deps(w)));
    expect(e.kind).toBe("rate_limited");
    expect(e.retryAfterSeconds).toBeNull();
    // the server DID send it; only the missing Access-Control-Expose-Headers hides it from a cross-origin page
    const sent = w.server.log.filter((l) => l.path.endsWith("/partner-session/reauth")).at(-1)!;
    const raw = await w.server.handler(new Request("https://api.example.test/functions/v1/partner-session/reauth", { method: "POST", headers: { authorization: `Bearer ${w.server.issuedTokens[0]}`, "content-type": "application/json", origin: PAGE_ORIGIN }, body: sent.body }));
    expect(raw.status).toBe(429);
    expect(raw.headers.get("retry-after")).toBe("1800");
    expect(raw.headers.get("access-control-expose-headers")).toBeNull();
  });
});
