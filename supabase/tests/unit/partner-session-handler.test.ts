// supabase/tests/unit/partner-session-handler.test.ts
//
// The partner `partner-session` handler (docs/security/partner-auth-design.md PA-10, PA-11, PA-12 and the S1.2 rules), against the in-memory ports of partner-fakes.ts. The cells that need a real
// authenticator are supabase/tests/deno-unit/partner-session-handler.deno.test.ts (the S0 wrapper and the software authenticator); the cells that need a real database are
// supabase/tests/integration/partner-session.deno.test.ts. Here the ports are fakes, and every cell states one thing the handler decides ON ITS OWN.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handlePartnerSessionRequest, REAUTH_BUCKET, routeOf } from "../../functions/_shared/partner/session-handler.ts";
import { PartnerAuthorityRefused, PartnerNotConfigured } from "../../functions/_shared/partner/ports.ts";
import { authed, challengeToken, credentialJson, makeFakes, NOW_MS, ORIGIN, req, SESSION_TOKEN, sha256Hex, USER_ID as USER_ID_FOR_L4, verifyBody } from "./partner-fakes.ts";

// built at run time (a literal token-shaped string trips the secret scanner): a three-part, base64url, JWT-shaped bearer
const b64u = (v: string) => btoa(v).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const JWT = [b64u(JSON.stringify({ alg: "HS256", typ: "JWT" })), b64u(JSON.stringify({ sub: "test-subject" })), b64u("not-a-real-signature")].join(".");

const DERIVED_FOR_LOG = btoa(String.fromCharCode(...new Uint8Array(32).fill(17))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const SALT_FOR_LOG = btoa(String.fromCharCode(...new Uint8Array(16).fill(51))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");

async function bodyOf(res: Response): Promise<unknown> {
  return JSON.parse(await res.text());
}

afterEach(() => vi.restoreAllMocks());

describe("PA-10: CORS and the server-side Origin refusal", () => {
  it("OPTIONS from the allowed origin: 204, exactly that origin, GET/POST/PATCH/DELETE, no credentials mode, and NO port is touched (no database connection)", async () => {
    const f = makeFakes();
    for (const method of ["GET", "POST", "PATCH", "DELETE"]) {
      const res = await handlePartnerSessionRequest(req("OPTIONS", "verify", { headers: { origin: ORIGIN, "access-control-request-method": method, "access-control-request-headers": "authorization,content-type,x-gr-pop" } }), f.deps);
      expect(res.status).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
      expect(res.headers.get("access-control-allow-methods")).toContain(method);
      expect(res.headers.get("access-control-allow-methods")).toBe("GET, POST, PATCH, DELETE, OPTIONS");
      expect(res.headers.get("access-control-allow-headers")).toBe("authorization, content-type, x-gr-pop");
      expect(res.headers.get("access-control-allow-credentials")).toBeNull();
      expect(res.headers.get("vary")).toBe("Origin");
      expect(Number(res.headers.get("access-control-max-age"))).toBeGreaterThan(0);
      expect(Number(res.headers.get("access-control-max-age"))).toBeLessThanOrEqual(600);
    }
    expect(f.calls).toEqual([]);
  });

  it("OPTIONS with no Origin header is 204 with no CORS header, and still touches nothing", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("OPTIONS", "session"), f.deps);
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(f.calls).toEqual([]);
  });

  it("a foreign Origin is 403 BEFORE routing, for every method and every route (an unknown route and a wrong method included), and gets NO CORS header", async () => {
    const f = makeFakes();
    const foreign = ["https://evil.example.test", "http://partners.example.test", "https://partners.example.test/", "https://PARTNERS.example.test", "https://partners.example.test:8443", "null", `${ORIGIN}, https://evil.example.test`];
    for (const origin of foreign) {
      for (const [method, path] of [["OPTIONS", "verify"], ["POST", "options"], ["POST", "verify"], ["GET", "session"], ["DELETE", "session"], ["PATCH", "lock"], ["POST", "no-such-route"], ["GET", "verify"]] as const) {
        const res = await handlePartnerSessionRequest(req(method, path, { headers: { origin }, body: method === "POST" ? {} : undefined }), f.deps);
        expect(res.status, `${method} ${path} from ${origin}`).toBe(403);
        expect(res.headers.get("access-control-allow-origin")).toBeNull();
        expect(res.headers.get("access-control-allow-methods")).toBeNull();
        expect(await bodyOf(res)).toEqual({ error: { code: "forbidden", message: "origin not allowed" } });
      }
    }
    expect(f.calls).toEqual([]);
  });

  it("a request with NO Origin (a non-browser client) is let through and gets no CORS header", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("POST", "options", { body: {} }), f.deps);
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("vary")).toBe("Origin");
  });

  it("with NO origin configured the lane fails closed: every request that carries an Origin is refused, the allowed one included", async () => {
    const f = makeFakes({}, null);
    expect((await handlePartnerSessionRequest(req("OPTIONS", "verify", { headers: { origin: ORIGIN } }), f.deps)).status).toBe(403);
    expect((await handlePartnerSessionRequest(req("POST", "options", { headers: { origin: ORIGIN }, body: {} }), f.deps)).status).toBe(403);
    expect(f.calls).toEqual([]);
    // and the database paths answer 503 (the configured origin and the database's cannot be compared)
    expect((await handlePartnerSessionRequest(req("POST", "options", { body: {} }), f.deps)).status).toBe(503);
  });

  it("every response carries Cache-Control: no-store and Vary: Origin; the allowed origin's responses carry its CORS header", async () => {
    const f = makeFakes();
    const ok = await handlePartnerSessionRequest(req("POST", "options", { headers: { origin: ORIGIN }, body: {} }), f.deps);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect(ok.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    const refused = await handlePartnerSessionRequest(req("GET", "session", { headers: { origin: ORIGIN } }), f.deps);
    expect(refused.status).toBe(401);
    expect(refused.headers.get("cache-control")).toBe("no-store");
    expect(refused.headers.get("access-control-allow-origin")).toBe(ORIGIN);
  });

  it("the media type is EXACTLY application/json: `text/plain; x=application/json` and every other near miss is 415 before the body is read, on the pre-auth routes", async () => {
    const f = makeFakes();
    const bad = ["text/plain; x=application/json", "text/plain", "application/jsonp", "application/json-patch+json", "application/x-www-form-urlencoded", "multipart/form-data; boundary=application/json", "application/json; x=1", "application/json; charset=latin1", "application/json;charset=utf-8;x=1", "xapplication/json", ""];
    for (const ct of bad) {
      for (const path of ["options", "verify"]) {
        const res = await handlePartnerSessionRequest(req("POST", path, { headers: { "content-type": ct, origin: ORIGIN }, raw: "{}" }), f.deps);
        expect(res.status, `${path} with ${JSON.stringify(ct)}`).toBe(415);
      }
    }
    expect(f.calls).toEqual([]);
    for (const ct of ["application/json", "application/json; charset=utf-8", "application/json;charset=UTF-8", "Application/JSON", 'application/json; charset="utf-8"']) {
      const res = await handlePartnerSessionRequest(req("POST", "options", { headers: { "content-type": ct }, raw: "{}" }), f.deps);
      expect(res.status, ct).toBe(200);
    }
  });

  it("an oversized body is 413 and invalid JSON or UTF-8 is 400 (the shared cap)", async () => {
    const f = makeFakes();
    expect((await handlePartnerSessionRequest(req("POST", "options", { raw: "{" + " ".repeat(70_000) + "}" }), f.deps)).status).toBe(413);
    expect((await handlePartnerSessionRequest(req("POST", "options", { raw: "{not json" }), f.deps)).status).toBe(400);
  });
});

describe("routing", () => {
  it("routeOf reads the path after the function name, and the whole path when the function name is absent", () => {
    expect(routeOf("https://x.test/partner-session/verify")).toBe("verify");
    expect(routeOf("https://x.test/functions/v1/partner-session/reauth/options")).toBe("reauth/options");
    expect(routeOf("https://x.test/verify")).toBe("verify");
    expect(routeOf("https://x.test/partner-session/")).toBe("");
    expect(routeOf("https://x.test/partner-session/verify/")).toBe("verify");
  });

  it("an unknown route is 404 and a wrong method is 405 with Allow, before anything else is touched", async () => {
    const f = makeFakes();
    expect((await handlePartnerSessionRequest(req("POST", "nope", { body: {} }), f.deps)).status).toBe(404);
    expect((await handlePartnerSessionRequest(req("POST", "", { body: {} }), f.deps)).status).toBe(404);
    const r = await handlePartnerSessionRequest(req("GET", "verify"), f.deps);
    expect(r.status).toBe(405);
    expect(r.headers.get("allow")).toBe("POST");
    const r2 = await handlePartnerSessionRequest(req("POST", "session", { headers: authed(), body: {} }), f.deps);
    expect(r2.status).toBe(405);
    expect(r2.headers.get("allow")).toBe("GET");
    expect((await handlePartnerSessionRequest(req("DELETE", "session", { headers: authed() }), f.deps)).status).toBe(405);
    expect((await handlePartnerSessionRequest(req("PATCH", "lock", { headers: authed(), body: {} }), f.deps)).status).toBe(405);
    expect(f.calls).toEqual([]);
  });
});

describe("PA-11: a Supabase JWT (or any foreign bearer) is the ONE 401 on every session route, and nothing is touched", () => {
  const sessionRoutes: Array<[string, string]> = [
    ["GET", "session"], ["POST", "sign-out"], ["POST", "lock"], ["POST", "reauth/options"], ["POST", "reauth"],
    // S1.3: the step-up PIN and the email proof are session routes too
    ["GET", "pin"], ["POST", "step-up/pin"], ["POST", "pin/set"], ["POST", "pin/change"], ["POST", "otp-proof/start"], ["POST", "otp-proof/verify"],
  ];
  it("a JWT, a wrong-length partner token, a wrong prefix, another scheme and no header are all refused identically", async () => {
    const f = makeFakes();
    const bearers: Array<string | null> = [
      `Bearer ${JWT}`, `Bearer gr_ps_short`, `Bearer ${SESSION_TOKEN}x`, `Bearer GR_PS_${SESSION_TOKEN.slice(6)}`, `Bearer gr_inv_${SESSION_TOKEN.slice(6)}`, `Basic ${SESSION_TOKEN}`, SESSION_TOKEN,
      `Bearer ${SESSION_TOKEN} extra`, "Bearer", "", null,
    ];
    const seen = new Set<string>();
    for (const b of bearers) {
      for (const [method, path] of sessionRoutes) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (b !== null) headers.authorization = b;
        const res = await handlePartnerSessionRequest(req(method, path, { headers, body: method === "POST" ? {} : undefined }), f.deps);
        expect(res.status, `${method} ${path} with ${b}`).toBe(401);
        seen.add(await res.text());
      }
    }
    expect(seen.size, "one constant 401 body").toBe(1);
    expect(f.calls).toEqual([]);
  });

  it("the 401 body is the same bytes whatever the cause: a bad bearer, a refused binder and a refused sign-in", async () => {
    const f = makeFakes({ bindRefused: true, lookup: { status: "unknown" } });
    const a = await (await handlePartnerSessionRequest(req("GET", "session", { headers: { authorization: `Bearer ${JWT}` } }), f.deps)).text();
    const b = await (await handlePartnerSessionRequest(req("GET", "session", { headers: authed() }), f.deps)).text();
    const c = await (await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps)).text();
    expect(b).toBe(a);
    expect(c).toBe(a);
    expect(JSON.parse(a)).toEqual({ error: { code: "unauthenticated", message: "authentication failed" } });
  });
});

describe("POST options", () => {
  it("issues a challenge from the minter lane, builds the options from the DATABASE's relying party, and returns token + expiry; the body must be {}", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("POST", "options", { headers: { origin: ORIGIN }, body: {} }), f.deps);
    expect(res.status).toBe(200);
    const b = (await bodyOf(res)) as { data: { options: unknown; challengeToken: string; expiresAt: string } };
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig", "mint.issueChallenge", "webauthn.options"]);
    expect(b.data.challengeToken).toMatch(/^[A-Za-z0-9_-]{43}\.[0-9]+\.[A-Za-z0-9_-]{43}$/);
    expect(b.data.expiresAt).toBe(new Date((NOW_MS / 1000 + 120) * 1000).toISOString());
    expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
    expect((await handlePartnerSessionRequest(req("POST", "options", { body: { extra: 1 } }), f.deps)).status).toBe(400);
  });

  it("a configured origin that differs from partner_rp_config.origin is a 503 and a rollback (the two copies of one fact cannot drift apart silently)", async () => {
    const f = makeFakes({ rp: { rpId: "partners.example.test", origin: "https://other.example.test" } });
    const res = await handlePartnerSessionRequest(req("POST", "options", { body: {} }), f.deps);
    expect(res.status).toBe(503);
    expect(f.tx).toEqual([{ kind: "mint", committed: false }]);
    expect(f.calls).not.toContain("mint.issueChallenge");
  });
});

describe("L4 (S1.2 gate): assertSameOrigin runs on the challenge-using routes, and refuses a GR_PARTNER_ORIGIN / partner_rp_config mismatch on verify and on reauth", () => {
  // The check is on the routes that USE a challenge and so read the relying party (options, verify, reauth/options, reauth); it is NOT on every database path (sign-out, lock, GET session and the PIN
  // routes read no relying party). Each cell below fails if the check is removed from its route (the mutants E18 and E19).
  const OTHER = { rpId: "partners.example.test", origin: "https://other.example.test" };

  it("verify: the database's origin differs from the configured one: 503, a rollback, and NOTHING is looked up, verified or minted", async () => {
    const f = makeFakes({ rp: OTHER });
    const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    expect(res.status).toBe(503);
    expect(await bodyOf(res)).toEqual({ error: { code: "service_unavailable", message: "partner sign-in is not available" } });
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig"]);
    expect(f.tx).toEqual([{ kind: "mint", committed: false }]);
    expect(f.mintInputs).toHaveLength(0);
  });

  it("verify: with NO origin configured at all (a request that carries no Origin header still reaches the database path) the answer is the same 503", async () => {
    const f = makeFakes({}, null);
    const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    expect(res.status).toBe(503);
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig"]);
    expect(f.mintInputs).toHaveLength(0);
  });

  it("verify control: the same request with matching origins mints (so the refusals above are the mismatch, not the route)", async () => {
    const f = makeFakes();
    expect((await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps)).status).toBe(201);
  });

  it("reauth: the database's origin (on the credential read) differs from the configured one: 503, a rollback, the assertion is NEVER verified and the reauth definer is never called", async () => {
    const f = makeFakes({ reauthCredential: { id: "11111111-1111-1111-1111-111111111111", userId: USER_ID_FOR_L4, alg: -7, publicKey: new Uint8Array(77).fill(6), signCount: 4, rp: OTHER } });
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(503);
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.reauthCredential"]);
    expect(f.tx).toEqual([{ kind: "session", committed: false }]);
    expect(f.reauthInputs).toHaveLength(0);
  });

  it("reauth: with NO origin configured the same 503 (a non-browser request carries no Origin, so it reaches the database path)", async () => {
    const f = makeFakes({}, null);
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: { authorization: `Bearer ${SESSION_TOKEN}` }, body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(503);
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.reauthCredential"]);
    expect(f.reauthInputs).toHaveLength(0);
  });

  it("reauth control: matching origins reauthenticate", async () => {
    const f = makeFakes();
    expect((await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps)).status).toBe(200);
  });

  it("the routes that read no relying party do NOT run the check (the doc's old wording, `every database path`, was wrong): GET session, sign-out, lock and the PIN routes work whatever the configured origin", async () => {
    const f = makeFakes({ rp: OTHER }, null);
    expect((await handlePartnerSessionRequest(req("GET", "session", { headers: { authorization: `Bearer ${SESSION_TOKEN}` } }), f.deps)).status).toBe(200);
    expect((await handlePartnerSessionRequest(req("POST", "lock", { headers: { authorization: `Bearer ${SESSION_TOKEN}` }, body: {} }), f.deps)).status).toBe(200);
    expect((await handlePartnerSessionRequest(req("GET", "pin", { headers: { authorization: `Bearer ${SESSION_TOKEN}` } }), f.deps)).status).toBe(200);
  });
});

describe("POST verify (PA-12): the wrapper first, the mint second, COMMIT on every status, one uniform 401", () => {
  it("a valid assertion: lookup, the wrapper, THEN the mint; the response is 201 with the opaque token ONCE, and only its sha256 reaches the database", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("POST", "verify", { headers: { origin: ORIGIN }, body: verifyBody() }), f.deps);
    expect(res.status).toBe(201);
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig", "mint.lookupCredential", "webauthn.verify", "mint.mint"]);
    const data = ((await bodyOf(res)) as { data: { token: string; expiresAt: string; aal: number } }).data;
    expect(data.token).toMatch(/^gr_ps_[A-Za-z0-9_-]{43}$/);
    expect(data.aal).toBe(1);
    expect(data.expiresAt).toBe("2030-01-01T20:00:00.000Z");
    expect(f.mintInputs).toHaveLength(1);
    expect(f.mintInputs[0]!.tokenHash).toBe(await sha256Hex(data.token));
    expect(JSON.stringify(f.mintInputs[0], (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v))).not.toContain(data.token);
    expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
  });

  it("the wrapper is given the database's relying party, the issued nonce, the STORED counter and the person's 16 bytes as the user handle", async () => {
    const f = makeFakes();
    await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    const v = f.verifyRequests[0]!;
    expect(v.rp).toEqual({ rpId: "partners.example.test", origin: ORIGIN });
    expect(Array.from(v.expectedChallenge)).toEqual(Array.from(new Uint8Array(32).fill(1)));
    expect(v.credential.signCount).toBe(4);
    expect(Array.from(v.expectedUserHandle)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0xa1]);
  });

  it("a refused verification (the wrapper) NEVER reaches the mint, counts one failure against the credential, and commits that count (one uniform 401)", async () => {
    const f = makeFakes({ verify: { ok: false, counterOnly: false } });
    const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    expect(res.status).toBe(401);
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig", "mint.lookupCredential", "webauthn.verify", "mint.recordFailure"]);
    expect(f.mintInputs).toHaveLength(0);
    expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
  });

  it("an unknown, a revoked and a cooling credential are ONE answer, nothing is verified and nothing is counted (the cooldown is not extended by presenting more)", async () => {
    for (const status of ["unknown", "cooldown"] as const) {
      const f = makeFakes({ lookup: { status } });
      const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
      expect(res.status).toBe(401);
      expect(f.calls).toEqual(["db.withMint", "mint.rpConfig", "mint.lookupCredential"]);
      expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
    }
  });

  it("a counter that only FAILS the counter (counterOnly) goes to the mint, which writes the alarm: the status is refused as 401, no failure is counted, and the transaction COMMITS", async () => {
    const f = makeFakes({ verify: { ok: false, counterOnly: true }, mintStatus: "counter_regression" });
    const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    expect(res.status).toBe(401);
    expect(f.calls).toEqual(["db.withMint", "mint.rpConfig", "mint.lookupCredential", "webauthn.verify", "mint.mint"]);
    expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
  });

  it("COMMIT ON EVERY STATUS (17.8): each of the 16 refusal statuses of the mint is a returned value, one uniform 401, and the transaction commits (the alarm rows, the nonce, the counter)", async () => {
    const statuses = ["bad_challenge", "expired", "unknown_credential", "rate_limited", "bad_client_data", "bad_client_type", "cross_origin", "bad_origin", "challenge_mismatch", "bad_authenticator_data", "bad_rp_id_hash", "user_not_present", "user_not_verified", "signature_invalid", "replayed", "counter_regression"];
    expect(statuses).toHaveLength(16);
    const bodies = new Set<string>();
    for (const mintStatus of statuses) {
      const f = makeFakes({ mintStatus });
      const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
      expect(res.status, mintStatus).toBe(401);
      expect(f.tx, mintStatus).toEqual([{ kind: "mint", committed: true }]);
      bodies.add(await res.text());
    }
    expect(bodies.size, "one uniform body").toBe(1);
  });

  it("an unexpected error (a database fault) is a constant 500 with no detail and ROLLS BACK; a deploy fault (PartnerNotConfigured) is a bare 503", async () => {
    const f = makeFakes({ throwIn: "mint" });
    const res = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), f.deps);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).not.toContain("secret database text");
    expect(JSON.parse(text)).toEqual({ error: { code: "internal_error", message: "internal error" } });
    expect(f.tx).toEqual([{ kind: "mint", committed: false }]);
    const g = makeFakes();
    g.deps.db.withMint = async () => {
      throw new PartnerNotConfigured();
    };
    expect((await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), g.deps)).status).toBe(503);
  });

  it("an expired challenge token is refused (401) by the Edge before any database work; a token one second from expiry still goes through", async () => {
    const f = makeFakes();
    const expired = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody({ challengeToken: challengeToken(NOW_MS / 1000) }) }), f.deps);
    expect(expired.status).toBe(401);
    expect(f.calls).toEqual([]);
    expect((await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody({ challengeToken: challengeToken(NOW_MS / 1000 + 1) }) }), f.deps)).status).toBe(201);
  });

  it("the body is strict: unknown keys, a malformed token, a non-canonical base64url field, a wrong type and a mismatched rawId are all 400", async () => {
    const f = makeFakes();
    const cases: Array<Record<string, unknown>> = [
      verifyBody({ extra: 1 }),
      verifyBody({ challengeToken: "not.a.token" }),
      verifyBody({ challengeToken: undefined }),
      verifyBody({ credential: credentialJson({ type: "password" }) }),
      verifyBody({ credential: credentialJson({ rawId: "AAAA" }) }),
      verifyBody({ credential: credentialJson({ unknown: 1 }) }),
      verifyBody({ credential: credentialJson({}, { signature: "AAAB=" }) }),
      verifyBody({ credential: credentialJson({}, { signature: "A" }) }),
      verifyBody({ credential: credentialJson({}, { authenticatorData: "AAAA" }) }),
      verifyBody({ credential: credentialJson({}, { surprise: "x" }) }),
      verifyBody({ credential: "x" }),
    ];
    for (const body of cases) expect((await handlePartnerSessionRequest(req("POST", "verify", { body }), f.deps)).status, JSON.stringify(body).slice(0, 80)).toBe(400);
    expect((await handlePartnerSessionRequest(req("POST", "verify", { raw: "[]" }), f.deps)).status).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("N7: pop_jkt and the X-GR-PoP header are accepted and IGNORED (the outcome is identical with and without), and a pop_jkt of the wrong type is still a 400", async () => {
    const plain = makeFakes();
    const withPop = makeFakes();
    const a = await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody() }), plain.deps);
    const b = await handlePartnerSessionRequest(req("POST", "verify", { headers: { "x-gr-pop": "garbage", origin: ORIGIN }, body: verifyBody({ pop_jkt: "thumbprint" }) }), withPop.deps);
    expect(b.status).toBe(a.status);
    expect(withPop.calls).toEqual(plain.calls);
    expect(withPop.mintInputs[0]).toEqual({ ...plain.mintInputs[0]!, tokenHash: withPop.mintInputs[0]!.tokenHash });
    expect((await handlePartnerSessionRequest(req("POST", "verify", { body: verifyBody({ pop_jkt: 7 }) }), makeFakes().deps)).status).toBe(400);
    expect((await handlePartnerSessionRequest(req("POST", "options", { headers: { "x-gr-pop": "garbage" }, body: {} }), makeFakes().deps)).status).toBe(200);
  });
});

describe("session routes", () => {
  it("GET session binds the token's sha256 (never the token) and returns the database's answer; no body is read", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("GET", "session", { headers: authed() }), f.deps);
    expect(res.status).toBe(200);
    expect(await bodyOf(res)).toEqual({ data: { userId: "00000000-0000-0000-0000-1000000000a1", aal: 1 } });
    expect(f.sessionHashes).toEqual([await sha256Hex(SESSION_TOKEN)]);
    expect(f.calls).toEqual(["db.withSession", "session.whoami"]);
  });

  it("a refused binder is the ONE 401 and a 42501 from a definer is a 403", async () => {
    const f = makeFakes({ bindRefused: true });
    expect((await handlePartnerSessionRequest(req("GET", "session", { headers: authed() }), f.deps)).status).toBe(401);
    const g = makeFakes();
    g.deps.db.withSession = async () => {
      throw new PartnerAuthorityRefused();
    };
    const res = await handlePartnerSessionRequest(req("POST", "lock", { headers: authed(), body: {} }), g.deps);
    expect(res.status).toBe(403);
    expect(await bodyOf(res)).toEqual({ error: { code: "forbidden", message: "forbidden" } });
  });

  it("sign-out and lock each run their one definer in one transaction and need {} as the body", async () => {
    const f = makeFakes();
    const out = await handlePartnerSessionRequest(req("POST", "sign-out", { headers: authed(), body: {} }), f.deps);
    expect(out.status).toBe(200);
    const lock = await handlePartnerSessionRequest(req("POST", "lock", { headers: authed(), body: {} }), f.deps);
    expect(lock.status).toBe(200);
    expect(f.calls).toEqual(["db.withSession", "session.signOut", "db.withSession", "session.lock"]);
    expect((await handlePartnerSessionRequest(req("POST", "sign-out", { headers: authed(), body: { all: true } }), f.deps)).status).toBe(400);
    expect((await handlePartnerSessionRequest(req("POST", "lock", { headers: authed({ "content-type": "text/plain" }), raw: "{}" }), f.deps)).status).toBe(415);
  });
});

describe("reauth (PA-27)", () => {
  it("reauth/options returns the options and a token from the SESSION's own challenge; the origin copies are compared", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("POST", "reauth/options", { headers: authed(), body: {} }), f.deps);
    expect(res.status).toBe(200);
    expect(f.calls).toEqual(["db.withSession", "session.reauthOptions", "webauthn.options"]);
    const g = makeFakes({ rp: { rpId: "partners.example.test", origin: "https://other.example.test" } });
    expect((await handlePartnerSessionRequest(req("POST", "reauth/options", { headers: authed(), body: {} }), g.deps)).status).toBe(503);
  });

  it("the member rate limit (10 an hour) is hit BEFORE the request transaction, and over it the answer is 429 with Retry-After and nothing else runs", async () => {
    const f = makeFakes({ rateLimitOk: false });
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    expect(f.calls).toEqual(["db.hitRateLimit"]);
    expect(f.rateLimitHits).toEqual([{ hash: await sha256Hex(SESSION_TOKEN), bucket: REAUTH_BUCKET, windowSeconds: 3600, max: 10 }]);
  });

  it("a valid reauth: hit, then ONE transaction: the session's own credential, the wrapper, the definer; the answer carries reauthUntil", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(200);
    expect(await bodyOf(res)).toEqual({ data: { reauthUntil: "2030-01-01T12:05:00.000Z" } });
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.reauthCredential", "webauthn.verify", "session.reauth"]);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("PA-27: a credential that is not the session's person's (the read returns nothing) is refused WITHOUT being verified or presented to the verifier; every refusal is the same 403", async () => {
    const f = makeFakes({ reauthCredential: null });
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(403);
    expect(await bodyOf(res)).toEqual({ error: { code: "reauth_refused", message: "reauthentication failed" } });
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.reauthCredential"]);
    // a wrapper refusal and a database refusal: the SAME bytes, never a 401 (a 401 would say the session is dead)
    const w = makeFakes({ verify: { ok: false, counterOnly: false } });
    const rw = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), w.deps);
    const d = makeFakes({ reauthStatus: "replayed" });
    const rd = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), d.deps);
    expect(rw.status).toBe(403);
    expect(await rw.text()).toBe(await rd.text());
    expect(w.calls).not.toContain("session.reauth");
    expect(d.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("a counterOnly failure is passed to the database (which writes its audit row) and the status is refused; an expired challenge is refused before the transaction", async () => {
    const f = makeFakes({ verify: { ok: false, counterOnly: true }, reauthStatus: "counter_regression" });
    const res = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson() } }), f.deps);
    expect(res.status).toBe(403);
    expect(f.calls).toContain("session.reauth");
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
    const g = makeFakes();
    const exp = await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(NOW_MS / 1000), credential: credentialJson() } }), g.deps);
    expect(exp.status).toBe(403);
    expect(g.calls).toEqual(["db.hitRateLimit"]);
  });

  it("the reauth body takes no pop_jkt (it is the sign-in's reserved slot)", async () => {
    const f = makeFakes();
    expect((await handlePartnerSessionRequest(req("POST", "reauth", { headers: authed(), body: { challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: "x" } }), f.deps)).status).toBe(400);
  });
});

describe("PA-11: nothing is ever logged", () => {
  it("across every route, refusal, error and the happy paths, no console method is called", async () => {
    const spies = (["log", "info", "warn", "error", "debug", "trace"] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    const matrix: Array<[Record<string, unknown>, string, string, Record<string, string>, unknown]> = [
      [{}, "POST", "options", { origin: ORIGIN }, {}],
      [{}, "POST", "verify", {}, verifyBody()],
      [{ verify: { ok: false, counterOnly: false } }, "POST", "verify", {}, verifyBody()],
      [{ mintStatus: "signature_invalid" }, "POST", "verify", {}, verifyBody()],
      [{ throwIn: "mint" }, "POST", "verify", {}, verifyBody()],
      [{ throwIn: "whoami" }, "GET", "session", authed(), undefined],
      [{ bindRefused: true }, "GET", "session", authed(), undefined],
      [{}, "GET", "session", { authorization: `Bearer ${JWT}` }, undefined],
      [{}, "POST", "reauth", authed(), { challengeToken: challengeToken(), credential: credentialJson() }],
      [{}, "POST", "nope", {}, {}],
      [{}, "OPTIONS", "verify", { origin: ORIGIN }, undefined],
      [{}, "GET", "session", { origin: "https://evil.example.test" }, undefined],
      // S1.3: the PIN and email-proof routes, happy and refused
      [{}, "GET", "pin", authed(), undefined],
      [{}, "POST", "step-up/pin", authed(), { derived: DERIVED_FOR_LOG }],
      [{ pinVerify: { status: "wrong", retryAfterSeconds: 30, grantUntil: null } }, "POST", "step-up/pin", authed(), { derived: DERIVED_FOR_LOG }],
      [{ pinWrite: { status: "locked", retryAfterSeconds: 0 } }, "POST", "pin/set", authed(), { derived: DERIVED_FOR_LOG, salt: SALT_FOR_LOG, iterations: 600000 }],
      [{}, "POST", "pin/change", authed(), { currentDerived: DERIVED_FOR_LOG, derived: DERIVED_FOR_LOG, salt: SALT_FOR_LOG, iterations: 600000 }],
      [{}, "POST", "otp-proof/start", authed(), {}],
      [{ otpSendThrows: true }, "POST", "otp-proof/start", authed(), {}],
      [{}, "POST", "otp-proof/verify", authed(), { code: "123456" }],
      [{ otpVerifyOk: false }, "POST", "otp-proof/verify", authed(), { code: "123456" }],
    ];
    for (const [state, method, path, headers, body] of matrix) {
      const f = makeFakes(state);
      await handlePartnerSessionRequest(req(method, path, { headers, body }), f.deps);
    }
    for (const s of spies) expect(s).not.toHaveBeenCalled();
  });
});
