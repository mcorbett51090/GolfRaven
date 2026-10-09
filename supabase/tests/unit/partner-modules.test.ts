// supabase/tests/unit/partner-modules.test.ts
//
// The pure helpers of the partner lane (docs/security/partner-auth-design.md 4.6, S1.2): the CORS decision, the exact media type, the token, the strict body shapes, and the structural rules a
// behavioural test cannot state as strongly (they read the source, like marker-scan-entrypoint.test.ts): no `console` anywhere in the partner modules (PA-11), `verify_jwt = false` for the function,
// the partner function never calls `getActorFromRequest`, and the entrypoint reads no environment.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { baseHeaders, decideOrigin, parseAllowedOrigin, preflightResponse } from "../../functions/_shared/partner/cors.ts";
import { isExactJsonMediaType, partnerError, readPartnerJsonBody, UNAUTHENTICATED_BODY, unauthenticated } from "../../functions/_shared/partner/http.ts";
import { fromB64u, newPartnerSessionToken, PARTNER_SESSION_TOKEN_RE, partnerTokenFromHeader, sha256Hex, toB64u, toHex } from "../../functions/_shared/partner/token.ts";
import { parseChallengeToken, parseEmptyBody, parseReauthBody, parseVerifyBody, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { challengeToken, credentialJson, NOW_MS } from "./partner-fakes.ts";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");
/** The partner lane's Edge Functions (design 4.5): each is a directory with an `index.ts`, `verify_jwt = false`, and no use of the player identity. */
const PARTNER_FUNCTIONS = ["partner-session", "partner-invites", "partner-members"];
const REPO = join(import.meta.dirname, "..", "..", "..");

describe("cors.ts", () => {
  const h = (origin?: string) => new Headers(origin === undefined ? {} : { origin });
  it("decideOrigin: none, allowed (exact string equality only) and refused", () => {
    expect(decideOrigin(h(), "https://a.test")).toEqual({ kind: "none" });
    expect(decideOrigin(h("https://a.test"), "https://a.test")).toEqual({ kind: "allowed", origin: "https://a.test" });
    for (const o of ["https://a.test/", "https://A.test", "http://a.test", "https://a.test:443", "https://a.test.evil.test", "https://evil.a.test", "null", "", "*", "https://a.test, https://b.test"]) {
      expect(decideOrigin(h(o), "https://a.test"), JSON.stringify(o)).toEqual({ kind: "refused" });
    }
    expect(decideOrigin(h("https://a.test"), null)).toEqual({ kind: "refused" });
    expect(decideOrigin(h(), null)).toEqual({ kind: "none" });
  });

  it("baseHeaders: no-store, Vary: Origin, nosniff; the CORS header only for the allowed origin; never a credentials header", () => {
    for (const d of [{ kind: "none" }, { kind: "refused" }] as const) {
      const b = baseHeaders(d);
      expect(b.get("access-control-allow-origin")).toBeNull();
      expect(b.get("cache-control")).toBe("no-store");
      expect(b.get("vary")).toBe("Origin");
      expect(b.get("x-content-type-options")).toBe("nosniff");
    }
    const a = baseHeaders({ kind: "allowed", origin: "https://a.test" });
    expect(a.get("access-control-allow-origin")).toBe("https://a.test");
    expect(a.get("access-control-allow-credentials")).toBeNull();
  });

  it("preflightResponse: 204 with the lists only for the allowed origin", () => {
    const ok = preflightResponse({ kind: "allowed", origin: "https://a.test" });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("access-control-allow-methods")).toBe("GET, POST, PATCH, DELETE, OPTIONS");
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://a.test");
    const none = preflightResponse({ kind: "none" });
    expect(none.status).toBe(204);
    expect(none.headers.get("access-control-allow-methods")).toBeNull();
  });

  it("parseAllowedOrigin: unset is null; an exact https origin passes; anything else throws (a malformed origin must stop the function at boot)", () => {
    expect(parseAllowedOrigin(undefined)).toBeNull();
    expect(parseAllowedOrigin(null)).toBeNull();
    expect(parseAllowedOrigin("")).toBeNull();
    expect(parseAllowedOrigin("https://partners.example.test")).toBe("https://partners.example.test");
    expect(parseAllowedOrigin("https://partners.example.test:8443")).toBe("https://partners.example.test:8443");
    for (const bad of ["https://partners.example.test/", "http://partners.example.test", "partners.example.test", "https://partners.example.test/path", "https://user@partners.example.test", "*", "https://A.example.test", "https://a.test https://b.test"]) {
      expect(() => parseAllowedOrigin(bad), bad).toThrow();
    }
  });
});

describe("http.ts", () => {
  it("isExactJsonMediaType: application/json and `charset=utf-8` only", () => {
    for (const ok of ["application/json", "Application/JSON", "application/json; charset=utf-8", "application/json;charset=UTF-8", ' application/json ; charset="utf-8" ']) expect(isExactJsonMediaType(ok), ok).toBe(true);
    for (const bad of [null, "", "text/plain; x=application/json", "application/json; x=1", "application/json; charset=latin1", "application/json; charset=utf-8; x=1", "application/jsonp", "application/json5", "application/vnd.api+json", "application/json,text/plain", "text/json"]) {
      expect(isExactJsonMediaType(bad), String(bad)).toBe(false);
    }
  });

  it("readPartnerJsonBody: 415 BEFORE the body is touched; 413 and 400 are the shared reader's", async () => {
    let touched = false;
    const spy = { headers: new Headers({ "content-type": "text/plain; x=application/json" }), get body() { touched = true; return null; } } as unknown as Request;
    await expect(readPartnerJsonBody(spy)).rejects.toMatchObject({ status: 415 });
    expect(touched).toBe(false);
    const post = (raw: string, ct = "application/json") => new Request("https://x.test/", { method: "POST", headers: { "content-type": ct }, body: raw });
    await expect(readPartnerJsonBody(post('{"a":1}'))).resolves.toEqual({ a: 1 });
    await expect(readPartnerJsonBody(post("x".repeat(70_000)))).rejects.toMatchObject({ status: 413 });
    await expect(readPartnerJsonBody(post("{"))).rejects.toMatchObject({ status: 400 });
    await expect(readPartnerJsonBody(new Request("https://x.test/", { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0xff, 0xfe]) }))).rejects.toMatchObject({ status: 400 });
  });

  it("the 401 is one constant body, and partnerError carries no details", async () => {
    const a = unauthenticated({ kind: "none" });
    const b = unauthenticated({ kind: "allowed", origin: "https://a.test" });
    expect(await a.text()).toBe(JSON.stringify(UNAUTHENTICATED_BODY));
    expect(await b.text()).toBe(JSON.stringify(UNAUTHENTICATED_BODY));
    expect(await partnerError({ kind: "none" }, 418, "teapot", "short and stout").text()).toBe('{"error":{"code":"teapot","message":"short and stout"}}');
  });
});

describe("token.ts", () => {
  it("base64url: unpadded, canonical, round-trips every length, refuses stray bits, padding and the standard alphabet", () => {
    for (let n = 0; n <= 40; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      const s = toB64u(b);
      expect(s).not.toMatch(/[=+/]/);
      expect(Array.from(fromB64u(s)!)).toEqual(Array.from(b));
    }
    expect(fromB64u("AAAB")).not.toBeNull();
    for (const bad of ["AAAA=", "A", "AAAAA", "AB", "+/+/", "AA A", "é", "AAAAB"]) expect(fromB64u(bad), bad).toBeNull();
    expect(toB64u(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
  });

  it("sha256Hex matches the published vector; toHex is lower-case two-digit", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(toHex(new Uint8Array([0, 1, 255]))).toBe("0001ff");
  });

  it("newPartnerSessionToken: gr_ps_ + 43 characters, hash = sha256(token), unique", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const t = await newPartnerSessionToken();
      expect(t.token).toMatch(PARTNER_SESSION_TOKEN_RE);
      expect(t.token).toHaveLength(49);
      expect(t.hash).toBe(await sha256Hex(t.token));
      expect(t.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(seen.has(t.token)).toBe(false);
      seen.add(t.token);
    }
  });

  it("partnerTokenFromHeader accepts only `Bearer gr_ps_<43>`", async () => {
    const t = (await newPartnerSessionToken()).token;
    expect(partnerTokenFromHeader(`Bearer ${t}`)).toBe(t);
    expect(partnerTokenFromHeader(`bearer ${t}`)).toBe(t);
    for (const bad of [null, "", t, `Basic ${t}`, `Bearer ${t}x`, `Bearer ${t.slice(0, -1)}`, `Bearer ${t} y`, "Bearer eyJhbGciOi.e30.sig", `Bearer  ${t}`, `Bearer ${t.replace("gr_ps_", "gr_inv_")}`]) {
      expect(partnerTokenFromHeader(bad), String(bad)).toBeNull();
    }
  });
});

describe("session-shape.ts", () => {
  it("parseEmptyBody: exactly {}", () => {
    expect(parseEmptyBody({})).toEqual({ ok: true, value: {} });
    expect(parseEmptyBody({ a: 1 }).ok).toBe(false);
    for (const bad of [null, [], "x", 1]) expect(parseEmptyBody(bad).ok).toBe(false);
  });

  it("parseChallengeToken: 32-byte nonce and MAC, a plain integer expiry", () => {
    expect(parseChallengeToken(challengeToken(1_900_000_000))).toMatchObject({ exp: 1_900_000_000 });
    for (const bad of [1, null, "", "a.b.c", `${"A".repeat(43)}.1.${"A".repeat(42)}`, `${"A".repeat(43)}.x.${"A".repeat(43)}`, `${"A".repeat(43)}.1.${"A".repeat(43)}.`, `${"A".repeat(42)}B.1.${"A".repeat(43)}`]) {
      expect(parseChallengeToken(bad), String(bad)).toBeNull();
    }
  });

  it("parseVerifyBody / parseReauthBody: a well-formed body decodes every field; pop_jkt only on verify; every limit is enforced", () => {
    const ok = parseVerifyBody({ challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: "abc" });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.value.popJkt).toBe("abc");
      expect(ok.value.assertion.credentialId).toHaveLength(32);
      expect(ok.value.assertion.authenticatorData).toHaveLength(37);
      expect(ok.value.assertion.json.clientExtensionResults).toEqual({});
    }
    expect(parseReauthBody({ challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: "abc" }).ok).toBe(false);
    expect(parseReauthBody({ challengeToken: challengeToken(), credential: credentialJson() }).ok).toBe(true);
    const bad = (credential: unknown) => parseVerifyBody({ challengeToken: challengeToken(), credential }).ok;
    expect(bad(credentialJson({}, { userHandle: undefined }))).toBe(true);
    expect(bad(credentialJson({ id: "A".repeat(20), rawId: "A".repeat(20) }))).toBe(false); // 15 bytes
    expect(bad(credentialJson({}, { clientDataJSON: "" }))).toBe(false);
    expect(bad(credentialJson({}, { authenticatorData: toB64u(new Uint8Array(36)) }))).toBe(false);
    expect(bad(credentialJson({}, { authenticatorData: toB64u(new Uint8Array(4097)) }))).toBe(false);
    expect(bad(credentialJson({}, { signature: toB64u(new Uint8Array(1025)) }))).toBe(false);
    expect(bad(credentialJson({}, { userHandle: toB64u(new Uint8Array(65)) }))).toBe(false);
    expect(bad(credentialJson({ clientExtensionResults: "x" }))).toBe(false);
    expect(parseVerifyBody({ challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: "" }).ok).toBe(false);
    expect(parseVerifyBody({ challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: "x".repeat(65) }).ok).toBe(false);
    expect(parseVerifyBody({ challengeToken: challengeToken(), credential: credentialJson(), pop_jkt: null }).ok).toBe(true);
  });

  it("uuidToBytes: 16 bytes of a canonical uuid, null for anything else", () => {
    expect(Array.from(uuidToBytes("00000000-0000-0000-0000-1000000000a1")!)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0xa1]);
    for (const bad of ["", "not-a-uuid", "00000000000000000000000000000001", "00000000-0000-0000-0000-00000000000g", "00000000-0000-0000-0000-00000000000"]) expect(uuidToBytes(bad), bad).toBeNull();
    expect(NOW_MS).toBeGreaterThan(0);
  });
});

/** The text of a source file with comments and string / template literals blanked, so a word in prose or in a message is not a use. */
function code(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    const n = text[i + 1];
    if (c === "/" && n === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && n === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
    } else if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < text.length && text[i] !== q) i += text[i] === "\\" ? 2 : 1;
      i++;
      out += '""';
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

function partnerFiles(): string[] {
  const dirs = [join(FUNCTIONS, "_shared", "partner"), ...PARTNER_FUNCTIONS.map((f) => join(FUNCTIONS, f))];
  return dirs.flatMap((d) => readdirSync(d).filter((f) => f.endsWith(".ts")).map((f) => join(d, f)));
}

describe("PA-11: the partner modules never log", () => {
  it("finds the modules it is meant to scan", () => {
    const names = partnerFiles().map((p) => p.split("/").slice(-2).join("/"));
    for (const n of ["partner/cors.ts", "partner/http.ts", "partner/session-handler.ts", "partner/session-shape.ts", "partner/token.ts", "partner/ports.ts", "partner/webauthn.ts", "partner/webauthn-port.ts", "partner-session/index.ts", "partner/pin-contract.ts", "partner/pin-deny-list.ts", "partner/pin-vectors.ts", "partner/totp-contract.ts", "partner-invites/index.ts", "partner-members/index.ts", "partner/invites-handler.ts", "partner/members-handler.ts", "partner/handler-kit.ts", "partner/invites-shape.ts", "partner/members-shape.ts", "partner/registration-shape.ts"]) expect(names).toContain(n);
  });

  it("no `console` identifier appears anywhere in code (comments and strings aside) in the partner modules, the function entrypoint or the partner lane section of privileged.ts", () => {
    for (const f of partnerFiles()) expect(code(readFileSync(f, "utf8")), f).not.toMatch(/\bconsole\b/);
    const priv = readFileSync(join(FUNCTIONS, "_shared", "privileged.ts"), "utf8");
    const start = priv.indexOf("PARTNER LANE (S1.2): docs/security/partner-auth-design.md 4.2 / 4.4 / 4.5 / 8. BEGIN");
    const end = priv.indexOf("PARTNER LANE (S1.2) END");
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    expect(code(priv.slice(start, end)), "the partner section of privileged.ts").not.toMatch(/\bconsole\b/);
  });

  it("the scanner itself works: it sees a real use, and ignores prose and strings", () => {
    expect(code('console.log("x")')).toMatch(/\bconsole\b/);
    expect(code("globalThis.console.error(1)")).toMatch(/\bconsole\b/);
    expect(code('// console.log(1)\n/* console.log(2) */ const s = "console.log(3)"; const t = `console.log(4)`;')).not.toMatch(/\bconsole\b/);
  });
});

describe("S1.3: the PIN never reaches the Edge, and the contract is importable by a browser", () => {
  const dir = join(FUNCTIONS, "_shared", "partner");
  const imports = (file: string): string[] => [...readFileSync(join(dir, file), "utf8").matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"/gm)].map((m) => m[1]!);

  it("pin-contract.ts imports only ./token.ts, and pin-deny-list.ts and pin-vectors.ts import nothing: the same files run in a browser, in Deno and in Node", () => {
    expect(imports("pin-contract.ts")).toEqual(["./token.ts"]);
    expect(imports("pin-deny-list.ts")).toEqual([]);
    expect(imports("pin-vectors.ts")).toEqual([]);
    expect(imports("token.ts")).toEqual([]);
  });

  it("only pin-contract.ts runs PBKDF2: no other partner module derives a key, and neither the handler nor the body parsers import the derivation (the Edge handles derived BYTES, never a PIN)", () => {
    for (const f of readdirSync(dir).filter((x) => x.endsWith(".ts") && x !== "pin-contract.ts")) {
      expect(code(readFileSync(join(dir, f), "utf8")), f).not.toMatch(/deriveBits|PBKDF2|derivePinKey/);
    }
    for (const f of ["session-handler.ts", "session-shape.ts", "ports.ts"]) expect(imports(f).filter((i) => i.includes("pin-deny-list") || i.includes("pin-vectors")), f).toEqual([]);
    expect(code(readFileSync(join(dir, "session-shape.ts"), "utf8"))).not.toMatch(/derivePinKey|pinRejection|isWellFormedPin/);
  });

  it("no request shape, port method or handler names a field `pin` (the bodies carry `derived`, `currentDerived`, `salt`, `iterations` and `code` only)", () => {
    for (const f of ["session-handler.ts", "session-shape.ts", "ports.ts"]) {
      expect(code(readFileSync(join(dir, f), "utf8")), f).not.toMatch(/\.pin\b|\bpin\s*:\s*string|\bpin\s*\?\s*:|\(pin\b/);
    }
  });
});

describe("the entrypoints and the configuration", () => {
  const HANDLERS: Readonly<Record<string, string>> = {
    "partner-session": "handlePartnerSessionRequest",
    "partner-invites": "handlePartnerInvitesRequest",
    "partner-members": "handlePartnerMembersRequest",
  };

  it("lists exactly the partner functions that exist: every directory under functions/ that holds a partner-* entrypoint is named here", () => {
    const onDisk = readdirSync(FUNCTIONS, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name.startsWith("partner-")).map((d) => d.name).sort();
    expect(onDisk).toEqual([...PARTNER_FUNCTIONS].sort());
    expect(Object.keys(HANDLERS).sort()).toEqual([...PARTNER_FUNCTIONS].sort());
  });

  for (const fn of PARTNER_FUNCTIONS) {
    it(`${fn}/index.ts never calls getActorFromRequest (a partner token is never a Supabase identity), reads no environment and opens no connection`, () => {
      const c = code(readFileSync(join(FUNCTIONS, fn, "index.ts"), "utf8"));
      expect(c).not.toMatch(/getActorFromRequest|withOwnership|Deno\.env|createClient|postgres/);
      expect(c).toMatch(new RegExp(HANDLERS[fn]!));
      expect(c).toMatch(/loadPartnerCorsOrigin\(\)/);
    });
  }

  it("no partner module imports getActorFromRequest or reaches GoTrue", () => {
    for (const f of partnerFiles()) expect(code(readFileSync(f, "utf8")), f).not.toMatch(/getActorFromRequest|supabase-js|createClient|auth\.getUser/);
  });

  it("supabase/config.toml sets verify_jwt = false for every partner function (and for no player function)", () => {
    const toml = readFileSync(join(REPO, "supabase", "config.toml"), "utf8");
    for (const fn of PARTNER_FUNCTIONS) {
      const m = new RegExp(`\\[functions\\.${fn}\\]([\\s\\S]*?)(?=\\n\\[|$)`).exec(toml);
      expect(m, `a [functions.${fn}] table`).not.toBeNull();
      expect(m![1]!.replace(/^\s*#.*$/gm, ""), fn).toMatch(/^\s*verify_jwt\s*=\s*false\s*$/m);
    }
    const others = [...toml.matchAll(/\[functions\.([a-z-]+)\]/g)].map((x) => x[1]);
    expect(others).toEqual([...PARTNER_FUNCTIONS]);
  });
});
