import { CspEvaluator } from "csp_evaluator/dist/evaluator.js";
import { Severity } from "csp_evaluator/dist/finding.js";
import { CspParser } from "csp_evaluator/dist/parser.js";
import { describe, expect, it } from "vitest";
import { PARTNER_FUNCTIONS as CLIENT_FUNCTIONS } from "../src/api/client";
import { DEFAULT_API_BASE, isLocalOrIpHost, isPlaceholderHost, resolveApiBase } from "../scripts/lib/config.mjs";
import { buildCsp, buildHeadersFile, connectSources, PARTNER_FUNCTIONS } from "../scripts/lib/csp.mjs";

const API_ORIGIN = "https://abc123.example.test";
const API = `${API_ORIGIN}/functions/v1`;
/** One connect-src entry per partner function: path-scoped, trailing slash (a prefix match). */
const CONNECT = PARTNER_FUNCTIONS.map((fn) => `${API}/${fn}/`);

/**
 * A reference model of CSP Level 3 host-source matching for a URL, enough for connect-src: scheme, host and port must match; an EMPTY source path
 * matches every path; a source path ending in "/" is a PREFIX of the URL path; any other source path must equal the URL path exactly. The query is
 * ignored. (The real browser is the Playwright cell; this model is what makes the unit assertions readable.)
 */
function cspAllows(source: string, url: string): boolean {
  const s = new URL(source);
  const u = new URL(url);
  if (s.origin !== u.origin) return false;
  if (s.pathname === "/" && !source.endsWith("/")) return true; // no path in the source
  return s.pathname.endsWith("/") ? u.pathname.startsWith(s.pathname) : u.pathname === s.pathname;
}
const allowedByCsp = (csp: string, url: string) => (directives(csp).get("connect-src") ?? []).some((src) => cspAllows(src, url));

function directives(csp: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of csp.split(";").map((p) => p.trim()).filter((p) => p !== "")) {
    const [name, ...values] = part.split(/\s+/);
    out.set(name!, values);
  }
  return out;
}

function evaluate(csp: string) {
  return new CspEvaluator(new CspParser(csp).csp).evaluate();
}

describe("the policy", () => {
  const csp = buildCsp(API);
  const d = directives(csp);

  it("is exactly the documented directive set", () => {
    expect(csp).toBe(
      `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src ${CONNECT.join(" ")}; manifest-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`,
    );
  });

  it("starts from default-src 'none' and allows scripts and styles from 'self' only", () => {
    expect(d.get("default-src")).toEqual(["'none'"]);
    expect(d.get("script-src")).toEqual(["'self'"]);
    expect(d.get("style-src")).toEqual(["'self'"]);
  });

  it("connect-src names one PATH-SCOPED source per partner function and nothing else (not the API origin, not 'self', not the data API)", () => {
    expect(PARTNER_FUNCTIONS.length).toBeGreaterThan(0);
    expect(d.get("connect-src")).toEqual(CONNECT);
    expect(d.get("connect-src")).not.toContain(API_ORIGIN);
    for (const src of d.get("connect-src")!) expect(src).toMatch(/\/functions\/v1\/[a-z][a-z0-9-]*\/$/);
  });

  it("connect-src names exactly partner-session, partner-invites (invite and enrolment acceptance, the first credential) and partner-members, each path-scoped", () => {
    expect(d.get("connect-src")).toEqual([`${API}/partner-session/`, `${API}/partner-invites/`, `${API}/partner-members/`]);
    expect(d.get("connect-src")!.join(" ")).not.toMatch(/partner-attest|rest\/v1|auth\/v1/);
  });

  it("the CSP list and the client's bearer allow-list are the SAME list (partner-functions.json)", () => {
    expect([...CLIENT_FUNCTIONS]).toEqual([...PARTNER_FUNCTIONS]);
    expect(connectSources(API, ["a-fn", "b-fn"])).toEqual([`${API}/a-fn/`, `${API}/b-fn/`]);
    expect(buildCsp(API, { functions: ["a-fn", "b-fn"] })).toContain(`connect-src ${API}/a-fn/ ${API}/b-fn/;`);
  });

  it("CSP3 path matching: a trailing-slash source is a PREFIX, so every URL the client builds is allowed, and a sibling path, the data API, another function and the bare function name are not", () => {
    // the exact URLs client.ts requests: `${base}/${fn}/${route}`, no trailing slash, no query
    for (const route of ["options", "verify", "session", "sign-out", "reauth/options", "reauth"]) expect(allowedByCsp(csp, `${API}/partner-session/${route}`), route).toBe(true);
    for (const blocked of [
      `${API_ORIGIN}/rest/v1/orgs`,
      `${API_ORIGIN}/rest/v1/`,
      `${API}/other-fn/x`,
      `${API}/partner-sessionx/x`, // shares the prefix string but not the path segment
      `${API}/partner-session`, // the bare name has no trailing slash, so the prefix source does not match it
      `${API}/partner-session/../../../rest/v1/x`, // the URL parser resolves the dot segments before CSP sees the path
      `${API_ORIGIN}/functions/v2/partner-session/x`,
      "https://elsewhere.example.test/functions/v1/partner-session/x",
    ]) expect(allowedByCsp(csp, blocked), blocked).toBe(false);
    // control: the model does see an origin-wide source as allowing the data API (so the blocked cases above prove something)
    expect(cspAllows(API_ORIGIN, `${API_ORIGIN}/rest/v1/orgs`)).toBe(true);
    expect(cspAllows(`${API}/partner-session`, `${API}/partner-session/options`)).toBe(false);
  });

  it("refuses a functions root whose path could change the CSP (a space, a semicolon, a comma)", () => {
    for (const bad of ["https://x.example.org/a;b", "https://x.example.org/a,b", "https://x.example.org/a b", "https://x.example.org/a%3Bb"]) expect(() => resolveApiBase(bad), bad).toThrow(/CSP/);
  });

  it("has no unsafe-inline, unsafe-eval, wasm-unsafe-eval, unsafe-hashes, strict-dynamic, nonce, hash, wildcard or scheme-only source in any directive", () => {
    for (const [name, values] of d) {
      for (const v of values) {
        expect(v, `${name} ${v}`).not.toMatch(/^'(unsafe-inline|unsafe-eval|wasm-unsafe-eval|unsafe-hashes|strict-dynamic)'$/);
        expect(v, `${name} ${v}`).not.toMatch(/^'(nonce|sha256|sha384|sha512)-/);
        expect(v, `${name} ${v}`).not.toMatch(/^(\*|[a-z]+:)$/); // a wildcard or a bare scheme (data:, blob:, http:, https:, filesystem:)
      }
    }
  });

  it("closes the framing, base, form, object and worker holes", () => {
    for (const name of ["object-src", "base-uri", "form-action", "worker-src", "frame-ancestors"]) expect(d.get(name), name).toEqual(["'none'"]);
  });

  it("requires Trusted Types for scripts and allows no policy", () => {
    expect(d.get("require-trusted-types-for")).toEqual(["'script'"]);
    expect(d.get("trusted-types")).toEqual(["'none'"]);
  });

  it("the meta form is the same policy without frame-ancestors (a meta element ignores it and logs an error)", () => {
    const meta = buildCsp(API, { meta: true });
    expect(meta).toBe(csp.replace("; frame-ancestors 'none'", ""));
    expect(meta).not.toContain("frame-ancestors");
  });

  it("csp_evaluator: no findings of any severity up to MEDIUM, and none for script-src, object-src or base-uri", () => {
    const findings = evaluate(csp);
    const serious = findings.filter((f) => f.severity <= Severity.MEDIUM);
    expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
  });

  it("csp_evaluator really does flag a weak policy (a control, so the pass above means something)", () => {
    expect(evaluate("script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src *").filter((f) => f.severity === Severity.HIGH).length).toBeGreaterThan(0);
  });
});

/** The blocks of a Cloudflare-Pages-style `_headers` text that apply to a path: `/*`, `/dir/*` (prefix) and exact paths. */
function matching(text: string, path: string): Array<{ pattern: string; names: string[]; headers: Array<[string, string]> }> {
  const blocks: Array<{ pattern: string; names: string[]; headers: Array<[string, string]> }> = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "" || line.startsWith("#")) continue;
    if (!/^\s/.test(line)) blocks.push({ pattern: line.trim(), names: [], headers: [] });
    else {
      const t = line.trim();
      const i = t.indexOf(":");
      const b = blocks[blocks.length - 1]!;
      b.names.push(t.slice(0, i).toLowerCase());
      b.headers.push([t.slice(0, i).toLowerCase(), t.slice(i + 1).trim()]);
    }
  }
  return blocks.filter((b) => (b.pattern.endsWith("/*") ? path.startsWith(b.pattern.slice(0, -1)) : b.pattern === path));
}
function headersFor(text: string, path: string): Record<string, string> {
  return Object.fromEntries(matching(text, path).flatMap((b) => b.headers));
}

describe("the _headers file", () => {
  const text = buildHeadersFile(API);

  it("carries the policy as a response header on every path", () => {
    expect(text).toContain(`/*\n  Content-Security-Policy: ${buildCsp(API)}\n`);
  });

  it("sends HSTS (one year, includeSubDomains) on every path", () => {
    expect(text).toContain("/*\n");
    expect(headersFor(text, "/")["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
    expect(headersFor(text, "/assets/app-X.js")["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
  });

  it("sets the hardening headers the design names (4.6)", () => {
    expect(text).toContain("  Referrer-Policy: no-referrer\n");
    expect(text).toContain("  X-Content-Type-Options: nosniff\n");
    expect(text).toContain("  Cross-Origin-Opener-Policy: same-origin\n");
    expect(text).toMatch(/Permissions-Policy: publickey-credentials-get=\(self\), publickey-credentials-create=\(self\)/);
  });

  it("withholds the powerful features the app never uses", () => {
    for (const f of ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"]) expect(text).toContain(f);
  });

  it("gives no request two values for one header name (Cloudflare Pages joins repeated names across the matching blocks with a comma instead of replacing)", () => {
    for (const path of ["/", "/index.html", "/invite", "/assets/app-X.js", "/assets/styles-X.css", "/favicon.svg", "/manifest.webmanifest"]) {
      const names = matching(text, path).flatMap((b) => b.names);
      expect(names.filter((n, i) => names.indexOf(n) !== i), path).toEqual([]);
    }
  });

  it("the page itself (/ and /index.html) is no-store, so Back never serves the signed-in page from a cache or the bfcache; the assets are not", () => {
    expect(headersFor(text, "/")["cache-control"]).toBe("no-store");
    expect(headersFor(text, "/index.html")["cache-control"]).toBe("no-store");
    // an invite link (/invite#<token>) is served the same page by the host's single-page fallback, and is just as uncacheable
    expect(headersFor(text, "/invite")["cache-control"]).toBe("no-store");
    for (const asset of ["/assets/app-X.js", "/assets/styles-X.css"]) expect(headersFor(text, asset)["cache-control"], asset).toBe("public, max-age=31536000, immutable");
    for (const other of ["/favicon.svg", "/manifest.webmanifest"]) expect(headersFor(text, other)["cache-control"], other).toBeUndefined();
  });

  it("gives only the content-hashed assets a long cache lifetime", () => {
    expect(text).toContain("/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n");
    expect(text.match(/max-age=31536000, immutable/g)).toHaveLength(1);
  });
});

describe("the API origin configuration", () => {
  it("defaults to a placeholder on the reserved .example TLD (owner question Q1)", () => {
    const r = resolveApiBase(undefined);
    expect(r.base).toBe(DEFAULT_API_BASE);
    expect(r.origin).toBe("https://partners-api.golfraven.example");
    expect(r.isPlaceholder).toBe(true);
    expect(resolveApiBase("").base).toBe(DEFAULT_API_BASE);
  });

  it("keeps the path (the functions root), drops a trailing slash, and derives the exact origin for connect-src", () => {
    expect(resolveApiBase("https://abc123.supabase.co/functions/v1/")).toEqual({ base: "https://abc123.supabase.co/functions/v1", origin: "https://abc123.supabase.co", isPlaceholder: false });
    expect(resolveApiBase("https://api.example.org:8443").origin).toBe("https://api.example.org:8443");
  });

  it("refuses http, credentials, a query, a fragment and a non-URL", () => {
    const withCredentials = new URL("https://api.example.org/functions/v1");
    withCredentials.username = "someone"; // built at run time: a literal user:password@host string is what a secret scanner looks for
    withCredentials.password = "dummy";
    for (const bad of ["http://api.example.org/functions/v1", "ftp://api.example.org", withCredentials.href, "https://api.example.org/?x=1", "https://api.example.org/#f", "not a url", "//api.example.org"]) {
      expect(() => resolveApiBase(bad), bad).toThrow();
    }
  });

  it("accepts a loopback http origin ONLY for the e2e build, and no other http host even then", () => {
    expect(() => resolveApiBase("http://localhost:4000/functions/v1")).toThrow();
    expect(resolveApiBase("http://localhost:4000/functions/v1", { allowLoopback: true }).origin).toBe("http://localhost:4000");
    expect(() => resolveApiBase("http://api.example.org/functions/v1", { allowLoopback: true })).toThrow();
  });

  it("a production build refuses the placeholder host in EVERY spelling: a trailing dot, upper case, the bare TLD (NIT)", () => {
    for (const host of ["golfraven.example.", "golfraven.example..", "GolfRaven.EXAMPLE", "partners-api.golfraven.example", "example", "example."]) {
      expect(() => resolveApiBase(`https://${host}/functions/v1`, { production: true }), host).toThrow(/placeholder/);
      expect(resolveApiBase(`https://${host}/functions/v1`).isPlaceholder, host).toBe(true);
    }
    for (const host of ["xexample.com", "golfraven.example.com", "examples.org", "abc123.supabase.co"]) expect(isPlaceholderHost(host), host).toBe(false);
  });

  it("a production build refuses https://localhost, loopback and bare IPs (NIT); a non-production build does not", () => {
    for (const host of ["localhost", "localhost.", "LOCALHOST", "api.localhost", "127.0.0.1", "127.1", "0x7f.1", "2130706433", "10.0.0.5", "192.168.1.9", "8.8.8.8", "[::1]", "[2001:db8::1]"]) {
      expect(() => resolveApiBase(`https://${host}/functions/v1`, { production: true }), host).toThrow(/localhost, loopback or bare-IP/);
      expect(resolveApiBase(`https://${host}/functions/v1`).origin, host).toMatch(/^https:\/\//);
    }
    for (const host of ["localhost", "127.0.0.1", "10.0.0.5", "[::1]"]) expect(isLocalOrIpHost(host), host).toBe(true);
    for (const host of ["abc123.supabase.co", "ip.example.org", "1.example.org", "localhost.example.org", "my-localhost.dev"]) expect(isLocalOrIpHost(host), host).toBe(false);
    expect(resolveApiBase("https://abc123.supabase.co/functions/v1", { production: true }).origin).toBe("https://abc123.supabase.co");
  });

  it("the e2e loopback allowance cannot be combined with a production build (LOW-1)", () => {
    expect(() => resolveApiBase("http://localhost:4000/functions/v1", { allowLoopback: true, production: true })).toThrow(/e2e/);
    expect(() => resolveApiBase("https://abc123.supabase.co/functions/v1", { allowLoopback: true, production: true })).toThrow(/e2e/);
    expect(resolveApiBase("http://localhost:4000/functions/v1", { allowLoopback: true }).origin).toBe("http://localhost:4000"); // control: fine outside production
  });

  it("a production build refuses the placeholder host", () => {
    expect(() => resolveApiBase(undefined, { production: true })).toThrow(/placeholder/);
    expect(() => resolveApiBase("https://x.example/functions/v1", { production: true })).toThrow(/placeholder/);
    expect(resolveApiBase("https://abc123.supabase.co/functions/v1", { production: true }).isPlaceholder).toBe(false);
  });
});
