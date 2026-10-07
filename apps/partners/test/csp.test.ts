import { CspEvaluator } from "csp_evaluator/dist/evaluator.js";
import { Severity } from "csp_evaluator/dist/finding.js";
import { CspParser } from "csp_evaluator/dist/parser.js";
import { describe, expect, it } from "vitest";
import { DEFAULT_API_BASE, resolveApiBase } from "../scripts/lib/config.mjs";
import { buildCsp, buildHeadersFile } from "../scripts/lib/csp.mjs";

const API = "https://abc123.example.test";

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
      `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src ${API}; manifest-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`,
    );
  });

  it("starts from default-src 'none' and allows scripts and styles from 'self' only", () => {
    expect(d.get("default-src")).toEqual(["'none'"]);
    expect(d.get("script-src")).toEqual(["'self'"]);
    expect(d.get("style-src")).toEqual(["'self'"]);
  });

  it("connect-src names the partners API origin and nothing else (not 'self', not the data API)", () => {
    expect(d.get("connect-src")).toEqual([API]);
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

describe("the _headers file", () => {
  const text = buildHeadersFile(API);

  it("carries the policy as a response header on every path", () => {
    expect(text).toContain(`/*\n  Content-Security-Policy: ${buildCsp(API)}\n`);
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

  it("repeats no header name across the blocks (Cloudflare Pages joins repeated names with a comma instead of replacing)", () => {
    const blocks = text.split(/\n\n/).map((b) => b.split("\n").filter((l) => /^\s+[A-Za-z-]+:/.test(l)).map((l) => l.trim().split(":")[0]!.toLowerCase()));
    const seen = new Set<string>();
    for (const names of blocks) for (const n of names) {
      expect(seen.has(n), n).toBe(false);
      seen.add(n);
    }
  });

  it("gives only the content-hashed assets a long cache lifetime", () => {
    expect(text).toContain("/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n");
    expect(text.match(/Cache-Control/g)).toHaveLength(1);
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
    for (const bad of ["http://api.example.org/functions/v1", "ftp://api.example.org", "https://user:pw@api.example.org", "https://api.example.org/?x=1", "https://api.example.org/#f", "not a url", "//api.example.org"]) {
      expect(() => resolveApiBase(bad), bad).toThrow();
    }
  });

  it("accepts a loopback http origin ONLY for the e2e build, and no other http host even then", () => {
    expect(() => resolveApiBase("http://localhost:4000/functions/v1")).toThrow();
    expect(resolveApiBase("http://localhost:4000/functions/v1", { allowLoopback: true }).origin).toBe("http://localhost:4000");
    expect(() => resolveApiBase("http://api.example.org/functions/v1", { allowLoopback: true })).toThrow();
  });

  it("a production build refuses the placeholder host", () => {
    expect(() => resolveApiBase(undefined, { production: true })).toThrow(/placeholder/);
    expect(() => resolveApiBase("https://x.example/functions/v1", { production: true })).toThrow(/placeholder/);
    expect(resolveApiBase("https://abc123.supabase.co/functions/v1", { production: true }).isPlaceholder).toBe(false);
  });
});
