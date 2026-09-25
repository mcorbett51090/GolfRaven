/**
 * serve-with-headers.test.ts — unit coverage for
 * `test/e2e/serve-with-headers.mjs`'s Cloudflare Pages `_headers`
 * semantics (re-gate blocking finding: the server used to just apply the
 * LAST matching block, silently masking the real bug — two matching
 * blocks' `Content-Security-Policy` lines actually get comma-joined by
 * real Cloudflare Pages, which is exactly what broke Pagefind under CSP).
 */
import { describe, expect, it } from "vitest";
import { parseHeadersFile, resolveHeaders } from "./e2e/serve-with-headers.mjs";

describe("parseHeadersFile", () => {
  it("parses set and detach ops, in order, per block", () => {
    const blocks = parseHeadersFile(
      [
        "/*",
        "  Content-Security-Policy: default-src 'self'",
        "  X-Content-Type-Options: nosniff",
        "",
        "/pagefind/*",
        "  ! Content-Security-Policy",
        "  Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
      ].join("\n"),
    );
    expect(blocks).toEqual([
      {
        path: "/*",
        ops: [
          { type: "set", name: "Content-Security-Policy", value: "default-src 'self'" },
          { type: "set", name: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
      {
        path: "/pagefind/*",
        ops: [
          { type: "detach", name: "Content-Security-Policy" },
          {
            type: "set",
            name: "Content-Security-Policy",
            value: "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
          },
        ],
      },
    ]);
  });

  it("ignores comments and blank lines", () => {
    const blocks = parseHeadersFile(["# a comment", "", "/*", "  X-Foo: bar"].join("\n"));
    expect(blocks).toHaveLength(1);
    expect(blocks[0]!.path).toBe("/*");
  });
});

describe("resolveHeaders: real Cloudflare Pages semantics", () => {
  it("REGRESSION (the actual bug): two matching blocks with NO detach comma-join the same header, they never override", () => {
    const blocks = parseHeadersFile(
      ["/*", "  Content-Security-Policy: default-src 'self'", "", "/pagefind/*", "  Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'"].join(
        "\n",
      ),
    );
    const headers = resolveHeaders(blocks, "/pagefind/pagefind.js");
    expect(headers["Content-Security-Policy"]).toBe(
      "default-src 'self', script-src 'self' 'wasm-unsafe-eval'",
    );
    // The joined value is NOT a usable single CSP — proves why the detach
    // below is required, not cosmetic.
  });

  it("the FIX: a detach before the re-set gives a single, clean value on the more-specific path", () => {
    const blocks = parseHeadersFile(
      [
        "/*",
        "  Content-Security-Policy: default-src 'self'",
        "",
        "/pagefind/*",
        "  ! Content-Security-Policy",
        "  Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
      ].join("\n"),
    );
    expect(resolveHeaders(blocks, "/pagefind/pagefind.js")["Content-Security-Policy"]).toBe(
      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
    );
    // The /* -only path is completely unaffected by the /pagefind/* block.
    expect(resolveHeaders(blocks, "/index.html")["Content-Security-Policy"]).toBe("default-src 'self'");
  });

  it("a bare detach with nothing after it removes the header entirely for that path", () => {
    const blocks = parseHeadersFile(["/*", "  X-Foo: bar", "", "/no-foo/*", "  ! X-Foo"].join("\n"));
    expect(resolveHeaders(blocks, "/no-foo/thing")["X-Foo"]).toBeUndefined();
    expect(resolveHeaders(blocks, "/other/thing")["X-Foo"]).toBe("bar");
  });

  it("non-CSP headers (no duplication) still resolve normally", () => {
    const blocks = parseHeadersFile(["/*", "  X-Content-Type-Options: nosniff", "  Referrer-Policy: strict-origin-when-cross-origin"].join("\n"));
    const headers = resolveHeaders(blocks, "/anything");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("path matching: exact, prefix (/x/*) and catch-all (/*)", () => {
    const blocks = parseHeadersFile(
      ["/*", "  X-A: 1", "", "/catalog/v1/*", "  X-Robots-Tag: noindex", "", "/exact/", "  X-Exact: yes"].join("\n"),
    );
    expect(resolveHeaders(blocks, "/catalog/v1/foo.json")).toMatchObject({ "X-A": "1", "X-Robots-Tag": "noindex" });
    expect(resolveHeaders(blocks, "/catalog/v2/foo.json")).toEqual({ "X-A": "1" });
    expect(resolveHeaders(blocks, "/exact/")).toMatchObject({ "X-A": "1", "X-Exact": "yes" });
    expect(resolveHeaders(blocks, "/exact/nested/")).toEqual({ "X-A": "1" });
  });
});

describe("resolveHeaders against gen-headers.mjs's REAL generated output", () => {
  it("the generated /pagefind/* block never comma-joins its CSP with the /* block's", async () => {
    const { buildHeaders } = await import("../scripts/gen-headers.mjs");
    const text = buildHeaders({});
    const blocks = parseHeadersFile(text);
    const pagefindCsp = resolveHeaders(blocks, "/pagefind/pagefind.js")["Content-Security-Policy"];
    expect(pagefindCsp).toContain("wasm-unsafe-eval");
    expect(pagefindCsp?.includes(",")).toBe(false); // a single policy, not two joined
    const rootCsp = resolveHeaders(blocks, "/index.html")["Content-Security-Policy"];
    expect(rootCsp).not.toContain("wasm-unsafe-eval");
  });
});

// ---------------------------------------------------------------------
// Forms config (claim/feedback, this task's scope): "Update the CSP
// generator so the Worker origin and Turnstile hosts are allowed only
// when configured. Keep CSP strict otherwise."
// ---------------------------------------------------------------------
describe("gen-headers.mjs: the Worker origin + Turnstile hosts are allowed ONLY when forms-config.mjs is configured", () => {
  it("with the real (TODO(owner)-placeholder) FORMS_CONFIG, the CSP allow-lists neither the Worker nor Turnstile — exactly as strict as before forms existed", async () => {
    const { buildHeaders } = await import("../scripts/gen-headers.mjs");
    const text = buildHeaders({}); // second arg defaults to the REAL, committed FORMS_CONFIG
    expect(text).toContain("forms-config.mjs isFormsConfigured()=false");
    const blocks = parseHeadersFile(text);
    const rootCsp = resolveHeaders(blocks, "/index.html")["Content-Security-Policy"];
    expect(rootCsp).toBe(
      "default-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; form-action 'self'",
    );
    expect(rootCsp).not.toContain("challenges.cloudflare.com");
    expect(rootCsp).not.toContain("connect-src");
    expect(rootCsp).not.toContain("frame-src");
  });

  it("with a real (non-placeholder) forms config, the CSP allow-lists exactly the Worker's own host + Turnstile's hosts — nothing broader", async () => {
    const { buildHeaders } = await import("../scripts/gen-headers.mjs");
    const configured = {
      workerUrl: "https://raven-secure-upload.matt-769.workers.dev",
      siteId: "golfraven",
      turnstileSiteKey: "0xREALKEY",
    };
    const text = buildHeaders({}, configured);
    expect(text).toContain("forms-config.mjs isFormsConfigured()=true");
    const blocks = parseHeadersFile(text);
    const rootCsp = resolveHeaders(blocks, "/index.html")["Content-Security-Policy"];
    expect(rootCsp).toContain("script-src 'self' https://challenges.cloudflare.com");
    expect(rootCsp).toContain("frame-src https://challenges.cloudflare.com");
    expect(rootCsp).toContain(
      "connect-src 'self' https://raven-secure-upload.matt-769.workers.dev https://challenges.cloudflare.com",
    );
    // Never the Turnstile SITE KEY itself, and never a comma-joined double policy.
    expect(rootCsp).not.toContain("0xREALKEY");
    expect(rootCsp?.includes(",")).toBe(false);
    // The /pagefind/* block stays isolated — forms config never leaks into it.
    const pagefindCsp = resolveHeaders(blocks, "/pagefind/pagefind.js")["Content-Security-Policy"];
    expect(pagefindCsp).not.toContain("challenges.cloudflare.com");
    expect(pagefindCsp).not.toContain("raven-secure-upload");
  });

  it("a partially-configured forms config (one placeholder left) is still treated as unconfigured", async () => {
    const { buildHeaders } = await import("../scripts/gen-headers.mjs");
    const halfConfigured = {
      workerUrl: "https://raven-secure-upload.matt-769.workers.dev",
      siteId: "golfraven",
      turnstileSiteKey: "TODO(owner): golfraven Turnstile site key",
    };
    const text = buildHeaders({}, halfConfigured);
    expect(text).toContain("forms-config.mjs isFormsConfigured()=false");
    const rootCsp = resolveHeaders(parseHeadersFile(text), "/index.html")["Content-Security-Policy"];
    expect(rootCsp).not.toContain("challenges.cloudflare.com");
    expect(rootCsp).not.toContain("raven-secure-upload");
  });
});
