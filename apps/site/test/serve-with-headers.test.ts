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
          {
            type: "set",
            name: "Content-Security-Policy",
            value: "default-src 'self'",
          },
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
    const blocks = parseHeadersFile(
      ["# a comment", "", "/*", "  X-Foo: bar"].join("\n"),
    );
    expect(blocks).toHaveLength(1);
    expect(blocks[0]!.path).toBe("/*");
  });
});

describe("resolveHeaders: real Cloudflare Pages semantics", () => {
  it("REGRESSION (the actual bug): two matching blocks with NO detach comma-join the same header, they never override", () => {
    const blocks = parseHeadersFile(
      [
        "/*",
        "  Content-Security-Policy: default-src 'self'",
        "",
        "/pagefind/*",
        "  Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'",
      ].join("\n"),
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
    expect(
      resolveHeaders(blocks, "/pagefind/pagefind.js")[
        "Content-Security-Policy"
      ],
    ).toBe("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'");
    // The /* -only path is completely unaffected by the /pagefind/* block.
    expect(
      resolveHeaders(blocks, "/index.html")["Content-Security-Policy"],
    ).toBe("default-src 'self'");
  });

  it("a bare detach with nothing after it removes the header entirely for that path", () => {
    const blocks = parseHeadersFile(
      ["/*", "  X-Foo: bar", "", "/no-foo/*", "  ! X-Foo"].join("\n"),
    );
    expect(resolveHeaders(blocks, "/no-foo/thing")["X-Foo"]).toBeUndefined();
    expect(resolveHeaders(blocks, "/other/thing")["X-Foo"]).toBe("bar");
  });

  it("non-CSP headers (no duplication) still resolve normally", () => {
    const blocks = parseHeadersFile(
      [
        "/*",
        "  X-Content-Type-Options: nosniff",
        "  Referrer-Policy: strict-origin-when-cross-origin",
      ].join("\n"),
    );
    const headers = resolveHeaders(blocks, "/anything");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("path matching: exact, prefix (/x/*) and catch-all (/*)", () => {
    const blocks = parseHeadersFile(
      [
        "/*",
        "  X-A: 1",
        "",
        "/catalog/v1/*",
        "  X-Robots-Tag: noindex",
        "",
        "/exact/",
        "  X-Exact: yes",
      ].join("\n"),
    );
    expect(resolveHeaders(blocks, "/catalog/v1/foo.json")).toMatchObject({
      "X-A": "1",
      "X-Robots-Tag": "noindex",
    });
    expect(resolveHeaders(blocks, "/catalog/v2/foo.json")).toEqual({
      "X-A": "1",
    });
    expect(resolveHeaders(blocks, "/exact/")).toMatchObject({
      "X-A": "1",
      "X-Exact": "yes",
    });
    expect(resolveHeaders(blocks, "/exact/nested/")).toEqual({ "X-A": "1" });
  });
});

describe("resolveHeaders against gen-headers.mjs's REAL generated output", () => {
  it("the generated /pagefind/* block never comma-joins its CSP with the /* block's", async () => {
    const { buildHeaders } = await import("../scripts/gen-headers.mjs");
    const text = buildHeaders({});
    const blocks = parseHeadersFile(text);
    const pagefindCsp = resolveHeaders(blocks, "/pagefind/pagefind.js")[
      "Content-Security-Policy"
    ];
    expect(pagefindCsp).toContain("wasm-unsafe-eval");
    expect(pagefindCsp?.includes(",")).toBe(false); // a single policy, not two joined
    const rootCsp = resolveHeaders(blocks, "/index.html")[
      "Content-Security-Policy"
    ];
    expect(rootCsp).not.toContain("wasm-unsafe-eval");
  });
});
