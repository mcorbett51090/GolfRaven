// supabase/tests/unit/import-endpoint.test.ts
//
// P3e round 2 gate, M5: entrypoint must-fail cells for import-catalog —
// anon JWT -> 401, player JWT -> 401, wrong method -> 405, oversize body
// -> 413, rate limit -> 429 — plus H4 (always drain) and the opaque
// not_configured NIT. Drives the REAL request handler
// (`_shared/catalog/import-endpoint.ts`, which `import-catalog/index.ts`
// merely wires real I/O into) with injected fakes.
import { describe, expect, it, vi } from "vitest";
import { handleImportCatalogRequest, MAX_IMPORT_REQUEST_BODY_BYTES, type ImportEndpointDeps } from "../../functions/_shared/catalog/import-endpoint.js";
import { handleRequest } from "../../functions/_shared/http.js";
import { buildWebhookSignatureHeader } from "../../functions/_shared/catalog/webhook-auth.js";

const SECRET = "s".repeat(40);
const NOW = new Date("2026-09-25T12:00:00.000Z");
const CONFIG = { artifactBaseUrl: "https://golfraven.example/catalog/v1", allowedHosts: ["golfraven.example"], webhookHmacSecret: SECRET };
const DRAINED = { scanned: 0, resolved: 0, needsAttention: 0, unknownId: 0, stillQueued: 0 };

function deps(over: Partial<ImportEndpointDeps> = {}): ImportEndpointDeps & { runImport: ReturnType<typeof vi.fn>; runDrain: ReturnType<typeof vi.fn>; hitRateLimit: ReturnType<typeof vi.fn> } {
  return {
    getConfig: () => CONFIG,
    hitRateLimit: vi.fn(async () => ({ ok: true as const, count: 1 })),
    runImport: vi.fn(async () => ({ ok: true, versionsImported: 1, currentVersion: 1 })),
    runDrain: vi.fn(async () => DRAINED),
    now: () => NOW,
    ...over,
  } as never;
}

async function signedReq(body = "{}", over: RequestInit = {}) {
  const bytes = new TextEncoder().encode(body);
  const sig = await buildWebhookSignatureHeader(SECRET, bytes, NOW);
  return new Request("https://x.example/import-catalog", { method: "POST", body, headers: { "x-golfraven-catalog-signature": sig }, ...over });
}

describe("import-catalog endpoint — must-fail cells (M5)", () => {
  it("anon JWT (apikey/Authorization only, no HMAC) -> 401, and nothing runs", async () => {
    const d = deps();
    const res = await handleImportCatalogRequest(new Request("https://x.example/", { method: "POST", body: "{}", headers: { authorization: "Bearer anon.jwt.value", apikey: "anon" } }), d);
    expect(res.status).toBe(401);
    expect(d.runImport).not.toHaveBeenCalled();
    expect(d.runDrain).not.toHaveBeenCalled();
  });

  it("player JWT -> 401 — no JWT path exists at all", async () => {
    const d = deps();
    const res = await handleImportCatalogRequest(new Request("https://x.example/", { method: "POST", body: "{}", headers: { authorization: "Bearer player.jwt.value" } }), d);
    expect(res.status).toBe(401);
    expect(d.runImport).not.toHaveBeenCalled();
  });

  it("a signature made with the wrong secret -> 401", async () => {
    const bytes = new TextEncoder().encode("{}");
    const sig = await buildWebhookSignatureHeader("w".repeat(40), bytes, NOW);
    const res = await handleImportCatalogRequest(new Request("https://x.example/", { method: "POST", body: "{}", headers: { "x-golfraven-catalog-signature": sig } }), deps());
    expect(res.status).toBe(401);
  });

  it.each(["GET", "PUT", "DELETE", "PATCH"])("%s -> 405", async (method) => {
    const res = await handleImportCatalogRequest(new Request("https://x.example/", { method }), deps());
    expect(res.status).toBe(405);
  });

  it("oversize body (declared) -> 413", async () => {
    const big = "x".repeat(MAX_IMPORT_REQUEST_BODY_BYTES + 1);
    const res = await handleRequest(async () => handleImportCatalogRequest(await signedReq(big), deps()));
    expect(res.status).toBe(413);
  });

  it("oversize body (undeclared/streamed) -> 413", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(MAX_IMPORT_REQUEST_BODY_BYTES + 10));
        c.close();
      },
    });
    const req = new Request("https://x.example/", { method: "POST", body: stream, headers: {}, duplex: "half" } as RequestInit);
    const res = await handleRequest(() => handleImportCatalogRequest(req, deps()));
    expect(res.status).toBe(413);
  });

  it("rate limit exceeded -> 429, and neither import nor drain runs", async () => {
    const d = deps({ hitRateLimit: vi.fn(async () => ({ ok: false as const, count: 61, retryAfterSeconds: 3600 })) });
    const res = await handleImportCatalogRequest(await signedReq(), d);
    expect(res.status).toBe(429);
    expect(d.runImport).not.toHaveBeenCalled();
    expect(d.runDrain).not.toHaveBeenCalled();
  });

  it("NIT: an unconfigured environment answers with the SAME opaque 401 as a bad signature (not a distinguishable 500)", async () => {
    const bad = await handleImportCatalogRequest(new Request("https://x.example/", { method: "POST", body: "{}" }), deps());
    const unconfigured = await handleImportCatalogRequest(await signedReq(), deps({ getConfig: () => null }));
    expect(unconfigured.status).toBe(401);
    expect(await unconfigured.text()).toBe(await bad.text());
  });

  it("a weak (<32 byte) configured secret is treated as unconfigured -> 401", async () => {
    const res = await handleImportCatalogRequest(await signedReq(), deps({ getConfig: () => ({ ...CONFIG, webhookHmacSecret: "short" }) }));
    expect(res.status).toBe(401);
  });
});

describe("import-catalog endpoint — sequencing (H4: always drain)", () => {
  it("happy path: import then drain, 200", async () => {
    const d = deps();
    const res = await handleImportCatalogRequest(await signedReq(), d);
    expect(res.status).toBe(200);
    expect(d.runImport).toHaveBeenCalledOnce();
    expect(d.runDrain).toHaveBeenCalledOnce();
  });

  it("a REJECTED import (422) still drains", async () => {
    const d = deps({ runImport: vi.fn(async () => ({ ok: false as const, reason: "catalog_forged" })) });
    const res = await handleImportCatalogRequest(await signedReq(), d);
    expect(res.status).toBe(422);
    expect(d.runDrain).toHaveBeenCalledOnce();
    const body = (await res.json()) as { error: { details: { reason: string; drained: unknown } } };
    expect(body.error.details.reason).toBe("catalog_forged");
    expect(body.error.details.drained).toEqual(DRAINED);
  });

  it("a THROWN import (500) still drains", async () => {
    const d = deps({ runImport: vi.fn(async () => { throw new Error("boom"); }) });
    const res = await handleImportCatalogRequest(await signedReq(), d);
    expect(res.status).toBe(500);
    expect(d.runDrain).toHaveBeenCalledOnce();
  });

  it("a failing drain never masks a successful import's outcome as a crash of the import itself (500 only because the drain failed)", async () => {
    const d = deps({ runDrain: vi.fn(async () => { throw new Error("drain boom"); }) });
    const res = await handleImportCatalogRequest(await signedReq(), d);
    expect(res.status).toBe(500);
    expect(d.runImport).toHaveBeenCalledOnce();
  });
});
