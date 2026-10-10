/**
 * P5 §43: the client half of `POST receipts` (`api.uploadReceipt`). Answers are shaped like the REAL handler's `mapStatus`
 * (`_shared/receipts/handler.ts` / `okResponse`) — multipart is not yet in `edge-contract.json`. What is proved: the URL,
 * multipart FormData (no JSON Content-Type), the owner's token, one request and no retry, the answer schema, refusal mapping,
 * and that NOTHING in the app calls it yet (`RECEIPTS_UPLOAD_UI_ENABLED` is false).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError, createHttpApiClient, createUnconfiguredApi, receiptUploadFormData, type ReceiptUploadRequest, type ReceiptUploadResult } from "../src/api";
import { createMockApi } from "../src/api/mock";
import { devOnly } from "../src/dev-guard";
import { RECEIPTS_UPLOAD_UI_ENABLED } from "../src/features";
import { jwt } from "./support/fakes";
import { scriptedFetch } from "./support/edge-fixtures";

const USER = "11111111-aaaa-4aaa-8aaa-111111111111";
const BASE = "https://x.test/functions/v1";
const creds = { userId: USER, accessToken: jwt({ sub: USER, role: "authenticated" }) };
const client = (fetch: ReturnType<typeof scriptedFetch>["fetch"]) => createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: async () => "session-token", sleep: async () => undefined });
const failure = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => e as ApiError,
  );

const TINY_JPEG = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12, 0x13, 0x0f, 0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c,
  0x1c, 0x20, 0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29, 0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32, 0x3c, 0x2e, 0x33, 0x34, 0x32, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01,
  0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x7b, 0xbf, 0xff, 0xd9,
]);

const okBody: ReceiptUploadResult = {
  status: "ok",
  localDate: "2030-01-02",
  dedupe: "clean",
  purchases: [{ purchaseId: "p1", trailId: "trl_t", purchaseStatus: "pending", creditId: "c1", creditStatus: "pending" }],
};

function jpegReq(over: Partial<ReceiptUploadRequest> = {}): ReceiptUploadRequest {
  return {
    facilityId: "fac_x",
    file: new Blob([TINY_JPEG], { type: "image/jpeg" }),
    fileName: "r.jpg",
    ...over,
  };
}

describe("api.uploadReceipt multipart wire", () => {
  it("POST <base>/receipts as FormData with the owner's token; 201 parses; Content-Type is not set by the client", async () => {
    const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: okBody }) });
    const req = jpegReq({ localDate: "2030-01-02", receiptNumberOcr: "ABC-1" });
    const out = await client(f.fetch).uploadReceipt(req, creds);
    expect(out).toEqual(okBody);
    expect(f.seen).toHaveLength(1);
    expect(f.seen[0]).toMatchObject({ url: `${BASE}/receipts`, method: "POST", redirect: "error", credentials: "omit" });
    expect(f.seen[0]!.headers.Authorization).toBe(`Bearer ${creds.accessToken}`);
    expect(f.seen[0]!.headers["Content-Type"]).toBeUndefined();
    expect(f.seen[0]!.body).toBeInstanceOf(FormData);
    const form = f.seen[0]!.body as FormData;
    expect(form.get("facilityId")).toBe("fac_x");
    expect(form.get("localDate")).toBe("2030-01-02");
    expect(form.get("receiptNumberOcr")).toBe("ABC-1");
    expect(form.get("file")).toBeInstanceOf(Blob);
  });

  it("optional fields are ABSENT on the wire when omitted (the server's parser treats empty/missing differently)", async () => {
    const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: okBody }) });
    await client(f.fetch).uploadReceipt(jpegReq(), creds);
    const form = f.seen[0]!.body as FormData;
    expect([...form.keys()].sort()).toEqual(["facilityId", "file"]);
  });

  it("receiptUploadFormData accepts a React Native uri part (a file field is present)", () => {
    const form = receiptUploadFormData({
      facilityId: "fac_x",
      file: { uri: "file:///tmp/r.jpg", name: "r.jpg", type: "image/jpeg" },
    });
    expect([...form.keys()].sort()).toEqual(["facilityId", "file"]);
    expect(form.get("facilityId")).toBe("fac_x");
    // Node's FormData stringifies non-Blob appends; RN preserves the uri object. Either way a file part is present.
    expect(form.get("file")).not.toBeNull();
  });

  it("every success status the contract names parses: ok, duplicate, review", async () => {
    for (const status of ["ok", "duplicate", "review"] as const) {
      const body: ReceiptUploadResult = { ...okBody, status, dedupe: status === "duplicate" ? "same_user" : status === "review" ? "cross_user" : "clean" };
      const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: body }) });
      expect((await client(f.fetch).uploadReceipt(jpegReq(), creds)).status).toBe(status);
    }
  });

  it("refusals are mapped and NONE is retried (a blind repeat may open another fingerprint)", async () => {
    const cases: Array<[number, string, string, string]> = [
      [404, "not_found", "facility not found", "not_found"],
      [403, "forbidden", "review account may not upload receipts", "forbidden"],
      [415, "unsupported_media_type", "receipt image must be JPEG, PNG, or HEIC", "rejected"],
      [413, "payload_too_large", "receipt file exceeds limit", "rejected"],
      [422, "no_programme", "no programme for facility", "rejected"],
      [400, "bad_request", "invalid receipt upload", "rejected"],
      [429, "rate_limited", "receipts rate limit exceeded", "rate_limited"],
    ];
    for (const [status, code, message, kind] of cases) {
      const f = scriptedFetch({
        status,
        body: JSON.stringify({ error: { code, message, ...(status === 429 ? { details: { retryAfterSeconds: 60 } } : {}) } }),
        ...(status === 429 ? { headers: { "retry-after": "60" } } : {}),
      });
      const err = await failure(client(f.fetch).uploadReceipt(jpegReq(), creds));
      expect(err, code).toMatchObject({ kind, status, code });
      expect(f.seen, code).toHaveLength(1);
    }
  });

  it("an answer the client cannot interpret is bad_response", async () => {
    for (const patch of [{ status: "credited" }, { purchases: undefined }, { localDate: "June 1" }, { dedupe: "maybe" }]) {
      const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: { ...okBody, ...patch } }) });
      expect(await failure(client(f.fetch).uploadReceipt(jpegReq(), creds)), JSON.stringify(patch)).toMatchObject({ kind: "bad_response" });
    }
    const f = scriptedFetch({ status: 200, body: JSON.stringify({ data: okBody }) });
    expect(await failure(client(f.fetch).uploadReceipt(jpegReq(), creds))).toMatchObject({ kind: "bad_response" });
  });

  it("the unconfigured build refuses, and the demo answers an obviously fake ok intake", async () => {
    expect(await failure(createUnconfiguredApi().uploadReceipt(jpegReq(), creds))).toMatchObject({ kind: "not_configured" });
    const mock = createMockApi(devOnly(true));
    const req = jpegReq();
    expect((await mock.uploadReceipt(req, creds)).status).toBe("ok");
    expect(mock.calls).toEqual([{ op: "receipt_upload", req }]);
  });
});

describe("nothing in the app calls uploadReceipt yet", () => {
  it("RECEIPTS_UPLOAD_UI_ENABLED is false, and no file under src/ outside src/api calls uploadReceipt", () => {
    expect(RECEIPTS_UPLOAD_UI_ENABLED).toBe(false);
    const root = fileURLToPath(new URL("../src", import.meta.url));
    const walk = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : n.endsWith(".ts") || n.endsWith(".tsx") ? [join(dir, n)] : []));
    const callers = walk(root).filter((f) => !f.startsWith(join(root, "api")) && /uploadReceipt/.test(readFileSync(f, "utf8")));
    expect(callers).toEqual([]);
  });
});
