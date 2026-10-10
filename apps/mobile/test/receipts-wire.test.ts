/**
 * P5 §56: the client half of `POST receipts` (`api.uploadReceipt`), against the REAL handler's recorded answers
 * (`test/fixtures/edge-contract.json`, `receipts_*`, recorded by `scripts/record-edge-contract.rec.ts`). What is proved: the URL,
 * multipart FormData (no JSON Content-Type) built from the logical fields the real parser accepted, the owner's token, one request
 * and no retry, the answer schema, the mapping of every recorded refusal, and that NOTHING in the app calls it yet outside the
 * gated upload path (`RECEIPTS_UPLOAD_UI_ENABLED` is false).
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
import { recorded, recordedRequest, scriptedFetch } from "./support/edge-fixtures";

const USER = "11111111-aaaa-4aaa-8aaa-111111111111";
const BASE = "https://x.test/functions/v1";
const creds = { userId: USER, accessToken: jwt({ sub: USER, role: "authenticated" }) };
const client = (fetch: ReturnType<typeof scriptedFetch>["fetch"]) => createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: async () => "session-token", sleep: async () => undefined });
const answerOf = (name: string): ReceiptUploadResult => JSON.parse(recorded(name).body).data as ReceiptUploadResult;
const failure = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => e as ApiError,
  );

/** Logical multipart fields the recorder stores (hex bytes, or length alone for oversize). */
type ReceiptRecordedRequest = {
  facilityId: string;
  fileName: string;
  fileBytesHex?: string;
  fileBytesLength?: number;
  localDate?: string;
  receiptNumberOcr?: string;
};

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(hex, "hex");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function reqFromRecorded(name: string): ReceiptUploadRequest {
  const r = recordedRequest<ReceiptRecordedRequest>(name);
  // Oversize entries store length only; rebuild a same-sized buffer so FormData carries that length.
  const bytes: Uint8Array<ArrayBuffer> = r.fileBytesHex !== undefined ? hexToBytes(r.fileBytesHex) : new Uint8Array(r.fileBytesLength ?? 0);
  return {
    facilityId: r.facilityId,
    file: new Blob([bytes], { type: "image/jpeg" }),
    fileName: r.fileName,
    ...(r.localDate !== undefined ? { localDate: r.localDate } : {}),
    ...(r.receiptNumberOcr !== undefined ? { receiptNumberOcr: r.receiptNumberOcr } : {}),
  };
}

/** Tiny JPEG used when the refusal under test does not need the recorded file bytes (response mapping only). */
const TINY_JPEG = hexToBytes(
  recordedRequest<ReceiptRecordedRequest>("receipts_201_ok").fileBytesHex!,
);

async function formLogical(form: FormData): Promise<{ facilityId: string; fileName: string; fileBytesHex?: string; fileBytesLength?: number; localDate?: string; receiptNumberOcr?: string }> {
  const facilityId = String(form.get("facilityId") ?? "");
  const localDate = form.get("localDate");
  const receiptNumberOcr = form.get("receiptNumberOcr");
  const file = form.get("file");
  if (!(file instanceof Blob)) throw new Error("expected file Blob");
  const buf = new Uint8Array(await file.arrayBuffer());
  // Match the recorder: oversize entries carry length only.
  const MAX = 5 * 1024 * 1024;
  const name = typeof File !== "undefined" && file instanceof File && file.name ? file.name : "r.jpg";
  return {
    facilityId,
    fileName: name,
    ...(buf.byteLength > MAX ? { fileBytesLength: buf.byteLength } : { fileBytesHex: Buffer.from(buf).toString("hex") }),
    ...(localDate !== null ? { localDate: String(localDate) } : {}),
    ...(receiptNumberOcr !== null ? { receiptNumberOcr: String(receiptNumberOcr) } : {}),
  };
}

describe("api.uploadReceipt against the real handler's recorded answers", () => {
  it("POST <base>/receipts as FormData with the owner's token; 201 parses; Content-Type is not set by the client", async () => {
    const f = scriptedFetch({ respond: "receipts_201_ok" });
    const req = reqFromRecorded("receipts_201_ok");
    const out = await client(f.fetch).uploadReceipt(req, creds);
    expect(out).toEqual(answerOf("receipts_201_ok"));
    expect(out).toMatchObject({ status: "ok", dedupe: "clean" });
    expect(f.seen).toHaveLength(1);
    expect(f.seen[0]).toMatchObject({ url: `${BASE}/receipts`, method: "POST", redirect: "error", credentials: "omit" });
    expect(f.seen[0]!.headers.Authorization).toBe(`Bearer ${creds.accessToken}`);
    expect(f.seen[0]!.headers["Content-Type"]).toBeUndefined();
    expect(f.seen[0]!.body).toBeInstanceOf(FormData);
    expect(await formLogical(f.seen[0]!.body as FormData)).toEqual(recordedRequest("receipts_201_ok"));
  });

  it("optional fields are ABSENT on the wire when omitted (the server's parser treats empty/missing differently)", async () => {
    const f = scriptedFetch({ respond: "receipts_429_rate_limited" });
    const req = reqFromRecorded("receipts_429_rate_limited");
    await client(f.fetch).uploadReceipt(req, creds).catch(() => undefined);
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
    expect(form.get("file")).not.toBeNull();
  });

  it("every recorded success shape parses: ok, duplicate, review", async () => {
    for (const [name, status, dedupe] of [
      ["receipts_201_ok", "ok", "clean"],
      ["receipts_201_duplicate", "duplicate", "same_user"],
      ["receipts_201_review", "review", "cross_user"],
    ] as const) {
      const f = scriptedFetch({ respond: name });
      const out = await client(f.fetch).uploadReceipt(reqFromRecorded(name), creds);
      expect(out.status, name).toBe(status);
      expect(out.dedupe, name).toBe(dedupe);
      expect(await formLogical(f.seen[0]!.body as FormData), name).toEqual(recordedRequest(name));
    }
  });

  it("every recorded refusal is mapped, and NONE is retried (a blind repeat may open another fingerprint)", async () => {
    const cases: Array<[string, string, number, string]> = [
      ["receipts_404_not_found", "not_found", 404, "not_found"],
      ["receipts_403_forbidden", "forbidden", 403, "forbidden"],
      ["receipts_415_unsupported_media", "rejected", 415, "unsupported_media_type"],
      ["receipts_413_payload_too_large", "rejected", 413, "payload_too_large"],
      ["receipts_422_no_programme", "rejected", 422, "no_programme"],
      ["receipts_400_bad_request", "rejected", 400, "bad_request"],
      ["receipts_429_rate_limited", "rate_limited", 429, "rate_limited"],
    ];
    for (const [name, kind, status, code] of cases) {
      const f = scriptedFetch({ respond: name });
      // Response mapping only: a tiny JPEG is enough (oversize length is pinned separately).
      const err = await failure(
        client(f.fetch).uploadReceipt({ facilityId: "fac_x", file: new Blob([TINY_JPEG], { type: "image/jpeg" }), fileName: "r.jpg" }, creds),
      );
      expect(err, name).toMatchObject({ kind, status, code });
      expect(f.seen, name).toHaveLength(1);
    }
  });

  it("a rate limit carries its Retry-After from the body's details", async () => {
    const f = scriptedFetch({ respond: "receipts_429_rate_limited" });
    const err = await failure(client(f.fetch).uploadReceipt(reqFromRecorded("receipts_429_rate_limited"), creds));
    expect(err?.retryAfterSeconds).toBe(3600);
  });

  it("an answer the client cannot interpret is bad_response", async () => {
    const good = answerOf("receipts_201_ok");
    for (const patch of [{ status: "credited" }, { purchases: undefined }, { localDate: "June 1" }, { dedupe: "maybe" }]) {
      const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: { ...good, ...patch } }) });
      expect(await failure(client(f.fetch).uploadReceipt(reqFromRecorded("receipts_201_ok"), creds)), JSON.stringify(patch)).toMatchObject({ kind: "bad_response" });
    }
    const f = scriptedFetch({ status: 200, body: JSON.stringify({ data: good }) });
    expect(await failure(client(f.fetch).uploadReceipt(reqFromRecorded("receipts_201_ok"), creds))).toMatchObject({ kind: "bad_response" });
  });

  it("the unconfigured build refuses, and the demo answers an obviously fake ok intake", async () => {
    expect(await failure(createUnconfiguredApi().uploadReceipt(reqFromRecorded("receipts_201_ok"), creds))).toMatchObject({ kind: "not_configured" });
    const mock = createMockApi(devOnly(true));
    const req = reqFromRecorded("receipts_201_ok");
    expect((await mock.uploadReceipt(req, creds)).status).toBe("ok");
    expect(mock.calls).toEqual([{ op: "receipt_upload", req }]);
  });

  it("the oversize recorded request carries length, not megabytes of hex", () => {
    const r = recordedRequest<ReceiptRecordedRequest>("receipts_413_payload_too_large");
    expect(r.fileBytesHex).toBeUndefined();
    expect(r.fileBytesLength).toBeGreaterThan(5 * 1024 * 1024);
  });
});

describe("uploadReceipt API callers outside api/", () => {
  it("RECEIPTS_UPLOAD_UI_ENABLED is false; only receipts/upload.ts calls api.uploadReceipt", () => {
    expect(RECEIPTS_UPLOAD_UI_ENABLED).toBe(false);
    const root = fileURLToPath(new URL("../src", import.meta.url));
    const walk = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : n.endsWith(".ts") || n.endsWith(".tsx") ? [join(dir, n)] : []));
    const callers = walk(root)
      .filter((f) => !f.startsWith(join(root, "api")) && /\.uploadReceipt\s*\(/.test(readFileSync(f, "utf8")))
      .map((f) => f.slice(root.length + 1))
      .sort();
    expect(callers).toEqual(["receipts/upload.ts", "screens/ReceiptUploadCard.tsx"]);
  });
});
