/**
 * P5 §50: receipt upload UI behind `RECEIPTS_UPLOAD_UI_ENABLED`. Flag stays false; injected `true` reaches the picker and API.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/api";
import type { ReceiptsApi } from "../src/api";
import { RECEIPTS_UPLOAD_UI_ENABLED } from "../src/features";
import {
  outcomeFromError,
  receiptsUploadUiAvailable,
  uploadReceiptImage,
  type ReceiptPickerPort,
  type ReceiptPickResult,
} from "../src/receipts";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
const read = (f: string): string => strip(readFileSync(join(root, f), "utf8"));

function fakePicker(result: ReceiptPickResult): ReceiptPickerPort & { calls: number } {
  const port = { calls: 0, pickFromLibrary: async () => (port.calls++, result) };
  return port;
}

function fakeApi(impl: ReceiptsApi["uploadReceipt"]): ReceiptsApi & { calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    calls,
    uploadReceipt: async (req, creds) => {
      calls.push({ req, creds });
      return impl(req, creds);
    },
  };
}

describe("the receipts switch ships OFF", () => {
  it("is literally false and the gate follows an injected value", () => {
    expect(RECEIPTS_UPLOAD_UI_ENABLED).toBe(false);
    expect(read("src/features.ts")).toMatch(/export const RECEIPTS_UPLOAD_UI_ENABLED = false;/);
    expect(receiptsUploadUiAvailable()).toBe(false);
    expect(receiptsUploadUiAvailable(true)).toBe(true);
  });

  it("OFF: upload refuses without opening the picker or calling the API", async () => {
    const picker = fakePicker({ kind: "picked", uri: "file:///r.jpg", name: "r.jpg", type: "image/jpeg" });
    const api = fakeApi(async () => ({ status: "ok", localDate: "2030-01-01", dedupe: "clean", purchases: [] }));
    const o = await uploadReceiptImage(
      {
        enabled: receiptsUploadUiAvailable(),
        api,
        picker,
        currentUserId: () => "user-a",
        accessTokenFor: async () => "tok",
      },
      { facilityId: "fac_1" },
    );
    expect(o).toEqual({ status: "disabled" });
    expect(picker.calls).toBe(0);
    expect(api.calls).toEqual([]);
  });

  it("the composition root gates the service on the gate (not a literal)", () => {
    const s = read("src/runtime/services.ts");
    expect(s).toMatch(/enabled: receiptsUploadUiAvailable\(\)/);
    expect(s).toMatch(/uploadReceiptImage/);
    expect(read("src/receipts/upload.ts")).toMatch(/if \(!deps\.enabled\) return \{ status: "disabled" \};/);
  });

  it("the facility page renders the receipt card only behind the gate", () => {
    const f = read("app/facility/[id].tsx");
    expect(f).toMatch(/\{receiptsUploadUiAvailable\(\) \? <ReceiptUploadCard facilityId=\{facility\.id\} \/> : null\}/);
    expect(f.match(/<ReceiptUploadCard/g)).toHaveLength(1);
    expect(f.match(/import \{ ReceiptUploadCard \}/g)).toHaveLength(1);
  });

  it("the card is imported by no one else", () => {
    for (const f of ["app/(tabs)/me.tsx", "app/(tabs)/index.tsx", "app/(tabs)/played.tsx", "app/(tabs)/wallet.tsx", "app/trail/[id].tsx", "app/course/[id].tsx", "src/runtime/AppProvider.tsx"]) {
      expect(read(f), f).not.toMatch(/ReceiptUploadCard/);
    }
  });

  it("only expo-image-picker.ts imports expo-image-picker", () => {
    const src = join(root, "src");
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : n.endsWith(".ts") || n.endsWith(".tsx") ? [join(dir, n)] : []));
    const importers = walk(src).filter((f) => /from ["']expo-image-picker["']/.test(readFileSync(f, "utf8"))).map((f) => relative(root, f));
    expect(importers).toEqual(["src/receipts/expo-image-picker.ts"]);
  });
});

describe("ON (injected): picker then upload", () => {
  it("posts the picked file with the owner's token", async () => {
    const picker = fakePicker({ kind: "picked", uri: "file:///r.jpg", name: "r.jpg", type: "image/jpeg" });
    const api = fakeApi(async () => ({
      status: "ok",
      localDate: "2030-01-02",
      dedupe: "clean",
      purchases: [{ purchaseId: "p1", trailId: "trl_t", purchaseStatus: "pending", creditId: "c1", creditStatus: "pending" }],
    }));
    const o = await uploadReceiptImage(
      {
        enabled: receiptsUploadUiAvailable(true),
        api,
        picker,
        currentUserId: () => "user-a",
        accessTokenFor: async () => "tok-a",
      },
      { facilityId: "fac_1", localDate: "2030-01-02" },
    );
    expect(o).toEqual({ status: "ok", localDate: "2030-01-02", purchaseCount: 1 });
    expect(picker.calls).toBe(1);
    expect(api.calls).toEqual([
      {
        req: { facilityId: "fac_1", file: { uri: "file:///r.jpg", name: "r.jpg", type: "image/jpeg" }, localDate: "2030-01-02" },
        creds: { userId: "user-a", accessToken: "tok-a" },
      },
    ]);
  });

  it("forwards a typed receipt number and omits blanks (P5 §55)", async () => {
    const picker = fakePicker({ kind: "picked", uri: "file:///r.jpg", name: "r.jpg", type: "image/jpeg" });
    const api = fakeApi(async () => ({ status: "ok", localDate: null, dedupe: "clean", purchases: [] }));
    const deps = {
      enabled: true as const,
      api,
      picker,
      currentUserId: () => "user-a",
      accessTokenFor: async () => "tok",
    };
    await uploadReceiptImage(deps, { facilityId: "fac_1", receiptNumberOcr: "  ABC-99  " });
    expect(api.calls[0]).toMatchObject({ req: { receiptNumberOcr: "ABC-99" } });
    await uploadReceiptImage(deps, { facilityId: "fac_1", receiptNumberOcr: "   " });
    expect((api.calls[1] as { req: { receiptNumberOcr?: string } }).req.receiptNumberOcr).toBeUndefined();
  });

  it("maps cancelled / denied without calling the API", async () => {
    const api = fakeApi(async () => ({ status: "ok", localDate: null, dedupe: null, purchases: [] }));
    expect(
      await uploadReceiptImage(
        { enabled: true, api, picker: fakePicker({ kind: "cancelled" }), currentUserId: () => "u", accessTokenFor: async () => "t" },
        { facilityId: "f" },
      ),
    ).toEqual({ status: "cancelled" });
    expect(
      await uploadReceiptImage(
        { enabled: true, api, picker: fakePicker({ kind: "denied", canAskAgain: false }), currentUserId: () => "u", accessTokenFor: async () => "t" },
        { facilityId: "f" },
      ),
    ).toEqual({ status: "denied", canAskAgain: false });
    expect(api.calls).toEqual([]);
  });

  it("maps ApiError codes the wire test covers", () => {
    expect(outcomeFromError(new ApiError({ kind: "rejected", status: 422, code: "no_programme" }))).toEqual({ status: "no_programme" });
    expect(outcomeFromError(new ApiError({ kind: "rejected", status: 415, code: "unsupported_media_type" }))).toEqual({ status: "unsupported_media" });
    expect(outcomeFromError(new ApiError({ kind: "rejected", status: 413, code: "payload_too_large" }))).toEqual({ status: "payload_too_large" });
    expect(outcomeFromError(new ApiError({ kind: "rate_limited", status: 429, retryAfterSeconds: 120 }))).toEqual({ status: "rate_limited", retryAfterSeconds: 120 });
  });
});
