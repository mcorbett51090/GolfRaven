import { describe, expect, it } from "vitest";
import { HttpError } from "../../functions/_shared/http.ts";
import { handleReceiptUpload } from "../../functions/_shared/receipts/handler.ts";
import { RECEIPTS_MAX_BYTES } from "../../functions/_shared/receipts/request-shape.ts";
import { makeFakeRepo, makeFakeState } from "./fake-repo.ts";

const UID = "00000000-0000-0000-0000-00000000000a";

const TINY_JPEG = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12, 0x13, 0x0f,
  0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c, 0x1c, 0x20, 0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29, 0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32, 0x3c, 0x2e, 0x33, 0x34, 0x32,
  0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
  0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x7b, 0xbf, 0xff, 0xd9,
]);

describe("handleReceiptUpload", () => {
  it("maps ok intake to 201", async () => {
    const repo = makeFakeRepo(makeFakeState(), UID);
    const uploads: string[] = [];
    const out = await handleReceiptUpload(
      { facilityId: "fac_x", fileBytes: TINY_JPEG, fileName: "r.jpg", localDate: null, receiptNumberOcr: null },
      UID,
      repo,
      {
        storage: {
          putObject: async (path) => { uploads.push(path); },
          removeObject: async () => {},
        },
        newObjectId: () => "11111111-1111-1111-1111-111111111111",
      },
    );
    expect(out.status).toBe(201);
    expect(out.body.status).toBe("ok");
    expect(uploads[0]).toBe(`receipts/${UID}/11111111-1111-1111-1111-111111111111.jpg`);
  });

  it("rejects PDF bytes with 415", async () => {
    const repo = makeFakeRepo(makeFakeState(), UID);
    await expect(
      handleReceiptUpload(
        { facilityId: "fac_x", fileBytes: Uint8Array.from([0x25, 0x50, 0x44, 0x46]), fileName: "x.pdf", localDate: null, receiptNumberOcr: null },
        UID,
        repo,
        { storage: { putObject: async () => {}, removeObject: async () => {} }, newObjectId: () => crypto.randomUUID() },
      ),
    ).rejects.toMatchObject({ status: 415 });
  });

  it("documents the 5 MB file cap constant", () => {
    expect(RECEIPTS_MAX_BYTES).toBe(5 * 1024 * 1024);
  });

  it("maps review_account to 403 and removes the uploaded object", async () => {
    const repo = makeFakeRepo(makeFakeState(), UID);
    const removed: string[] = [];
    repo.receipts.intake = async () => ({
      status: "review_account",
      localDate: null,
      dedupe: null,
      purchases: [],
    });
    await expect(
      handleReceiptUpload(
        { facilityId: "fac_x", fileBytes: TINY_JPEG, fileName: "r.jpg", localDate: null, receiptNumberOcr: null },
        UID,
        repo,
        {
          storage: {
            putObject: async () => {},
            removeObject: async (path) => { removed.push(path); },
          },
          newObjectId: () => "22222222-2222-2222-2222-222222222222",
        },
      ),
    ).rejects.toBeInstanceOf(HttpError);
    expect(removed[0]).toContain("22222222-2222-2222-2222-222222222222.jpg");
  });
});
