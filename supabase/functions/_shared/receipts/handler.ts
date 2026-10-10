import { Errors, HttpError } from "../http.ts";
import type { Repo } from "../types.ts";
import type { ReceiptsStoragePort } from "./ports.ts";
import type { ParsedReceiptUpload } from "./request-shape.ts";
import {
  contentTypeForKind,
  extensionForKind,
  prepareReceiptImage,
  sniffReceiptImageKind,
} from "./image.ts";
import type { ReceiptIntakeResult } from "./ports.ts";

export interface ReceiptUploadDeps {
  storage: ReceiptsStoragePort;
  newObjectId: () => string;
}

function mapStatus(result: ReceiptIntakeResult): { status: number; body: ReceiptIntakeResult } {
  const base = {
    status: result.status,
    localDate: result.localDate,
    dedupe: result.dedupe,
    purchases: result.purchases.map((p) => ({
      purchaseId: p.purchaseId,
      trailId: p.trailId,
      purchaseStatus: p.purchaseStatus,
      creditId: p.creditId,
      creditStatus: p.creditStatus,
    })),
  };
  switch (result.status) {
    case "ok":
    case "duplicate":
    case "review":
      return { status: 201, body: base };
    case "no_facility":
      throw Errors.notFound("facility not found");
    case "no_programme":
    case "bad_args":
      throw Errors.unprocessable(result.status, result.status === "bad_args" ? "invalid receipt upload" : "no programme for facility");
    case "review_account":
      throw Errors.forbidden("review account may not upload receipts");
    default:
      throw Errors.internal(`unexpected receipt intake status: ${result.status}`);
  }
}

async function removeQuietly(storage: ReceiptsStoragePort, path: string): Promise<void> {
  try {
    await storage.removeObject(path);
  } catch {
    // Best-effort orphan cleanup; Storage purge is a documented follow-up (§40.3).
  }
}

export async function handleReceiptUpload(
  parsed: ParsedReceiptUpload,
  actorUid: string,
  repo: Repo,
  deps: ReceiptUploadDeps,
): Promise<{ status: number; body: ReceiptIntakeResult }> {
  const kind = sniffReceiptImageKind(parsed.fileBytes);
  if (!kind) {
    throw Errors.unsupportedMediaType("receipt image must be JPEG, PNG, or HEIC");
  }

  let stripped: Uint8Array;
  let phash: string;
  try {
    ({ stripped, phash } = prepareReceiptImage(parsed.fileBytes, kind));
  } catch {
    throw Errors.unsupportedMediaType("receipt image could not be decoded");
  }

  const objectId = deps.newObjectId();
  const ext = extensionForKind(kind);
  const storageObject = `receipts/${actorUid}/${objectId}.${ext}`;
  const contentType = contentTypeForKind(kind);

  await deps.storage.putObject(storageObject, stripped, contentType);

  let intake: ReceiptIntakeResult;
  try {
    intake = await repo.receipts.intake({
      facilityId: parsed.facilityId,
      storageObject,
      phash,
      localDate: parsed.localDate,
      receiptNumberOcr: parsed.receiptNumberOcr,
    });
  } catch (err) {
    await removeQuietly(deps.storage, storageObject);
    throw err;
  }

  try {
    return mapStatus(intake);
  } catch (err) {
    // Expected refusals (404/422/403) leave no purchase rows — drop the object.
    if (err instanceof HttpError && err.status >= 400 && err.status < 500 && err.status !== 201) {
      await removeQuietly(deps.storage, storageObject);
    }
    throw err;
  }
}
