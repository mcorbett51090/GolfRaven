/**
 * Pick a receipt image and POST it (`api.uploadReceipt`). Never throws.
 * Refuses while the receipts UI switch is off — before any picker prompt.
 */
import type { ReceiptsApi } from "../api";
import type { ReceiptPickerPort } from "./picker";
import { outcomeFromAnswer, outcomeFromError, type ReceiptUploadOutcome } from "./outcome";

export interface ReceiptUploadDeps {
  readonly enabled: boolean;
  readonly api: ReceiptsApi;
  readonly picker: ReceiptPickerPort;
  readonly currentUserId: () => string | null;
  readonly accessTokenFor: (userId: string) => Promise<string | null>;
}

export interface ReceiptUploadInput {
  readonly facilityId: string;
  readonly localDate?: string;
  /** Optional typed receipt / invoice number (Edge `receiptNumberOcr`; empty omitted). */
  readonly receiptNumberOcr?: string;
}

/** Trim and bound a typed receipt number for the multipart field; empty → undefined (omit). */
export function normalizeReceiptNumber(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim().slice(0, 64);
  return trimmed.length === 0 ? undefined : trimmed;
}

export async function uploadReceiptImage(deps: ReceiptUploadDeps, input: ReceiptUploadInput): Promise<ReceiptUploadOutcome> {
  if (!deps.enabled) return { status: "disabled" };
  const owner = deps.currentUserId();
  if (owner === null) return { status: "signed_out" };

  const picked = await deps.picker.pickFromLibrary();
  if (picked.kind === "cancelled") return { status: "cancelled" };
  if (picked.kind === "denied") return { status: "denied", canAskAgain: picked.canAskAgain };
  if (picked.kind === "unavailable") return { status: "picker_unavailable" };

  let accessToken: string | null;
  try {
    accessToken = await deps.accessTokenFor(owner);
  } catch {
    return { status: "offline" };
  }
  if (accessToken === null) return { status: "sign_in_required" };

  const receiptNumberOcr = normalizeReceiptNumber(input.receiptNumberOcr);

  try {
    const answer = await deps.api.uploadReceipt(
      {
        facilityId: input.facilityId,
        file: { uri: picked.uri, name: picked.name, type: picked.type },
        localDate: input.localDate,
        ...(receiptNumberOcr !== undefined ? { receiptNumberOcr } : {}),
      },
      { userId: owner, accessToken },
    );
    return outcomeFromAnswer(answer);
  } catch (e) {
    return outcomeFromError(e);
  }
}
