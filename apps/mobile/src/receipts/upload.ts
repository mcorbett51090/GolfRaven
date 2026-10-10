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

  try {
    const answer = await deps.api.uploadReceipt(
      {
        facilityId: input.facilityId,
        file: { uri: picked.uri, name: picked.name, type: picked.type },
        localDate: input.localDate,
      },
      { userId: owner, accessToken },
    );
    return outcomeFromAnswer(answer);
  } catch (e) {
    return outcomeFromError(e);
  }
}
