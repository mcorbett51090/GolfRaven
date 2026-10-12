import { RECEIPTS_UPLOAD_UI_ENABLED } from "../features";

/**
 * The ONLY question the screens and the upload service ask about the receipts switch.
 * `enabled` is injectable so tests can exercise both states; the app never passes it.
 * While false: the facility page shows no receipt card, and `uploadReceiptImage` refuses before any picker prompt.
 */
export function receiptsUploadUiAvailable(enabled: boolean = RECEIPTS_UPLOAD_UI_ENABLED): boolean {
  return enabled;
}
