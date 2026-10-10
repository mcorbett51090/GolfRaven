export { receiptsUploadUiAvailable } from "./gate";
export type { ReceiptPickerPort, ReceiptPickResult } from "./picker";
// `createExpoReceiptPicker` is NOT re-exported: importing it pulls `expo-image-picker` / RN into Vitest.
// The composition root imports `./expo-image-picker` directly.
export { normalizeReceiptNumber, uploadReceiptImage, type ReceiptUploadDeps, type ReceiptUploadInput } from "./upload";
export { outcomeFromAnswer, outcomeFromError, needsSettings, type ReceiptUploadOutcome } from "./outcome";
export { receiptOutcomeMessage } from "./copy";
