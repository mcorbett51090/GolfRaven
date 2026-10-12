/**
 * Image-picker port for receipt upload (P5 §50). The ONLY production adapter imports `expo-image-picker`
 * (`expo-image-picker.ts`); tests inject a fake. Prompts must run only from a button `onPress`.
 */

export type ReceiptPickResult =
  | { kind: "picked"; uri: string; name: string; type: string }
  | { kind: "cancelled" }
  | { kind: "denied"; canAskAgain: boolean }
  | { kind: "unavailable" };

export interface ReceiptPickerPort {
  /** Open the system photo library (no camera). May prompt for photo-library access. */
  pickFromLibrary(): Promise<ReceiptPickResult>;
}
