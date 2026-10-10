/**
 * `ReceiptPickerPort` over `expo-image-picker`: the ONLY file in the app that imports it.
 *
 * LIBRARY ONLY (P5 §50): `launchImageLibraryAsync` — no camera. The app config sets
 * `cameraPermission: false` / `microphonePermission: false` so CAMERA and RECORD_AUDIO stay blocked
 * (`app.json` + policy allow-list). `[unverified: nothing here has run on a device]`
 */
import * as ImagePicker from "expo-image-picker";
import type { ReceiptPickerPort, ReceiptPickResult } from "./picker";

function mimeOf(uri: string, assetType: string | null | undefined): string {
  const lower = uri.toLowerCase();
  if (lower.endsWith(".png") || assetType === "image/png") return "image/png";
  if (lower.endsWith(".heic") || lower.endsWith(".heif") || assetType === "image/heic" || assetType === "image/heif") {
    return "image/heic";
  }
  return "image/jpeg";
}

function nameOf(uri: string, mime: string): string {
  const base = uri.split("/").pop()?.split("?")[0] ?? "";
  if (base.length > 0 && /\.[A-Za-z0-9]+$/.test(base)) return base.slice(0, 128);
  if (mime === "image/png") return "receipt.png";
  if (mime === "image/heic") return "receipt.heic";
  return "receipt.jpg";
}

export function createExpoReceiptPicker(): ReceiptPickerPort {
  return {
    async pickFromLibrary(): Promise<ReceiptPickResult> {
      try {
        const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
        if (!perm.granted) {
          return { kind: "denied", canAskAgain: perm.canAskAgain };
        }
        const result = await ImagePicker.launchImageLibraryAsync({
          mediaTypes: ["images"],
          allowsEditing: false,
          quality: 1,
          exif: false,
        });
        if (result.canceled || result.assets.length === 0) return { kind: "cancelled" };
        const asset = result.assets[0]!;
        const type = mimeOf(asset.uri, asset.mimeType);
        return { kind: "picked", uri: asset.uri, name: nameOf(asset.uri, type), type };
      } catch {
        return { kind: "unavailable" };
      }
    },
  };
}
