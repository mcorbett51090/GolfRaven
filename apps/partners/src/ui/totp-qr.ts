/**
 * TOTP enrol QR element (design §90): canvas + aria label. Seed / otpauth text stay in the panel below.
 */

import { h } from "./dom";
import { drawQrOnCanvas } from "./qr";

export function totpQrCanvas(otpauthUrl: string, ariaLabel: string): HTMLCanvasElement {
  const canvas = h("canvas", {
    class: "totp-qr",
    role: "img",
    "aria-label": ariaLabel,
    "data-testid": "totp-qr",
  }) as HTMLCanvasElement;
  drawQrOnCanvas(canvas, otpauthUrl);
  return canvas;
}
