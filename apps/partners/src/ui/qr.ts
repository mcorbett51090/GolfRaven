/**
 * Canvas QR for the TOTP enrol panel (design §90 / 6.4).
 *
 * Renders via `<canvas>` so CSP `img-src` (no `data:` / `blob:`) stays closed. Encoder is the vendored
 * Nayuki library under `src/lib/qrcodegen.ts` — no npm dependency (partners README).
 */

import { Ecc, QrCode } from "../lib/qrcodegen";

/** Quiet-zone modules on each side (ISO/IEC 18004). */
const QUIET = 4;

/** Pixel size of one module. */
const SCALE = 4;

/**
 * Encode `text` as a QR matrix (dark = true), including the quiet zone.
 * Error correction MEDIUM (~15%) matches typical authenticator-app scans of otpauth URIs.
 */
export function qrModules(text: string): readonly (readonly boolean[])[] {
  const qr = QrCode.encodeText(text, Ecc.MEDIUM);
  const n = qr.size + QUIET * 2;
  const rows: boolean[][] = [];
  for (let y = 0; y < n; y++) {
    const row: boolean[] = [];
    for (let x = 0; x < n; x++) {
      const mx = x - QUIET;
      const my = y - QUIET;
      row.push(mx >= 0 && my >= 0 && mx < qr.size && my < qr.size && qr.getModule(mx, my));
    }
    rows.push(row);
  }
  return rows;
}

/** Draw `text` as a QR code onto `canvas` (resizes the canvas). Returns the module count including quiet zone. */
export function drawQrOnCanvas(canvas: HTMLCanvasElement, text: string): number {
  const modules = qrModules(text);
  const n = modules.length;
  const px = n * SCALE;
  canvas.width = px;
  canvas.height = px;
  const ctx = canvas.getContext("2d");
  if (ctx === null) throw new Error("canvas_2d_unavailable");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, px, px);
  ctx.fillStyle = "#000000";
  for (let y = 0; y < n; y++) {
    const row = modules[y];
    if (row === undefined) continue;
    for (let x = 0; x < n; x++) {
      if (row[x]) ctx.fillRect(x * SCALE, y * SCALE, SCALE, SCALE);
    }
  }
  return n;
}
