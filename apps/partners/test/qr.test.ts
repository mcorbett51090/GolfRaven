/**
 * Vendored Nayuki QR encoder + canvas helper (design §90).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { Ecc, QrCode } from "../src/lib/qrcodegen";
import { drawQrOnCanvas, qrModules } from "../src/ui/qr";

const OTPAUTH =
  "otpauth://totp/GolfRaven:ops%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GolfRaven&algorithm=SHA1&digits=6&period=30";

/** Golden matrix from Nayuki (ECC M, no quiet zone) for OTPAUTH — regenerable via esbuild of qrcodegen. */
const GOLDEN_PATH = join(dirname(fileURLToPath(import.meta.url)), "fixtures/totp-otpauth-qr-m.txt");

describe("qrcodegen (Nayuki)", () => {
  it("encodes a typical otpauth URI at ECC M matching the committed golden matrix", () => {
    const golden = readFileSync(GOLDEN_PATH, "utf8")
      .trim()
      .split("\n")
      .filter((l) => l.length > 0 && !l.startsWith("#"));
    const qr = QrCode.encodeText(OTPAUTH, Ecc.MEDIUM);
    expect(qr.size).toBe(golden.length);
    for (let y = 0; y < qr.size; y++) {
      let row = "";
      for (let x = 0; x < qr.size; x++) row += qr.getModule(x, y) ? "1" : "0";
      expect(row, `row ${y}`).toBe(golden[y]);
    }
  });

  it("qrModules adds a 4-module quiet zone around the symbol", () => {
    const qr = QrCode.encodeText("HELLO", Ecc.MEDIUM);
    const withQuiet = qrModules("HELLO");
    expect(withQuiet.length).toBe(qr.size + 8);
    expect(withQuiet[0]?.every((c) => !c)).toBe(true);
    expect(withQuiet[4]?.[4]).toBe(qr.getModule(0, 0));
  });
});

describe("drawQrOnCanvas", () => {
  it("resizes the canvas and paints through a 2d context (stub)", () => {
    const fills: Array<{ style: string; x: number; y: number; w: number; h: number }> = [];
    let fillStyle = "";
    const canvas = {
      width: 0,
      height: 0,
      getContext(kind: string) {
        if (kind !== "2d") return null;
        return {
          get fillStyle() {
            return fillStyle;
          },
          set fillStyle(v: string) {
            fillStyle = v;
          },
          fillRect(x: number, y: number, w: number, h: number) {
            fills.push({ style: fillStyle, x, y, w, h });
          },
        };
      },
    } as unknown as HTMLCanvasElement;
    const n = drawQrOnCanvas(canvas, OTPAUTH);
    expect(n).toBeGreaterThan(20);
    expect(canvas.width).toBe(n * 4);
    expect(canvas.height).toBe(n * 4);
    expect(fills[0]?.style).toBe("#ffffff");
    expect(fills.some((f) => f.style === "#000000")).toBe(true);
  });
});
