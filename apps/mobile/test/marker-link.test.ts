import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCourseQrLink } from "../src/marker/link";

/** Structural stand-in for a rotating course-QR JWS (three base64url segments). Not a real JWT — avoids the gitleaks `jwt` rule. */
const TOKEN = "aa.bb.cc";
const KID = "kid_1";
const SIG86 = "A".repeat(86);

describe("parseCourseQrLink", () => {
  it("parses a rotating /q/m#token link", () => {
    expect(parseCourseQrLink(`https://golfraven.app/q/m#${TOKEN}`)).toEqual({ kind: "rotating", token: TOKEN });
    expect(parseCourseQrLink(`https://preview.example.com/q/m/#${TOKEN}`)).toEqual({ kind: "rotating", token: TOKEN });
  });

  it("parses a printed /q/f/<slug>#kid.sig link", () => {
    expect(parseCourseQrLink(`https://golfraven.app/q/f/maple-glen#${KID}.${SIG86}`)).toEqual({
      kind: "static_pin",
      facilitySlug: "maple-glen",
      kid: KID,
      sig: SIG86,
    });
  });

  it("refuses http, wrong paths, missing fragments, and malformed parts", () => {
    expect(parseCourseQrLink(`http://golfraven.app/q/m#${TOKEN}`)).toBeNull();
    expect(parseCourseQrLink(`https://golfraven.app/q/x#${TOKEN}`)).toBeNull();
    expect(parseCourseQrLink("https://golfraven.app/q/m")).toBeNull();
    expect(parseCourseQrLink("https://golfraven.app/q/m#")).toBeNull();
    expect(parseCourseQrLink(`https://golfraven.app/q/f/slug#${KID}`)).toBeNull();
    expect(parseCourseQrLink(`https://golfraven.app/q/f/slug#${KID}.short`)).toBeNull();
    expect(parseCourseQrLink("not a url")).toBeNull();
    expect(parseCourseQrLink("")).toBeNull();
  });

  it("does not call the network or invent a scan body", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/marker/link.ts"), "utf8");
    expect(src).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|\.scanMarker\b|scanMarker\s*\(/);
  });
});
