/** P4.2c: every outcome of the check-in and of the marker capture has copy in en and fr-CA, with the right words (a refusal is never worded as a success), and the iOS usage strings agree with the copy. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkInFailureText, formatDistance, markerFailureText, needsSettings, type CheckInFailure, type MarkerFailure } from "../src/checkin";
import { translate } from "../src/i18n";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";

const CHECKIN: CheckInFailure[] = [
  { kind: "disabled" },
  { kind: "signed_out" },
  { kind: "no_geometry" },
  { kind: "no_catalog" },
  { kind: "no_timezone" },
  { kind: "already_picked", courseId: "crs_a" },
  { kind: "permission", status: "denied" },
  { kind: "permission", status: "blocked" },
  { kind: "permission", status: "approximate" },
  { kind: "services_off" },
  { kind: "no_fix", reason: "timeout" },
  { kind: "no_fix", reason: "unavailable" },
  { kind: "no_fix", reason: "invalid" },
  { kind: "stale_fix" },
  { kind: "simulated" },
  { kind: "inaccurate", accuracyMeters: 83.4 },
  { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY },
  { kind: "not_here", distanceMeters: 1234, nearby: [] },
  { kind: "not_here", distanceMeters: null, nearby: [] },
  { kind: "failed", message: "x" },
];
const MARKER: MarkerFailure[] = [
  { kind: "disabled" }, { kind: "signed_out" }, { kind: "no_catalog" }, { kind: "no_geometry" }, { kind: "permission", status: "denied" }, { kind: "permission", status: "blocked" }, { kind: "permission", status: "approximate" },
  { kind: "services_off" }, { kind: "no_fix", reason: "timeout" }, { kind: "no_fix", reason: "unavailable" }, { kind: "stale_fix" }, { kind: "simulated" }, { kind: "inaccurate", accuracyMeters: 90 },
  { kind: "not_here", distanceMeters: 800 }, { kind: "no_challenge" }, { kind: "failed", message: "x" },
];

describe.each([["en"], ["fr-CA"]] as const)("copy (%s)", (locale) => {
  const t = (k: Parameters<typeof translate>[1], p?: Parameters<typeof translate>[2]): string => translate(locale, k, p);
  it("every check-in outcome has a sentence with no unfilled placeholder and no raw key", () => {
    for (const o of CHECKIN) {
      const s = checkInFailureText(o, t, { course: "Pine Valley", picked: "Cypress" });
      expect(s, JSON.stringify(o)).not.toMatch(/\{\w+\}|^[a-z]+\.[a-z_.]+$/);
      expect(s.length).toBeGreaterThan(10);
    }
  });
  it("every marker outcome has a sentence too", () => {
    for (const o of MARKER) {
      const s = markerFailureText(o, t, "Pine Valley GC");
      expect(s, JSON.stringify(o)).not.toMatch(/\{\w+\}|^[a-z]+\.[a-z_.]+$/);
      expect(s.length).toBeGreaterThan(10);
    }
  });
  it("names the course, the course already picked, the distance and the accuracy where they matter", () => {
    expect(checkInFailureText({ kind: "not_here", distanceMeters: 1234, nearby: [] }, t, { course: "Pine Valley" })).toContain("Pine Valley");
    expect(checkInFailureText({ kind: "not_here", distanceMeters: 1234, nearby: [] }, t, { course: "Pine Valley" })).toContain("1.2 km");
    expect(checkInFailureText({ kind: "already_picked", courseId: "crs_a" }, t, { course: "Pine Valley", picked: "Cypress" })).toContain("Cypress");
    expect(checkInFailureText({ kind: "inaccurate", accuracyMeters: 83.4 }, t, { course: "x" })).toContain("83");
  });
});

describe("the words are honest", () => {
  it("no refusal says 'checked in' / 'recorded' (en) or 'enregistr' as a success; the saved message says it is saved ON THIS PHONE", () => {
    for (const o of CHECKIN) {
      expect(checkInFailureText(o, (k, p) => translate("en", k, p), { course: "X", picked: "Y" })).not.toMatch(/^Checked in|\bYou are checked in\b/i);
    }
    expect(en["checkin.saved"]).toMatch(/saved on this phone/i);
    expect(frCA["checkin.saved"]).toMatch(/sauvegardée sur ce téléphone/i);
    expect(en["marker.captured"]).toMatch(/kept on this phone/i);
  });

  it("the marker hint says where the record stays (this phone) and does not promise a credit", () => {
    expect(en["marker.hint"]).toMatch(/saves a location check on this phone/i);
    expect(en["marker.hint"]).not.toMatch(/credit|reward|free|earn/i);
    expect(frCA["marker.hint"]).not.toMatch(/crédit|récompense|gratuit|gagn/i);
  });

  it("a permission refusal tells the player the next step (tap again / Settings)", () => {
    expect(en["checkin.err.denied"]).toMatch(/tap/i);
    expect(en["checkin.err.blocked"]).toMatch(/Settings/);
    expect(en["checkin.err.approximate"]).toMatch(/precise/i);
    expect(frCA["checkin.err.blocked"]).toMatch(/Réglages/);
  });

  it("needsSettings is true exactly for a blocked or approximate permission", () => {
    expect(needsSettings({ kind: "permission", status: "blocked" })).toBe(true);
    expect(needsSettings({ kind: "permission", status: "approximate" })).toBe(true);
    expect(needsSettings({ kind: "permission", status: "denied" })).toBe(false);
    expect(needsSettings({ kind: "simulated" })).toBe(false);
  });

  it("formatDistance: metres under a kilometre, one decimal of kilometres above", () => {
    expect([formatDistance(0), formatDistance(849.6), formatDistance(999), formatDistance(1000), formatDistance(12_345)]).toEqual(["0 m", "850 m", "999 m", "1.0 km", "12.3 km"]);
  });
});

describe("the iOS location usage strings (app.json / locales) are honest and match the buttons", () => {
  const app = JSON.parse(readFileSync(fileURLToPath(new URL("../app.json", import.meta.url)), "utf8")) as { expo: { plugins: unknown[] } };
  const entry = app.expo.plugins.find((p) => Array.isArray(p) && p[0] === "expo-location") as [string, Record<string, string>];
  const fr = JSON.parse(readFileSync(fileURLToPath(new URL("../locales/fr-CA.json", import.meta.url)), "utf8")) as Record<string, string>;

  it("the English string names the two buttons by their real labels, the foreground-only promise, and no tracking", () => {
    const s = entry[1]["locationWhenInUsePermission"]!;
    expect(s).toContain(`“${en["course.checkIn"]}”`);
    expect(s).toContain(`“${en["marker.button"]}”`);
    expect(s).toMatch(/only while the app is open/);
    expect(s).toMatch(/never tracks you in the background/);
  });

  it("the French string names the two buttons by their real fr-CA labels too", () => {
    const s = fr["NSLocationWhenInUseUsageDescription"]!;
    expect(s).toContain(`« ${frCA["course.checkIn"]} »`);
    expect(s).toContain(`« ${frCA["marker.button"]} »`);
  });
});
