/**
 * P4.2b-3c (PR #44 gate NIT): what the offline-code card keeps in React state, and when it forgets it. The pure parts (`offline-code/display.ts`) are tested directly; the card itself is
 * a React component this Node suite does not render, so its source is pinned for the properties that matter (no seed in state, the foreground / focus drop, the clock-only countdown).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { OFFLINE_CODE_STEP_SECONDS, appIsForeground, countdownSeconds, isStale, mayShowCode, secondsToNextStep, shownFrom, stepEndMs, type CodeView, type ShownCode } from "../src/offline-code";

const STEP = OFFLINE_CODE_STEP_SECONDS * 1000;
const T = 7 * STEP + 123_456; // inside a step, not on its edge
const view = (over: Partial<CodeView & { status: "ready" }> = {}): CodeView & { status: "ready" } => ({
  status: "ready",
  code: "012345",
  secondsRemaining: 100,
  seedVersion: 3,
  clock: { offsetMs: 1500, warn: false },
  resyncNeeded: false,
  ...over,
});
const src = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

describe("what is kept: the derived digits, never the seed", () => {
  it("shownFrom keeps exactly the code, version, clock estimate, resync flag and the end of the code's step", () => {
    const shown = shownFrom(view(), T);
    expect(shown).toEqual({ code: "012345", seedVersion: 3, clock: { offsetMs: 1500, warn: false }, resyncNeeded: false, validUntilMs: 8 * STEP });
    expect(Object.keys(shown).sort()).toEqual(["clock", "code", "resyncNeeded", "seedVersion", "validUntilMs"]);
  });

  it("nothing in it is a byte array, and it carries nothing a `view()` answer did not (leading zeros of the code are kept)", () => {
    const shown = shownFrom(view({ code: "000042" }), T);
    expect(shown.code).toBe("000042");
    const walk = (x: unknown): void => {
      expect(x instanceof Uint8Array).toBe(false);
      if (typeof x === "object" && x !== null) Object.values(x).forEach(walk);
    };
    walk(shown);
  });

  it("the end of the step is the next 600 s boundary: exactly on a boundary the NEW step has begun", () => {
    expect(stepEndMs(T)).toBe(8 * STEP);
    expect(stepEndMs(7 * STEP)).toBe(8 * STEP);
    expect(stepEndMs(8 * STEP - 1)).toBe(8 * STEP);
    expect(stepEndMs(8 * STEP)).toBe(9 * STEP);
    expect(stepEndMs(0)).toBe(STEP);
  });
});

describe("when the digits must be read again", () => {
  const shown: ShownCode = shownFrom(view(), T);

  it("not stale within their step; stale the instant it ends", () => {
    expect(isStale(shown, 7 * STEP)).toBe(false);
    expect(isStale(shown, T)).toBe(false);
    expect(isStale(shown, 8 * STEP - 1)).toBe(false);
    expect(isStale(shown, 8 * STEP)).toBe(true);
    expect(isStale(shown, 8 * STEP + 5_000)).toBe(true);
  });

  it("stale when the device clock moved BACK before the start of their step (a manual clock change)", () => {
    expect(isStale(shown, 7 * STEP - 1)).toBe(true);
    expect(isStale(shown, 3 * STEP)).toBe(true);
  });

  it("the countdown is computed from the clock alone (no seed): 1 to 600, and 600 exactly on a boundary", () => {
    expect(countdownSeconds(T)).toBe(secondsToNextStep(T));
    expect(countdownSeconds(7 * STEP)).toBe(600);
    expect(countdownSeconds(8 * STEP - 1000)).toBe(1);
    expect(countdownSeconds(T)).toBe(Math.ceil((8 * STEP - T) / 1000));
  });
});

describe("when the digits must be forgotten", () => {
  it("only an `active` app counts as the foreground: inactive (the app switcher, a system sheet), background and unknown values do not", () => {
    expect(appIsForeground("active")).toBe(true);
    for (const s of ["inactive", "background", "unknown", "extension", ""]) expect(appIsForeground(s), s).toBe(false);
  });

  it("the code may be kept only while the Me tab is focused AND the app is in the foreground", () => {
    expect(mayShowCode({ focused: true, appState: "active" })).toBe(true);
    expect(mayShowCode({ focused: false, appState: "active" })).toBe(false); // tabs stay mounted: blur drops it
    expect(mayShowCode({ focused: true, appState: "background" })).toBe(false);
    expect(mayShowCode({ focused: true, appState: "inactive" })).toBe(false);
    expect(mayShowCode({ focused: false, appState: "background" })).toBe(false);
  });
});

describe("the card (source pinned: it is a React component, not rendered here)", () => {
  const code = strip(src("../src/screens/OfflineCodeCard.tsx"));

  it("never holds or even names the seed: no StoredSeed, no seed state, no seed accessor, no byte array", () => {
    expect(code).not.toMatch(/StoredSeed|loadSeed|viewOf|\bseed\b|seedBytes|Uint8Array|base32|hmac|codeAt\(/);
    expect(code).not.toMatch(/useState<[^>]*(Seed|Uint8Array)/);
    const states = [...code.matchAll(/useState(?:<([^>]*)>)?\(/g)].map((m) => m[1] ?? "");
    expect(states.length).toBeGreaterThanOrEqual(5);
    for (const t of states) expect(t).not.toMatch(/seed|bytes/i); // (`offline.noSeed` is a message key, not state)
    expect(code).toMatch(/useState<ShownCode \| null>\(null\)/);
  });

  it("gets the digits only from the manager's `view()`, which reads the seed and drops it", () => {
    expect(code).toMatch(/services\.offlineCode\.view\(at\)/);
    expect(code).toMatch(/shownFrom\(v, at\)/);
    expect(code).not.toMatch(/services\.offlineCode\.(?!view\(|provision\()\w+/);
  });

  it("drops the digits when the tab loses focus or the app leaves the foreground (and on unmount), and recomputes them only while visible", () => {
    expect(code).toMatch(/useIsFocused\(\)/);
    expect(code).toMatch(/AppState\.currentState/);
    expect(code).toMatch(/AppState\.addEventListener\("change"/);
    expect(code).toMatch(/const visible = userId !== null && mayShowCode\(\{ focused, appState \}\)/);
    expect(code).toMatch(/useEffect\(\(\) => \{\s*setShown\(null\);\s*setLoaded\(false\);\s*return \(\) => setShown\(null\);\s*\}, \[visible, userId\]\)/);
    expect(code).toMatch(/if \(!visible\) return undefined;/);
  });

  it("recomputes when the step ends, and the countdown comes from the clock (`countdownSeconds(now)`), not from a stored view", () => {
    expect(code).toMatch(/if \(isStale\(shown, at\)\) setReload\(/);
    expect(code).toMatch(/formatCountdown\(countdownSeconds\(now\)\)/);
  });
});
