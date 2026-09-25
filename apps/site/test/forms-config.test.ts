/**
 * forms-config.test.ts — unit coverage for
 * `src/config/forms-config.mjs`'s placeholder-detection logic (this
 * task's scope: "While the config is unset, a form must not pretend to
 * submit... Add a unit test for this"). This is the SAME function both
 * `SecureFormScript.astro`'s build-time render (no Turnstile widget/
 * loader while unconfigured) and its client-side submit handler (no
 * `fetch()`, a "forms aren't live yet" message) import directly — see
 * that component's doc — so covering it here covers both call sites at
 * once, without needing a browser/e2e harness for this particular
 * behaviour.
 */
import { describe, expect, it } from "vitest";
import {
  FORMS_CONFIG,
  formsWorkerHost,
  isFormsConfigured,
  isPlaceholderValue,
  TURNSTILE_HOSTS,
} from "../src/config/forms-config.mjs";

describe("isPlaceholderValue", () => {
  it.each([
    [undefined, true],
    [null, true],
    ["", true],
    ["TODO(owner): fill me in", true],
    ["todo(owner): case-insensitive", true],
    // No leading-whitespace tolerance: only a value that STARTS with the
    // literal marker is treated as a placeholder — deliberately narrow,
    // so a real value that happens to mention "TODO" mid-string is never
    // misclassified.
    ["  TODO(owner): leading whitespace means this does NOT match", false],
    ["https://raven-secure-upload.matt-769.workers.dev", false],
    ["golfraven", false],
    ["0xAAAAAAAAAAAAAAAAAAAAAA", false],
  ])("isPlaceholderValue(%o) => %s", (value, expected) => {
    expect(isPlaceholderValue(value as never)).toBe(expected);
  });
});

describe("isFormsConfigured", () => {
  it("the REAL, committed FORMS_CONFIG (this repo's current state) is NOT configured", () => {
    // The whole point of the TODO(owner) placeholders: this must be false
    // until the owner provisions golfraven into the shared Worker.
    expect(isFormsConfigured(FORMS_CONFIG)).toBe(false);
    expect(FORMS_CONFIG.siteId).toBe("golfraven");
    expect(isPlaceholderValue(FORMS_CONFIG.workerUrl)).toBe(true);
    expect(isPlaceholderValue(FORMS_CONFIG.turnstileSiteKey)).toBe(true);
  });

  it("false when ANY single field is still a placeholder (not just when all three are)", () => {
    const base = {
      workerUrl: "https://raven-secure-upload.matt-769.workers.dev",
      siteId: "golfraven",
      turnstileSiteKey: "0xREALKEY",
    };
    expect(isFormsConfigured(base)).toBe(true);
    expect(isFormsConfigured({ ...base, workerUrl: "TODO(owner): worker url" })).toBe(false);
    expect(isFormsConfigured({ ...base, siteId: "" })).toBe(false);
    expect(isFormsConfigured({ ...base, turnstileSiteKey: undefined as unknown as string })).toBe(false);
  });

  it("true once every field is a real, non-placeholder value", () => {
    expect(
      isFormsConfigured({
        workerUrl: "https://raven-secure-upload.matt-769.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
      }),
    ).toBe(true);
  });
});

describe("formsWorkerHost", () => {
  it("null while unconfigured — the current, committed FORMS_CONFIG", () => {
    expect(formsWorkerHost(FORMS_CONFIG)).toBeNull();
  });

  it("the exact host, once configured with a real URL", () => {
    expect(
      formsWorkerHost({
        workerUrl: "https://raven-secure-upload.matt-769.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
      }),
    ).toBe("raven-secure-upload.matt-769.workers.dev");
  });

  it("null on a malformed workerUrl, even if otherwise 'configured'-shaped", () => {
    expect(
      formsWorkerHost({
        workerUrl: "not a url at all",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
      }),
    ).toBeNull();
  });
});

describe("TURNSTILE_HOSTS", () => {
  it("is exactly Cloudflare's Turnstile host — the CSP generator allow-lists nothing broader", () => {
    expect(TURNSTILE_HOSTS).toEqual(["challenges.cloudflare.com"]);
  });
});
