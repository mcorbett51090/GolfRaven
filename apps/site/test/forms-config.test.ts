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
  assertValidFormsConfig,
  buildFormsConfig,
  FORMS_CONFIG,
  formsWorkerHost,
  isFormsConfigured,
  isPlaceholderValue,
  isValidWorkerUrl,
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
    ["https://secure-upload.example.workers.dev", false],
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
      workerUrl: "https://secure-upload.example.workers.dev",
      siteId: "golfraven",
      turnstileSiteKey: "0xREALKEY",
      contactEmail: "",
    };
    expect(isFormsConfigured(base)).toBe(true);
    expect(isFormsConfigured({ ...base, workerUrl: "TODO(owner): worker url" })).toBe(false);
    expect(isFormsConfigured({ ...base, siteId: "" })).toBe(false);
    expect(isFormsConfigured({ ...base, turnstileSiteKey: undefined as unknown as string })).toBe(false);
  });

  it("true once every field is a real, non-placeholder value", () => {
    expect(
      isFormsConfigured({
        workerUrl: "https://secure-upload.example.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
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
        workerUrl: "https://secure-upload.example.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
      }),
    ).toBe("secure-upload.example.workers.dev");
  });

  it("null on a malformed workerUrl, even if otherwise 'configured'-shaped", () => {
    expect(
      formsWorkerHost({
        workerUrl: "not a url at all",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
      }),
    ).toBeNull();
  });
});

describe("TURNSTILE_HOSTS", () => {
  it("is exactly Cloudflare's Turnstile host — the CSP generator allow-lists nothing broader", () => {
    expect(TURNSTILE_HOSTS).toEqual(["challenges.cloudflare.com"]);
  });
});

// ---------------------------------------------------------------------
// S1 (gate review): "Validate workerUrl. 'Configured' only if it parses
// as protocol https:, with no username or password, no port, and a
// hostname matching ^[a-z0-9.-]+$ with no *. If a value is
// non-placeholder but invalid, throw at build time."
// ---------------------------------------------------------------------

describe("isValidWorkerUrl", () => {
  it("a real, well-formed https: Worker URL is valid", () => {
    expect(isValidWorkerUrl("https://secure-upload.example.workers.dev")).toBe(true);
    expect(isValidWorkerUrl("https://secure-upload.example.workers.dev/")).toBe(true);
  });

  it("http: (not https:) is rejected", () => {
    expect(isValidWorkerUrl("http://secure-upload.example.workers.dev")).toBe(false);
  });

  it("a wildcard hostname is rejected", () => {
    expect(isValidWorkerUrl("https://*.example.workers.dev")).toBe(false);
    expect(isValidWorkerUrl("https://*.workers.dev")).toBe(false);
  });

  it("a scheme-less value is rejected — this is the 'must not become a relative POST' case", () => {
    // Without this check, `fetch(\`${workerUrl}/submit\`)` on a
    // scheme-less string like this would resolve RELATIVE to the
    // current page's own origin (e.g. POSTing to
    // "https://golfraven.example/raven-secure-upload.workers.dev/submit"
    // on this very site) instead of failing loudly — silently sending
    // name/email/message to the wrong place, or nowhere at all.
    expect(isValidWorkerUrl("raven-secure-upload.workers.dev")).toBe(false);
    expect(isValidWorkerUrl("secure-upload.example.workers.dev")).toBe(false);
    expect(isValidWorkerUrl("//secure-upload.example.workers.dev")).toBe(false);
  });

  it("userinfo (username/password) in the URL is rejected", () => {
    expect(isValidWorkerUrl("https://user@secure-upload.example.workers.dev")).toBe(false);
    expect(isValidWorkerUrl("https://user:pass@secure-upload.example.workers.dev")).toBe(false);
  });

  it("a non-default port is rejected; the default https port (443, normalised away by URL parsing) is fine", () => {
    expect(isValidWorkerUrl("https://secure-upload.example.workers.dev:8443")).toBe(false);
    expect(isValidWorkerUrl("https://secure-upload.example.workers.dev:443")).toBe(true);
  });

  it("injected quote/control characters in the hostname are rejected", () => {
    expect(isValidWorkerUrl('https://ho"st.example.com')).toBe(false);
    expect(isValidWorkerUrl("https://ho<script>st.example.com")).toBe(false);
    // A hostname with an embedded space fails URL PARSING outright (not
    // just the regex) — still correctly rejected, via the try/catch.
    expect(isValidWorkerUrl("https://ho st.example.com")).toBe(false);
  });

  it("an uppercase hostname is fine — the URL parser itself lower-cases it before this checks the regex", () => {
    expect(isValidWorkerUrl("https://SECURE-UPLOAD.EXAMPLE.WORKERS.DEV")).toBe(true);
  });

  it("non-string / empty / unparseable input never throws, always returns false", () => {
    expect(isValidWorkerUrl("")).toBe(false);
    expect(isValidWorkerUrl(undefined as unknown as string)).toBe(false);
    expect(isValidWorkerUrl(null as unknown as string)).toBe(false);
    expect(isValidWorkerUrl("not a url at all")).toBe(false);
    // The literal TODO(owner) placeholder itself — also correctly "not
    // a valid URL" (isFormsConfigured() below is what treats a
    // placeholder as its own, non-error case).
    expect(isValidWorkerUrl("TODO(owner): raven-site-kit secure-upload Worker URL")).toBe(false);
  });
});

describe("assertValidFormsConfig — throws at build time for a SET-but-invalid workerUrl", () => {
  it("does NOT throw for the placeholder (unset is fine)", () => {
    expect(() =>
      assertValidFormsConfig({
        workerUrl: "TODO(owner): raven-site-kit secure-upload Worker URL",
        siteId: "golfraven",
        turnstileSiteKey: "TODO(owner): golfraven Turnstile site key",
        contactEmail: "",
      }),
    ).not.toThrow();
  });

  it("does NOT throw for a real, valid workerUrl", () => {
    expect(() =>
      assertValidFormsConfig({
        workerUrl: "https://secure-upload.example.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
      }),
    ).not.toThrow();
  });

  it.each([
    ["http: instead of https:", "http://secure-upload.example.workers.dev"],
    ["a wildcard hostname", "https://*.example.workers.dev"],
    ["a scheme-less value", "secure-upload.example.workers.dev"],
    ["userinfo in the URL", "https://user:pass@secure-upload.example.workers.dev"],
    ["a non-default port", "https://secure-upload.example.workers.dev:8443"],
  ])("THROWS for a SET-but-invalid workerUrl (%s)", (_label, badUrl) => {
    expect(() =>
      assertValidFormsConfig({
        workerUrl: badUrl,
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
      }),
    ).toThrow(/not a valid Worker URL/);
  });

  it("the REAL, committed FORMS_CONFIG never throws (it's still the placeholder)", () => {
    expect(() => assertValidFormsConfig(FORMS_CONFIG)).not.toThrow();
  });
});

describe("isFormsConfigured also enforces isValidWorkerUrl, not just non-placeholder", () => {
  it("false for a non-placeholder but INVALID workerUrl (http:)", () => {
    expect(
      isFormsConfigured({
        workerUrl: "http://secure-upload.example.workers.dev",
        siteId: "golfraven",
        turnstileSiteKey: "0xREALKEY",
        contactEmail: "",
      }),
    ).toBe(false);
  });
});

describe("buildFormsConfig — env var override (this is how a real deployment, and this repo's own test suite, sets real values without hand-editing the source)", () => {
  it("env vars set => those values win, siteId always stays 'golfraven'", () => {
    const config = buildFormsConfig({
      GOLFRAVEN_FORMS_WORKER_URL: "https://secure-upload.example.workers.dev",
      GOLFRAVEN_FORMS_TURNSTILE_SITE_KEY: "1x00000000000000000000AA",
      GOLFRAVEN_FORMS_CONTACT_EMAIL: "hello@example.test",
    });
    expect(config).toEqual({
      workerUrl: "https://secure-upload.example.workers.dev",
      siteId: "golfraven",
      turnstileSiteKey: "1x00000000000000000000AA",
      contactEmail: "hello@example.test",
    });
    expect(isFormsConfigured(config)).toBe(true);
  });

  it("no env vars set => falls back to the TODO(owner) placeholders, unconfigured", () => {
    const config = buildFormsConfig({});
    expect(isFormsConfigured(config)).toBe(false);
    expect(isPlaceholderValue(config.workerUrl)).toBe(true);
    expect(isPlaceholderValue(config.turnstileSiteKey)).toBe(true);
    expect(config.contactEmail).toBe("");
  });

  it("a blank/whitespace-only env var is treated as unset, not as an empty override", () => {
    const config = buildFormsConfig({ GOLFRAVEN_FORMS_WORKER_URL: "   " });
    expect(isPlaceholderValue(config.workerUrl)).toBe(true);
  });
});
