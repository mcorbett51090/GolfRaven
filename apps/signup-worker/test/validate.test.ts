import { describe, expect, it } from "vitest";
import { validateSignupPayload } from "../src/validate";

const VALID = {
  email: "Player@Example.com",
  ageConfirmed: true,
  consentVersion: "2026-09-23",
  turnstileToken: "tok",
};

describe("validateSignupPayload", () => {
  it("accepts a well-formed payload and lower-cases the email", () => {
    const result = validateSignupPayload(VALID);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.emailLc).toBe("player@example.com");
      expect(result.value.ageConfirmed).toBe(true);
    }
  });

  it("rejects a non-object body", () => {
    expect(validateSignupPayload(null).ok).toBe(false);
    expect(validateSignupPayload("x").ok).toBe(false);
    expect(validateSignupPayload([]).ok).toBe(false);
  });

  it("rejects a missing/invalid email", () => {
    expect(validateSignupPayload({ ...VALID, email: undefined }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, email: "not-an-email" }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, email: "" }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, email: `${"a".repeat(250)}@example.com` }).ok).toBe(false);
  });

  it("rejects ageConfirmed that is not the literal boolean true", () => {
    expect(validateSignupPayload({ ...VALID, ageConfirmed: "true" }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, ageConfirmed: 1 }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, ageConfirmed: false }).ok).toBe(false);
  });

  it("rejects a consentVersion outside the allow-list", () => {
    expect(validateSignupPayload({ ...VALID, consentVersion: "2020-01-01" }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, consentVersion: 123 }).ok).toBe(false);
  });

  it("rejects a missing or oversized turnstileToken", () => {
    expect(validateSignupPayload({ ...VALID, turnstileToken: "" }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, turnstileToken: undefined }).ok).toBe(false);
    expect(validateSignupPayload({ ...VALID, turnstileToken: "a".repeat(5000) }).ok).toBe(false);
  });

  it("accepts an optional source within the length cap and strips control chars", () => {
    const result = validateSignupPayload({ ...VALID, source: "reddit\u0007" });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.source).toBe("reddit");
  });

  it("rejects an oversized source", () => {
    expect(validateSignupPayload({ ...VALID, source: "x".repeat(100) }).ok).toBe(false);
  });
});
