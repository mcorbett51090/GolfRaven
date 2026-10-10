import { describe, expect, it } from "vitest";
import { PartnerApiError, type ApiErrorKind } from "../src/api/errors";
import { messageForError, messageForPinRejection } from "../src/app/messages";
import { en } from "../src/i18n/messages/en";
import { WebAuthnFailure, type WebAuthnFailureKind } from "../src/webauthn/assertion";

describe("messageForError", () => {
  const webauthn: Array<[WebAuthnFailureKind, string]> = [
    ["unsupported", "error.webauthnUnsupported"],
    ["cancelled", "error.cancelled"],
    ["bad_options", "error.badOptions"],
    ["failed", "error.webauthnFailed"],
  ];
  it.each(webauthn)("WebAuthn %s -> %s", (kind, key) => {
    expect(messageForError(new WebAuthnFailure(kind), "sign-in")).toEqual({ key });
  });

  const api: Array<[ApiErrorKind, "sign-in" | "session", string]> = [
    ["unauthenticated", "sign-in", "error.signInFailed"],
    ["unauthenticated", "session", "error.sessionEnded"],
    ["forbidden", "session", "error.forbidden"],
    ["reauth_refused", "session", "error.forbidden"],
    ["rate_limited", "sign-in", "error.rateLimited"],
    ["unavailable", "sign-in", "error.unavailable"],
    ["network", "sign-in", "error.network"],
    ["server", "session", "error.generic"],
    ["bad_request", "session", "error.generic"],
    ["unsupported_media_type", "sign-in", "error.generic"],
    ["not_found", "session", "error.generic"],
    ["malformed_response", "sign-in", "error.generic"],
  ];
  it.each(api)("API %s in %s -> %s", (kind, ctx, key) => {
    expect(messageForError(new PartnerApiError(kind), ctx)).toEqual({ key });
  });

  it("a 429 with a readable Retry-After names the wait", () => {
    expect(messageForError(new PartnerApiError("rate_limited", { retryAfterSeconds: 90 }), "sign-in")).toEqual({ key: "error.rateLimited.wait", params: { seconds: 90 } });
  });

  describe("the step-up and enrolment contexts read the server's CLOSED error code, never its prose", () => {
    const e = (kind: ApiErrorKind, code: string | null, retryAfterSeconds: number | null = null) => new PartnerApiError(kind, { status: 0, code, retryAfterSeconds });
    const cases: Array<[ApiErrorKind, string | null, Parameters<typeof messageForError>[1], string]> = [
      ["forbidden", "pin_wrong", "pin", "pin.wrong"],
      ["forbidden", "pin_locked", "pin", "pin.locked"],
      ["rate_limited", "pin_backoff", "pin", "pin.backoff"],
      ["conflict", "pin_already_set", "pin", "pin.alreadySet"],
      ["conflict", "pin_not_set", "pin", "pin.notSet"],
      ["conflict", "pin_must_change", "pin", "pin.mustChange"],
      ["forbidden", "forbidden", "pin", "error.forbidden"],
      ["forbidden", "otp_refused", "proof", "proof.refused"],
      ["conflict", "otp_unavailable", "proof", "proof.unavailable"],
      ["forbidden", "totp_wrong", "totp", "totp.wrong"],
      ["forbidden", "totp_locked", "totp", "totp.locked"],
      ["rate_limited", "totp_backoff", "totp", "totp.backoff"],
      ["conflict", "totp_not_set", "totp", "totp.notSet"],
      ["conflict", "totp_unconfirmed", "totp", "totp.unconfirmed"],
      ["conflict", "totp_already_confirmed", "totp", "totp.alreadyConfirmed"],
      ["conflict", "totp_wrong_session", "totp", "totp.wrongSession"],
      ["forbidden", "accept_refused", "enrol", "enrol.refused"],
      ["forbidden", "registration_refused", "enrol", "enrol.refused"],
      ["gone", "expired", "enrol", "enrol.expired"],
      ["conflict", "credential_exists", "enrol", "enrol.conflict"],
      ["unauthenticated", null, "pin", "error.sessionEnded"],
      ["conflict", null, "session", "error.generic"],
      ["gone", null, "sign-in", "error.generic"],
      ["unprocessable", null, "pin", "error.generic"],
    ];
    it.each(cases)("%s %s in %s -> %s", (kind, code, ctx, key) => {
      expect(messageForError(e(kind, code), ctx)).toEqual({ key });
      expect(Object.keys(en)).toContain(key);
    });

    it("a code only counts in its own context (a pin code in the totp context is just a refusal)", () => {
      expect(messageForError(e("forbidden", "pin_wrong"), "totp")).toEqual({ key: "error.forbidden" });
    });

    it("a back-off with a readable Retry-After names the wait", () => {
      expect(messageForError(e("rate_limited", "pin_backoff", 30), "pin")).toEqual({ key: "pin.backoff.wait", params: { seconds: 30 } });
      expect(messageForError(e("rate_limited", "totp_backoff", 12), "totp")).toEqual({ key: "totp.backoff.wait", params: { seconds: 12 } });
    });

    it("every PIN rejection reason has a message", () => {
      for (const r of ["format", "repeated", "run", "year", "date", "common"] as const) expect(Object.keys(en)).toContain(messageForPinRejection(r).key);
    });
  });

  it("anything unknown is the generic message and never echoes the error's own text", () => {
    expect(messageForError(new Error("secret"), "session")).toEqual({ key: "error.generic" });
    expect(messageForError("boom", "sign-in")).toEqual({ key: "error.generic" });
  });

  it("every key it can return exists in the English catalogue", () => {
    const keys = [...webauthn.map(([, k]) => k), ...api.map(([, , k]) => k), "error.rateLimited.wait"];
    for (const k of keys) expect(Object.keys(en)).toContain(k);
  });
});
