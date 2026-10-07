import { describe, expect, it } from "vitest";
import { PartnerApiError, type ApiErrorKind } from "../src/api/errors";
import { messageForError } from "../src/app/messages";
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

  it("anything unknown is the generic message and never echoes the error's own text", () => {
    expect(messageForError(new Error("secret"), "session")).toEqual({ key: "error.generic" });
    expect(messageForError("boom", "sign-in")).toEqual({ key: "error.generic" });
  });

  it("every key it can return exists in the English catalogue", () => {
    const keys = [...webauthn.map(([, k]) => k), ...api.map(([, , k]) => k), "error.rateLimited.wait"];
    for (const k of keys) expect(Object.keys(en)).toContain(k);
  });
});
