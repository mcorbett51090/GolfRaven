// supabase/tests/unit/partner-edge-pwa-error-contract.test.ts
//
// The Edge -> portal error contract, run END TO END: a REAL `Response` built by the Edge's own helpers, classified the way the portal's client
// classifies it (`api/client.ts`: the `error.code` in the body, `kindForStatus`, `Retry-After` only on a 429), then handed to the portal's REAL
// `messageForError`. Each side already had unit tests, and they agreed with themselves while disagreeing with each other:
//
//   * the portal keyed "a new member's daily limit has been reached" on the code `cold_start_cap` (design 26.1, 28.2), and the Edge answered every
//     cap with the generic `rate_limited`, so the explanation could never be shown and staff were told to "try again in 3600 s" for a rolling 24 hour cap;
//   * a 409 on ADDING a passkey (`credential_exists`, `credential_in_use`, ...) fell into the portal's "conflict" fallback of the credentials
//     context and read "That passkey was already revoked."
//
// What this file does NOT cover, on purpose and recorded in design 115.3: a self-attest. The database raises a generic 22023 for it, so the Edge can only
// say `422 invalid_request`; the portal's `self_attestation_refused` key waits for a database status that does not exist yet (needs a migration).

import { describe, expect, it } from "vitest";
import {
  coldStartCapped,
  rateLimited,
  registrationRefusal,
} from "../../functions/_shared/partner/handler-kit.ts";
import { partnerError } from "../../functions/_shared/partner/http.ts";
import type { OriginDecision } from "../../functions/_shared/partner/cors.ts";
import {
  kindForStatus,
  parseRetryAfter,
  PartnerApiError,
} from "../../../apps/partners/src/api/errors.ts";
import {
  messageForError,
  type ErrorContext,
} from "../../../apps/partners/src/app/messages.ts";
import { en } from "../../../apps/partners/src/i18n/messages/en.ts";
import { frCA } from "../../../apps/partners/src/i18n/messages/fr-CA.ts";

const DECISION: OriginDecision = {
  kind: "allowed",
  origin: "https://partners.example.test",
};
const NOW = 1_780_000_000_000;

/** What the portal's client makes of an Edge response (the same three steps as `api/client.ts`). */
async function asPortalError(res: Response): Promise<PartnerApiError> {
  const body = (await res.json()) as { error?: { code?: unknown } };
  const code = typeof body.error?.code === "string" ? body.error.code : null;
  const kind = kindForStatus(res.status, code);
  return new PartnerApiError(kind, {
    status: res.status,
    code,
    retryAfterSeconds:
      kind === "rate_limited"
        ? parseRetryAfter(res.headers.get("retry-after"), NOW)
        : null,
  });
}

const text = (key: string): string => {
  expect(Object.keys(en), `${key} in en`).toContain(key);
  expect(Object.keys(frCA), `${key} in fr-CA`).toContain(key);
  return (en as Record<string, string>)[key]!;
};

describe("the cold-start cap: the Edge's 429 reaches the member as the explanation, in every context that can raise it", () => {
  const contexts: Array<[ErrorContext, string]> = [
    ["attest", "attest.coldStart"],
    ["handover", "handover.coldStart"],
    ["offer-redeem", "offerRedeem.coldStart"],
  ];

  it("is a 429 with its OWN code and the same Retry-After hour as every other cap", async () => {
    const res = coldStartCapped(DECISION);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    const err = await asPortalError(res);
    expect([err.kind, err.code, err.retryAfterSeconds]).toEqual([
      "rate_limited",
      "cold_start_cap",
      3600,
    ]);
  });

  it.each(contexts)(
    '%s: the portal says why (%s), not "try again in 3600 s"',
    async (context, key) => {
      const err = await asPortalError(coldStartCapped(DECISION));
      expect(messageForError(err, context)).toEqual({ key });
      text(key);
    },
  );

  it("the generic cap is still the generic wait (the two stay distinguishable)", async () => {
    const err = await asPortalError(
      rateLimited(DECISION, "too many failed attempts: try again later", 3600),
    );
    expect(err.code).toBe("rate_limited");
    for (const [context, key] of contexts) {
      const m = messageForError(err, context);
      expect(m.key, context).not.toBe(key);
      expect(m.params, context).toEqual({ seconds: 3600 });
    }
  });
});

describe('adding a passkey: the Edge\'s 409 refusals never read as "already revoked"', () => {
  // `registrationRefusal` is the ONE place the Edge builds these (members-handler POST credentials and the enrolment ceremony).
  const addRefusals: Array<[string, string]> = [
    ["credential_exists", "enrol.conflict"],
    ["credential_in_use", "enrol.conflict"],
    ["already_registered", "enrol.conflict"],
    ["other_membership", "enrol.conflict"],
    ["too_many", "credentials.tooMany"],
  ];

  it.each(addRefusals)(
    "409 %s -> %s in the credentials context",
    async (status, key) => {
      const res = registrationRefusal(DECISION, status);
      expect(res.status).toBe(409);
      const err = await asPortalError(res);
      expect(err.code).toBe(status);
      expect(messageForError(err, "credentials")).toEqual({ key });
      expect(key).not.toBe("credentials.alreadyRevoked");
      text(key);
    },
  );

  it("an actual revoke conflict (the Edge's explicit already_revoked) still reads as already revoked", async () => {
    const err = await asPortalError(
      partnerError(
        DECISION,
        409,
        "already_revoked",
        "this credential has already been revoked",
      ),
    );
    expect(messageForError(err, "credentials")).toEqual({
      key: "credentials.alreadyRevoked",
    });
  });
});
