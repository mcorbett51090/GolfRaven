// supabase/tests/unit/partner-invites-shape.test.ts
//
// The strict body shapes of `partner-invites` / `partner-members` (S1.5) and the invite and enrolment tokens. Pure: no ports. The handler suites state what the handlers DO with these; this one states what the
// shapes accept and refuse on their own.

import { describe, expect, it } from "vitest";
import { normaliseEmail, parseInviteCreateBody, parseInviteListQuery, parseUuid } from "../../functions/_shared/partner/invites-shape.ts";
import { parseRevokeAllBody } from "../../functions/_shared/partner/members-shape.ts";
import { newPartnerEnrolmentToken, newPartnerInviteToken, newPartnerSessionToken, PARTNER_ENROLMENT_TOKEN_RE, PARTNER_INVITE_TOKEN_RE, PARTNER_SESSION_TOKEN_RE, partnerTokenFromHeader, sha256Hex } from "../../functions/_shared/partner/token.ts";
import { ORG_ID } from "./partner-fakes.ts";

describe("the three opaque tokens", () => {
  it("each has its own prefix and shape; the other two shapes never match it, and only the session token is a bearer", async () => {
    const [s, i, e] = [await newPartnerSessionToken(), await newPartnerInviteToken(), await newPartnerEnrolmentToken()];
    expect(s.token).toMatch(PARTNER_SESSION_TOKEN_RE);
    expect(i.token).toMatch(PARTNER_INVITE_TOKEN_RE);
    expect(e.token).toMatch(PARTNER_ENROLMENT_TOKEN_RE);
    for (const [t, others] of [[s.token, [PARTNER_INVITE_TOKEN_RE, PARTNER_ENROLMENT_TOKEN_RE]], [i.token, [PARTNER_SESSION_TOKEN_RE, PARTNER_ENROLMENT_TOKEN_RE]], [e.token, [PARTNER_SESSION_TOKEN_RE, PARTNER_INVITE_TOKEN_RE]]] as const) {
      for (const re of others) expect(re.test(t)).toBe(false);
    }
    expect(partnerTokenFromHeader(`Bearer ${s.token}`)).toBe(s.token);
    expect(partnerTokenFromHeader(`Bearer ${i.token}`)).toBeNull();
    expect(partnerTokenFromHeader(`Bearer ${e.token}`)).toBeNull();
    for (const t of [s, i, e]) expect(t.hash).toBe(await sha256Hex(t.token));
    expect(new Set([s.token, i.token, e.token]).size).toBe(3);
  });
});

describe("normaliseEmail: exactly what the database accepts (lower(btrim), 3 to 254, no whitespace, one @ with text each side)", () => {
  it("accepts and normalises", () => {
    expect(normaliseEmail("  New.Staff@Example.TEST ")).toBe("new.staff@example.test");
    expect(normaliseEmail("a@b")).toBe("a@b");
  });
  it("refuses what the definer would refuse with 22023", () => {
    for (const v of ["", "ab", "no-at", "@x", "x@", "a@b@c", "a b@c.test", "a@b\n.test", `${"a".repeat(250)}@b.test`, 5, null, undefined]) expect(normaliseEmail(v), String(v)).toBeNull();
  });
});

describe("parseUuid and the invite shapes", () => {
  it("a uuid in any case is lower-cased; anything else is null", () => {
    expect(parseUuid(ORG_ID.toUpperCase())).toBe(ORG_ID);
    for (const v of ["", "x", ORG_ID + "0", ORG_ID.replaceAll("-", ""), 5, null]) expect(parseUuid(v)).toBeNull();
  });
  it("POST invites: the three fields, a role that is not sponsor, no extras; a non-object is refused", () => {
    expect(parseInviteCreateBody({ orgId: ORG_ID, role: "manager", email: "A@b.test" })).toEqual({ ok: true, value: { orgId: ORG_ID, role: "manager", email: "a@b.test" } });
    for (const b of [{ orgId: ORG_ID, role: "sponsor", email: "a@b.test" }, { orgId: ORG_ID, role: "staff", email: "a@b.test", token: "x" }, null, [], "x"]) expect(parseInviteCreateBody(b).ok).toBe(false);
  });
  it("GET invites: only ?orgId, once, as a uuid", () => {
    expect(parseInviteListQuery(new URL("https://x.test/p?orgId=" + ORG_ID))).toEqual({ ok: true, value: { orgId: ORG_ID } });
    expect(parseInviteListQuery(new URL("https://x.test/p"))).toEqual({ ok: true, value: { orgId: null } });
    for (const q of ["?orgId=1", "?x=1", `?orgId=${ORG_ID}&orgId=${ORG_ID}`, `?orgId=${ORG_ID}&x=1`]) expect(parseInviteListQuery(new URL("https://x.test/p" + q)).ok, q).toBe(false);
  });
});

describe("parseRevokeAllBody", () => {
  it("an instant that does not exist is refused, not rolled forward; milliseconds are allowed; the result is normalised", () => {
    expect(parseRevokeAllBody({ createdAfter: "2030-02-28T23:59:59.5Z" })).toEqual({ ok: true, value: { createdAfter: "2030-02-28T23:59:59.500Z" } });
    for (const v of ["2030-02-30T00:00:00Z", "2030-13-01T00:00:00Z", "2030-01-01T25:00:00Z", "2030-01-01T00:00:00", "2030-01-01"]) expect(parseRevokeAllBody({ createdAfter: v }).ok, v).toBe(false);
    expect(parseRevokeAllBody({})).toEqual({ ok: true, value: { createdAfter: null } });
    expect(parseRevokeAllBody({ other: 1 }).ok).toBe(false);
  });
});
