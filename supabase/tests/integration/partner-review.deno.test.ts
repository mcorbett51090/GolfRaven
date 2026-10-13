// supabase/tests/integration/partner-review.deno.test.ts
//
// Slice S4 / 0057 + 0061 (docs/security/partner-auth-design.md 27, 115, 122; AT(10)): the REAL `partner-review` handler over the REAL privileged.ts (`partnerDb.withReview` = `withPartnerSession`), a REAL admin
// session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as
// `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The pgTAP file (39_at10_issuance_staff_gate.sql) proves the DATABASE answers `no_active_staff`; the unit suite proves the handler maps a status it is HANDED. Neither
// ran the path between them: `privileged.ts` validates the database's `o_status` against a closed list and THROWS for anything else, so a status the SQL learned (0061) but the list did not was an uncaught 500
// that no cell could see. This file drives an admin's approve of a held offer code at a facility with no active staff through the handler, the validation and the database, and reads the row back.
//
// The one shortcut: the admin's step-up state (aal 2, a live `mfa_until`) is written into the session row by the OWNER with the guard trigger off for that statement only (the pgTAP file and the other
// integration files do the same); TOTP itself is proved elsewhere. Everything else is the real path.

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  adminSql,
  createTestUser,
  ensureServiceRole,
  freshUuid,
  rawOwnerSql,
  withTemporaryOwnerAccess as withOwnerAccess,
} from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { handlePartnerReviewRequest } from "../../functions/_shared/partner/review-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import {
  parseChallengeToken,
  uuidToBytes,
} from "../../functions/_shared/partner/session-shape.ts";
import {
  newPartnerSessionToken,
  sha256Hex,
} from "../../functions/_shared/partner/token.ts";
import { partnerDb } from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const HELD = new Set(["app.partner_credential", "app.partner_org"]);
const rows = <T>(
  table: string,
  query: (sql: ReturnType<typeof rawOwnerSql>) => Promise<T>,
): Promise<T> =>
  withOwnerAccess(
    table,
    query as never,
    HELD.has(table) ? "insert, delete" : "select, insert, update, delete",
  ) as Promise<T>;
await rawOwnerSql().unsafe(
  "grant select, update on app.partner_credential, app.partner_org to current_user",
);

const RP = {
  rpId: "partners.example.test",
  origin: "https://partners.example.test",
};
await rows(
  "app.partner_rp_config",
  (sql) =>
    sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`,
);
const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function sessionCall(
  method: string,
  path: string,
  body: unknown,
): Promise<Response> {
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
  });
  return await handlePartnerSessionRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-session/${path}`,
      { method, headers, body: JSON.stringify(body) },
    ),
    {
      db: partnerDb,
      allowedOrigin: RP.origin,
      webauthn: assertionVerifier,
      otp: {
        send: () => Promise.reject(new Error("unused")),
        verify: () => Promise.reject(new Error("unused")),
      },
      nowMs: () => Date.now(),
      newSessionToken: newPartnerSessionToken,
    },
  );
}

/** The review lane's Storage port is only used by the receipt preview route; the resolve routes never reach it. */
const NO_STORAGE = {
  createSignedUrl: () =>
    Promise.reject(new Error("storage is not used by the resolve routes")),
};
async function review(
  token: string,
  path: string,
  body: unknown,
): Promise<Response> {
  return await handlePartnerReviewRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-review/${path}`,
      {
        method: "POST",
        headers: {
          origin: RP.origin,
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      },
    ),
    { db: partnerDb, storage: NO_STORAGE, allowedOrigin: RP.origin },
  );
}

interface Member {
  readonly uid: string;
  readonly token: string;
  readonly hash: string;
}
let seq = 0;
/** A real credential for `uid` and a session from the real mint (the software authenticator's real assertion). */
async function signInAs(uid: string): Promise<Member> {
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await rows(
    "app.partner_credential",
    (sql) =>
      sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`,
  );
  const o = await sessionCall("POST", "options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  const res = await sessionCall("POST", "verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, token, hash: await sha256Hex(token) };
}

/** A staff member of a fresh org scoped to `facilityId`, with a real credential and a session from the real mint. */
async function newStaff(facilityId: string): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `rv-staff-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"review org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${facilityId})`,
  );
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, 'staff', now() - interval '60 days')`,
  );
  return await signInAs(uid);
}

/** The admin the harness already seeds (helpers.sql puts this uid in app.admin_user, and the pgTAP matrices rely on it in both modes), signed in once with a real credential. Creating an admin here
 * instead (an owner insert into app.admin_user) is not an option: no other integration file does it, and an owner-side fixture insert is exactly what did not persist under HARNESS_MODE=restricted. */
const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0";
let adminSession: Member | null = null;
/** The admin's session at aal 2 with a live second factor (class A3 needs both); re-seeded on every use because `mfa_until` is short. */
async function newAdmin(): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID);
  const m = adminSession;
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = 2, mfa_until = clock_timestamp() + interval '240 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
  return m;
}

// A facility on no member's scope yet (so: no active staff), one live offer, and held offer codes at it. The player and device are the harness's seeded ones (helpers.sql).
const PLAYER = "00000000-0000-0000-0000-00000000000a";
const DEVICE = "20000000-0000-0000-0000-000000000001";
const FAC = `fac_rv${Date.now().toString(36)}`;
// Seeded as service_role, the way marker-scan.deno.test.ts creates its facilities: the same inserts through the owner temp-policy path ran without an error and did NOT persist under HARNESS_MODE=restricted
// (found by running this file in both modes), and everything that referenced the facility then vanished with it.
await ensureServiceRole();
await adminSql()`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${FAC}, 'facility', 'verified', 1)`;
await adminSql()`insert into app.catalog_facility (id, slug, name, region, tz, catalog_version) values (${FAC}, ${"slug-" + FAC}, ${"Review facility"}, 'US-TN', 'America/Chicago', 1)`;

/** A live offer at FAC and a held_review offer code on it, shaped as the activation leaves it. Seeded as service_role, the way the other integration files seed offers and codes. The BEFORE INSERT trigger of a held_review code takes the
 * reservation and pauses its expiry itself (0027), exactly as the activation path does. */
async function heldCode(): Promise<string> {
  const offer = freshUuid();
  const code = freshUuid();
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
    values (${offer}, 'trl_t', ${FAC}, '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live')`;
  await sql`insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, activated_device_id, devicecheck_token_hash, activated_at, hold_detail)
    values (${code}, ${offer}, ${PLAYER}, ${FAC}, 'held_review', now() - interval '1 day', now() + interval '20 days', ${DEVICE}, ${"tok-" + code}, now() - interval '1 hour',
            jsonb_build_object('heldFor', 'no_active_staff'))`;
  return code;
}
const stateOf = async (code: string): Promise<string> => {
  await ensureServiceRole();
  return (await adminSql()`select state::text as s from app.offer_code where id = ${code}`)[0]!.s as string;
};

Deno.test(
  "AT(10): approving a held code at a facility with NO active staff is a 422 `no_active_staff` through the real stack (it was an uncaught 500), and the code stays held",
  DT,
  async () => {
    const admin = await newAdmin();
    const code = await heldCode();
    const res = await review(admin.token, "resolve/offer-code", {
      id: code,
      approve: true,
    });
    const text = await res.clone().text();
    assertEquals(res.status, 422, text);
    assertEquals((await res.json()).error.code, "no_active_staff");
    assertEquals(
      await stateOf(code),
      "held_review",
      "a refusal leaves the code held: the admin can add staff and approve again, or reject",
    );
  },
);

Deno.test(
  "AT(10): a REJECT needs no staff (return-to-earned is not an issuance): 200 and the code is void",
  DT,
  async () => {
    const admin = await newAdmin();
    const code = await heldCode();
    const res = await review(admin.token, "resolve/offer-code", {
      id: code,
      approve: false,
    });
    assertEquals(res.status, 200, await res.clone().text());
    assertEquals((await res.json()).data, { state: "void" });
    assertEquals(await stateOf(code), "void");
  },
);

Deno.test(
  "AT(10): once the facility has active staff the same approve issues the code (200 `issued`)",
  DT,
  async () => {
    const admin = await newAdmin();
    const code = await heldCode();
    assertEquals(
      (
        await review(admin.token, "resolve/offer-code", {
          id: code,
          approve: true,
        })
      ).status,
      422,
      "no staff yet",
    );
    await newStaff(FAC);
    const res = await review(admin.token, "resolve/offer-code", {
      id: code,
      approve: true,
    });
    assertEquals(res.status, 200, await res.clone().text());
    assertEquals((await res.json()).data, { state: "issued" });
    assertEquals(await stateOf(code), "issued");
  },
);
