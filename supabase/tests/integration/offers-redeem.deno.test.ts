// supabase/tests/integration/offers-redeem.deno.test.ts
//
// Slice P5.1b / 0060 (docs/security/partner-auth-design.md 4.5, 6.3, 35, 126; AT(14)): the REAL `partner-offers-redeem` handler over the REAL privileged.ts (`partnerDb.withOffersRedeem` = `withPartnerSession`), a REAL staff
// session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner`
// through SET LOCAL ROLE). This is the money path: a staff member redeems a player's issued offer code against the player's check-in token.
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port and the pgTAP matrix calls the definers directly. Neither runs the Edge's own call (`::uuid` / `::text` arguments, the status list, the row
// mapping of the queue) end to end, nor reads the effects back: the code, the offer's budget, the attestation and the replay guard. Every effect below is read as service_role, not through the code under test.
//
// The same shortcut as the other partner integration files: a PIN grant (one per action, 50 s) is written by the OWNER with the session-guard trigger off for that one statement; the PIN itself is proved elsewhere.

// `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The pgTAP file (39_at10_issuance_staff_gate.sql) proves the DATABASE answers `no_active_staff`; the unit suite proves the handler maps a status it is HANDED. Neither
// ran the path between them: `privileged.ts` validates the database's `o_status` against a closed list and THROWS for anything else, so a status the SQL learned (0061) but the list did not was an uncaught 500
// that no cell could see. This file drives an admin's approve of a held offer code at a facility with no active staff through the handler, the validation and the database, and reads the row back.
//
// The one shortcut: the admin's step-up state (aal 2, a live `mfa_until`) is written into the session row by the OWNER with the guard trigger off for that statement only (the pgTAP file and the other
// integration files do the same); TOTP itself is proved elsewhere. Everything else is the real path.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
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
import { handlePartnerOffersRedeemRequest } from "../../functions/_shared/partner/offers-redeem-handler.ts";
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
  await createTestUser(uid, `rd-staff-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"redeem org " + seq})`,
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

const FAC = "fac_x"; // seeded by the harness (helpers.sql), on trail trl_t, with a timezone

/** A PIN grant, as a verified PIN leaves it (50 s): the owner writes it with the guard trigger off for this statement only. One per action (class A1). */
async function grant(m: Member): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set pin_grant_until = clock_timestamp() + interval '50 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}

async function redeemCall(
  m: Member,
  path: string,
  method: "GET" | "POST",
  body?: unknown,
  withGrant = true,
): Promise<Response> {
  if (withGrant && method === "POST") await grant(m);
  const headers = new Headers({
    origin: RP.origin,
    authorization: `Bearer ${m.token}`,
  });
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handlePartnerOffersRedeemRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-offers-redeem/${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    ),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
const redeem = (m: Member, offerCodeId: string, credential: string, withGrant = true) =>
  redeemCall(m, "redeem", "POST", { facilityId: FAC, offerCodeId, method: "staff_scan", credential }, withGrant);
const errOf = async (res: Response) => (await res.json()).error?.code as string;

interface Player {
  readonly uid: string;
  readonly handle: string;
  readonly device: string;
}
async function newPlayer(): Promise<Player> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `rd-plr-${seq}`);
  const device = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.device (id, user_id, platform) values (${device}, ${uid}, 'ios')`;
  return { uid, handle: `u${uid.replace(/-/g, "").slice(0, 19)}`, device };
}
/** The player's check-in token at FAC (what the player shows the staff member), seeded the way the attest test seeds it; its jti is the redeem credential. */
async function newToken(p: Player, ttlMinutes = 10): Promise<string> {
  const challenge = freshUuid();
  const jti = freshUuid();
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) values (${challenge}, ${p.uid}, ${p.device}, ${FAC}, ${"n-" + challenge}, now() + ${ttlMinutes + " minutes"}::interval, 'live')`;
  await sql`insert into app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) values (${jti}, ${challenge}, ${p.uid}, ${p.device}, ${FAC}, 'attested', 'live', now(), now() + ${ttlMinutes + " minutes"}::interval)`;
  return jti;
}
/** A live offer at FAC with the given cap and reservation. A fresh offer per code: (user, offer) is unique. */
async function newOffer(cap: number, reserved: number): Promise<string> {
  const id = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, budget_reserved, face_value, valid_from, valid_to, status)
    values (${id}, 'trl_t', ${FAC}, '{}'::jsonb, 'operator', ${cap}, ${reserved}, 10, current_date, current_date + 30, 'live')`;
  return id;
}
/** An issued offer code for `p` against `offerId`, as the activation leaves it, carrying its reservation. */
async function issuedCode(p: Player, offerId: string, reservedAmount = 10): Promise<string> {
  const id = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, activated_device_id, devicecheck_token_hash, activated_at, reserved_amount)
    values (${id}, ${offerId}, ${p.uid}, ${FAC}, 'issued', now() - interval '1 day', now() + interval '20 days', ${p.device}, ${"tok-" + id}, now() - interval '1 hour', ${reservedAmount})`;
  return id;
}
/** An offer with a 100 cap and one 10 reservation, an issued code for a new player, and that player's token: the ordinary redeemable thing. */
async function redeemable() {
  const player = await newPlayer();
  const offer = await newOffer(100, 10);
  const code = await issuedCode(player, offer);
  return { player, offer, code, jti: await newToken(player) };
}

interface CodeRow { state: string; redeemed_by_staff: string | null; redeemed_at: Date | null; redeemed_offline: boolean }
const codeRow = async (id: string): Promise<CodeRow> => {
  await ensureServiceRole();
  return (await adminSql()`select state::text as state, redeemed_by_staff::text as redeemed_by_staff, redeemed_at, redeemed_offline from app.offer_code where id = ${id}`)[0] as unknown as CodeRow;
};
const budgetOf = async (offerId: string): Promise<{ used: number; reserved: number }> => {
  await ensureServiceRole();
  const r = (await adminSql()`select budget_used::text as used, budget_reserved::text as reserved from app.offer where id = ${offerId}`)[0]!;
  return { used: Number(r.used), reserved: Number(r.reserved) };
};

Deno.test(
  "P5.1b: the queue lists the facility's issued offer codes with the player's handle, an ISO expiry and the face value as a number",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const { player, offer, code } = await redeemable();
    const res = await redeemCall(staff, `queue?facilityId=${FAC}`, "GET");
    assertEquals(res.status, 200, await res.clone().text());
    const rowsOut = (await res.json()).data.offerCodes as Array<Record<string, unknown>>;
    const mine = rowsOut.find((r) => r.offerCodeId === code)!;
    assert(mine, "the issued code is in the queue");
    assertEquals([mine.offerId, mine.playerHandle, mine.faceValue], [offer, player.handle, 10]);
    assert(typeof mine.expiresAt === "string" && !Number.isNaN(Date.parse(mine.expiresAt)), "an ISO timestamp");
  },
);

Deno.test(
  "P5.1b: a staff scan redeems the code through the real stack: 201 with the attestation, the code redeemed by that staff member, the budget moved from reserved to used, and the attestation row is the staff member's",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const { player, offer, code, jti } = await redeemable();
    assertEquals(await budgetOf(offer), { used: 0, reserved: 10 });

    const res = await redeem(staff, code, jti);
    assertEquals(res.status, 201, await res.clone().text());
    const attestationId = (await res.json()).data.attestationId as string;
    assert(/^[0-9a-f-]{36}$/.test(attestationId), "a uuid");

    const row = await codeRow(code);
    assertEquals([row.state, row.redeemed_by_staff, row.redeemed_offline], ["redeemed", staff.uid, false]);
    assert(row.redeemed_at instanceof Date, "redeemed_at is set");
    assertEquals(await budgetOf(offer), { used: 10, reserved: 0 });

    await ensureServiceRole();
    const att = (await adminSql()`select kind::text as kind, staff_user_id::text as staff, player_user_id::text as player, facility_id from app.attestation where id = ${attestationId}`)[0];
    assertEquals(att, { kind: "offer_redemption", staff: staff.uid, player: player.uid, facility_id: FAC });
  },
);

Deno.test(
  "P5.1b: the same token twice is 409 replayed (the second code stays issued and the budget is untouched); another player's token is 422 token_invalid; a redeemed code is 422 not_issued",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const a = await redeemable();
    assertEquals((await redeem(staff, a.code, a.jti)).status, 201);

    // the same player, a second offer: their (now consumed) token again
    const offer2 = await newOffer(100, 10);
    const code2 = await issuedCode(a.player, offer2);
    const again = await redeem(staff, code2, a.jti);
    assertEquals([again.status, await errOf(again)], [409, "replayed"]);
    assertEquals((await codeRow(code2)).state, "issued");
    assertEquals(await budgetOf(offer2), { used: 0, reserved: 10 });

    // someone else's token for a.player's code
    const b = await redeemable();
    const wrong = await redeem(staff, b.code, a.jti);
    assertEquals([wrong.status, await errOf(wrong)], [422, "token_invalid"]);
    assertEquals((await codeRow(b.code)).state, "issued");

    // a code that is already redeemed
    const done = await redeem(staff, a.code, await newToken(a.player));
    assertEquals([done.status, await errOf(done)], [422, "not_issued"]);
  },
);

Deno.test(
  "P5.1b: a code whose reservation the offer cannot cover is 422 budget_short and nothing moves (the code stays issued, the budget is unchanged); an unknown code is 404",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const player = await newPlayer();
    const offer = await newOffer(5, 0); // cap 5, nothing reserved: consuming a 10 reservation breaks the cap
    const code = await issuedCode(player, offer, 10);
    const jti = await newToken(player);

    const res = await redeem(staff, code, jti);
    assertEquals([res.status, await errOf(res)], [422, "budget_short"]);
    assertEquals((await codeRow(code)).state, "issued");
    assertEquals(await budgetOf(offer), { used: 0, reserved: 0 });

    const unknown = await redeem(staff, freshUuid(), jti);
    assertEquals([unknown.status, await errOf(unknown)], [404, "not_found"]);
  },
);

Deno.test(
  "P5.1b / A1: redeeming needs a PIN grant (403 without one, nothing written), and a staff member cannot redeem their own account's code (refused, nothing written)",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const r = await redeemable();
    const noGrant = await redeem(staff, r.code, r.jti, false);
    assertEquals(noGrant.status, 403, await noGrant.clone().text());
    assertEquals((await codeRow(r.code)).state, "issued");

    // a code owned by the staff member's own account
    const offer = await newOffer(100, 10);
    const own: Player = { uid: staff.uid, handle: "", device: freshUuid() };
    await ensureServiceRole();
    await adminSql()`insert into app.device (id, user_id, platform) values (${own.device}, ${own.uid}, 'ios')`;
    const ownCode = await issuedCode(own, offer);
    const self = await redeem(staff, ownCode, await newToken(own));
    assertEquals(self.status, 422, await self.clone().text()); // 22023 self_redeem_refused: a 422, not a 403 (the member has the scope and the grant)
    assertEquals((await codeRow(ownCode)).state, "issued");
    assertEquals(await budgetOf(offer), { used: 0, reserved: 10 });
  },
);
