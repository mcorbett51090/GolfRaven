// supabase/tests/integration/partner-settlement-sponsor.deno.test.ts
//
// Slice S6 / 0060 + 0062 + 0109 + 0112 (docs/security/partner-auth-design.md 12, 132, 137, 143; AT(17), AT(20)): the settlement export of a SPONSOR-FUNDED offer, driven end to end through the real routes. The sponsorship is
// made and approved through the REAL `sponsorships-admin` handler, the offer through the REAL `offers-admin` handler and the admin's approve, the redemption through the REAL `partner-offers-redeem` handler (a staff scan
// with a PIN grant), and the export through the REAL `settlement-export` handler, over the REAL privileged.ts, with REAL sessions minted from the software authenticator's REAL assertion, against the REAL database
// tools/db/test.sh builds. The exports bucket is the one thing not real: the harness has no Supabase Storage, so the storage port is a recorder.
//
// WHAT THIS CLOSES. Every earlier settlement cell (partner-settlement.deno.test.ts) saw `sponsorshipId: null` only: the offers were operator-funded, the codes were planted by the owner. So the attribution column
// (AT(20), 0060: "one line per facility, funder and sponsorship"), the grouping by SPONSORSHIP rather than by offer, and the CSV carrying the id were read from the migration, not run (design 137.1 marked its claim about
// attribution `[unverified]` for exactly this reason). This file runs them.
//
// WHAT IS STILL SEEDED, and why. The reservation an activation makes (the offer's reserved budget and the code's `reserved_amount`) and the issued code itself are written by the OWNER as the player-lane activation would
// leave them (the same seeds as offers-redeem.deno.test.ts): activation is a player-lane flow with its own cells. Everything on the partner side is real.
//
// Redemptions are dated NOW, so the export month is the current month and the shared database holds other files' redemptions in it: every assertion is about the lines that name THIS file's sponsorships.
//

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
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
import { handlePartnerSponsorshipsRequest } from "../../functions/_shared/partner/sponsorships-handler.ts";
import { handlePartnerOffersAdminRequest } from "../../functions/_shared/partner/offers-handler.ts";
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
import { handlePartnerOffersRedeemRequest } from "../../functions/_shared/partner/offers-redeem-handler.ts";
import { handleSettlementExportRequest } from "../../functions/_shared/partner/settlement-handler.ts";
import type { ExportsStoragePort } from "../../functions/_shared/partner/ports.ts";

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

async function sessionCall(path: string, body: unknown): Promise<Response> {
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
  });
  return await handlePartnerSessionRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-session/${path}`,
      { method: "POST", headers, body: JSON.stringify(body) },
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
  const o = await sessionCall("options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  const res = await sessionCall("verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, token, hash: await sha256Hex(token) };
}

/** A member of a fresh org with a real credential and a session from the real mint: an operator of `trailId` (operator org, trail scope), or a staff member of fac_x (facility org). */
async function newMember(
  kind: "operator" | "staff",
  trailId?: string,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `sse-${kind}-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, ${kind === "operator" ? "operator" : "facility"}, ${"settlement sponsor org " + seq})`,
  );
  if (kind === "operator")
    await rows(
      "app.partner_scope",
      (sql) =>
        sql`insert into app.partner_scope (org_id, trail_id) values (${org}, ${trailId!})`,
    );
  else
    await rows(
      "app.partner_scope",
      (sql) =>
        sql`insert into app.partner_scope (org_id, facility_id) values (${org}, 'fac_x')`,
    );
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${kind}, now() - interval '60 days')`,
  );
  return await signInAs(uid);
}

/** Step-up state a session cannot be BORN with: the guard trigger is off for this one statement (aal 2 and a live second factor, class A3). */
async function stepUp(m: Member, aal = 2): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = ${aal}, mfa_until = clock_timestamp() + interval '240 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}

async function callWith(
  handler: (
    req: Request,
    deps: { db: typeof partnerDb; allowedOrigin: string },
  ) => Promise<Response>,
  fn: string,
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  withStepUp = true,
): Promise<Response> {
  if (m !== null && withStepUp) await stepUp(m);
  const headers = new Headers({ origin: RP.origin });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handler(
    new Request(`https://project.example.test/functions/v1/${fn}/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
const spCall = (
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) =>
  callWith(
    handlePartnerSponsorshipsRequest,
    "sponsorships-admin",
    m,
    method,
    path,
    body,
  );
const offCall = (
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) =>
  callWith(
    handlePartnerOffersAdminRequest,
    "offers-admin",
    m,
    method,
    path,
    body,
  );
const errOf = async (res: Response) => (await res.json()).error?.code as string;
const dataOf = async (res: Response) =>
  (await res.json()).data as Record<string, unknown>;

/** The admin the harness already seeds (helpers.sql puts this uid in app.admin_user), signed in once with a real credential; its step-up state is re-seeded on every call. */
const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0";
let adminSession: Member | null = null;
async function newAdmin(): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID);
  await stepUp(adminSession);
  return adminSession;
}

/** A sponsor organisation (kind sponsor): the only kind a sponsorship may name. */
async function newSponsorOrg(): Promise<string> {
  seq += 1;
  const id = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${id}, 'sponsor', ${"sponsorship rules org " + seq})`,
  );
  return id;
}
/** A sponsorship of `trail` with `scope`, made through its own route by `op` (an operator of that trail); live (approved through its own route) unless `approve` is false, in which case it stays a draft. */
async function sponsorship(
  op: Member,
  trail: string,
  scope = "offers",
  approve = true,
): Promise<string> {
  const org = await newSponsorOrg();
  const made = await spCall(
    op,
    "POST",
    "sponsorships",
    sponsorshipBody(trail, org, scope),
  );
  assertEquals(made.status, 200, await made.clone().text());
  const id = (await dataOf(made)).id as string;
  if (approve) {
    const ok = await spCall(op, "POST", "sponsorships/approve", { id });
    assertEquals(ok.status, 200, await ok.clone().text());
  }
  return id;
}
const sponsorshipBody = (
  trail: string,
  org: string,
  scope: string,
  id?: string,
) => ({
  ...(id === undefined ? {} : { id }),
  trailId: trail,
  sponsorOrgId: org,
  category: "equipment",
  scope,
  attributionName: "Rules Golf",
  attributionAsset: null,
  placementFee: null,
  startsOn: "2031-01-01",
  endsOn: "2031-12-31",
});
const ELIGIBLE = {
  kind: "compare",
  op: ">=",
  left: {
    kind: "agg",
    name: "played",
    courseId: "crs_01H0ABCDEFGHJKMNPQRSTVWXYZ",
  },
  right: { kind: "literal", value: 1 },
};
const offerBody = (trailId: string, over: Record<string, unknown> = {}) => ({
  trailId,
  facilityId: "fac_x",
  eligibility: ELIGIBLE,
  funder: "operator",
  budgetCap: 250.5,
  maxRedemptions: 40,
  faceValue: 12.25,
  validFrom: "2031-03-01",
  validTo: "2031-09-30",
  ...over,
});
interface OfferRow {
  status: string;
  funder: string;
  trail_id: string;
  sponsorship_id: string | null;
}
/** The row as the table holds it, read as service_role (not through the code under test). */
async function offerRow(id: string): Promise<OfferRow | undefined> {
  await ensureServiceRole();
  return (
    await adminSql()`select status::text as status, funder::text as funder, trail_id, sponsorship_id::text as sponsorship_id from app.offer where id = ${id}`
  )[0] as OfferRow | undefined;
}

const TRAIL = "trl_t"; // seeded by the harness (helpers.sql); fac_x is on it, accepted, with a timezone
const FAC = "fac_x";
const isoDay = (offsetDays: number): string =>
  new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);

// ---------------------------------------------------------------------------------------------------------------------------------------------
// the redemption (the same seeds and calls as offers-redeem.deno.test.ts)
// ---------------------------------------------------------------------------------------------------------------------------------------------

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
async function redeemCall(m: Member, body: unknown): Promise<Response> {
  await grant(m);
  const headers = new Headers({
    origin: RP.origin,
    authorization: `Bearer ${m.token}`,
    "content-type": "application/json",
  });
  return await handlePartnerOffersRedeemRequest(
    new Request(
      "https://project.example.test/functions/v1/partner-offers-redeem/redeem",
      { method: "POST", headers, body: JSON.stringify(body) },
    ),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}

interface Player {
  readonly uid: string;
  readonly device: string;
}
async function newPlayer(): Promise<Player> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `sse-plr-${seq}`);
  const device = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.device (id, user_id, platform) values (${device}, ${uid}, 'ios')`;
  return { uid, device };
}
/** The player's check-in token at FAC (what the player shows the staff member); its jti is the redeem credential. */
async function newToken(p: Player): Promise<string> {
  const challenge = freshUuid();
  const jti = freshUuid();
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) values (${challenge}, ${p.uid}, ${p.device}, ${FAC}, ${"n-" + challenge}, now() + interval '10 minutes', 'live')`;
  await sql`insert into app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) values (${jti}, ${challenge}, ${p.uid}, ${p.device}, ${FAC}, 'attested', 'live', now(), now() + interval '10 minutes')`;
  return jti;
}
/** What the activation leaves behind for an offer the route made live: the offer carries the reservation, and an issued code for a new player carries `reserved_amount`. Returns the code and the player's token. */
async function activatedFor(offerId: string, faceValue: number) {
  await rows(
    "app.offer",
    (sql) =>
      sql`update app.offer set budget_reserved = budget_reserved + ${faceValue} where id = ${offerId}`,
  );
  const player = await newPlayer();
  const id = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, activated_device_id, devicecheck_token_hash, activated_at, reserved_amount)
    values (${id}, ${offerId}, ${player.uid}, ${FAC}, 'issued', now() - interval '1 day', now() + interval '20 days', ${player.device}, ${"tok-" + id}, now() - interval '1 hour', ${faceValue})`;
  return { code: id, jti: await newToken(player) };
}
interface CodeRow {
  state: string;
  redeemed_by_staff: string | null;
  redeemed_at: Date | null;
}
const codeRow = async (id: string): Promise<CodeRow> => {
  await ensureServiceRole();
  return (
    await adminSql()`select state::text as state, redeemed_by_staff::text as redeemed_by_staff, redeemed_at from app.offer_code where id = ${id}`
  )[0] as unknown as CodeRow;
};
const budgetOf = async (offerId: string) => {
  await ensureServiceRole();
  const r = (
    await adminSql()`select budget_used::text as used, budget_reserved::text as reserved from app.offer where id = ${offerId}`
  )[0]!;
  return { used: Number(r.used), reserved: Number(r.reserved) };
};

/** A sponsor-funded offer at FAC made the way an operator makes one and an admin approves it, through the real routes; returns its id. */
async function liveSponsorOffer(
  op: Member,
  admin: Member,
  sponsorshipId: string,
  faceValue: number,
): Promise<string> {
  const made = await offCall(
    op,
    "POST",
    "offers",
    offerBody(TRAIL, {
      funder: "sponsor",
      sponsorshipId,
      facilityId: FAC,
      faceValue,
      budgetCap: 100,
      validFrom: isoDay(-1),
      validTo: isoDay(30),
    }),
  );
  assertEquals(made.status, 200, await made.clone().text());
  const id = (await dataOf(made)).id as string;
  const ok = await offCall(admin, "POST", "offers/approve", { id });
  assertEquals(ok.status, 200, await ok.clone().text());
  assertEquals((await offerRow(id))!.status, "live");
  return id;
}
/** A staff scan of a fresh activated code of `offerId`, through the real redeem handler; returns the code id. */
async function redeemOnce(
  staff: Member,
  offerId: string,
  faceValue: number,
): Promise<string> {
  const { code, jti } = await activatedFor(offerId, faceValue);
  const res = await redeemCall(staff, {
    facilityId: FAC,
    offerCodeId: code,
    method: "staff_scan",
    credential: jti,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const row = await codeRow(code);
  assertEquals(row.state, "redeemed");
  assertEquals(row.redeemed_by_staff, staff.uid);
  return code;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// the export (the same recorder as partner-settlement.deno.test.ts)
// ---------------------------------------------------------------------------------------------------------------------------------------------

interface Put {
  path: string;
  body: string;
  contentType: string;
  expiresInSeconds: number;
}
/** The exports bucket, recorded: nothing here is Supabase Storage. */
const puts: Put[] = [];
const storage: ExportsStoragePort = {
  putSigned(path, body, contentType, expiresInSeconds) {
    puts.push({
      path,
      body: new TextDecoder().decode(body),
      contentType,
      expiresInSeconds,
    });
    return Promise.resolve({
      path,
      signedUrl: `https://storage.example.test/${path}?token=t`,
      expiresAt: new Date(Date.now() + expiresInSeconds * 1000).toISOString(),
    });
  },
  purgeOlderThan: () => Promise.resolve(0),
};
async function exportCall(m: Member, body: unknown): Promise<Response> {
  await stepUp(m);
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
    authorization: `Bearer ${m.token}`,
  });
  return await handleSettlementExportRequest(
    new Request(
      "https://project.example.test/functions/v1/settlement-export/export",
      { method: "POST", headers, body: JSON.stringify(body) },
    ),
    { db: partnerDb, storage, allowedOrigin: RP.origin },
  );
}
interface Line {
  facilityId: string;
  month: string;
  funder: string;
  sponsorshipId: string | null;
  redemptions: number;
  offlineCount: number;
  unconfirmedCount: number;
  faceValueTotal: number;
}
/** The first day of the month the database dated a redemption in (read back as the owner, in the database's own terms). */
async function monthOf(codeId: string): Promise<string> {
  await ensureServiceRole();
  return (
    await adminSql()`select to_char(date_trunc('month', redeemed_at), 'YYYY-MM-DD') as m from app.offer_code where id = ${codeId}`
  )[0]!.m as string;
}

Deno.test(
  "0060 / AT(20): a SPONSOR-FUNDED offer's redemptions are exported on a line that NAMES the sponsorship: two offers of one sponsorship are ONE line (grouped by sponsorship, not by offer, the numeric total summed), a second sponsorship is its own line, no sponsor line is attributed to anyone else, and the CSV carries the same ids",
  DT,
  async () => {
    const op = await newMember("operator", TRAIL);
    const staff = await newMember("staff");
    const admin = await newAdmin();
    const s1 = await sponsorship(op, TRAIL, "offers");
    const s2 = await sponsorship(op, TRAIL, "both");

    // s1 funds two offers (12.25 and 7.5), s2 one (5); each is redeemed once through the real staff scan
    const o1 = await liveSponsorOffer(op, admin, s1, 12.25);
    const o2 = await liveSponsorOffer(op, admin, s1, 7.5);
    const o3 = await liveSponsorOffer(op, admin, s2, 5);
    const c1 = await redeemOnce(staff, o1, 12.25);
    await redeemOnce(staff, o2, 7.5);
    await redeemOnce(staff, o3, 5);
    // the redemption moved the budget from reserved to used (the redeem path is the real one)
    assertEquals(await budgetOf(o1), { used: 12.25, reserved: 0 });

    const month = await monthOf(c1);
    puts.length = 0;
    const res = await exportCall(op, { trailId: TRAIL, month });
    assertEquals(res.status, 200, await res.clone().text());
    const data = (await res.json()).data as { lines: Line[] };

    const line1 = data.lines.filter((l) => l.sponsorshipId === s1);
    const line2 = data.lines.filter((l) => l.sponsorshipId === s2);
    assertEquals(line1, [
      {
        facilityId: FAC,
        month,
        funder: "sponsor",
        sponsorshipId: s1,
        redemptions: 2,
        offlineCount: 0,
        unconfirmedCount: 0,
        faceValueTotal: 19.75,
      },
    ]);
    assertEquals(line2, [
      {
        facilityId: FAC,
        month,
        funder: "sponsor",
        sponsorshipId: s2,
        redemptions: 1,
        offlineCount: 0,
        unconfirmedCount: 0,
        faceValueTotal: 5,
      },
    ]);
    // the funder and the sponsorship id go together on every line: a sponsor line always names one, and a line that names one is a sponsor line
    for (const l of data.lines)
      assertEquals(
        l.funder === "sponsor",
        l.sponsorshipId !== null,
        `line ${JSON.stringify(l)}`,
      );

    // the CSV is the same lines, with the sponsorship id in its column
    assertEquals(puts.length, 1);
    const csv = puts[0]!.body.split("\n");
    assertEquals(
      csv[0],
      "facility_id,month,funder,sponsorship_id,redemptions,offline_count,unconfirmed_count,face_value_total",
    );
    assert(
      csv.includes(`${FAC},${month},sponsor,${s1},2,0,0,19.75`),
      csv.join("\n"),
    );
    assert(
      csv.includes(`${FAC},${month},sponsor,${s2},1,0,0,5`),
      csv.join("\n"),
    );
    assertEquals(
      csv.length,
      data.lines.length + 2,
      "a header, one row per line, a trailing newline",
    );
  },
);
