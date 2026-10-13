// supabase/tests/integration/partner-settlement.deno.test.ts
//
// Slice P5.1b / 0060 (docs/security/partner-auth-design.md 4.5, 6.3, 12, 32, 132; AT(17), AT(20)): the REAL `settlement-export` handler over the REAL privileged.ts (`partnerDb.withSettlementExport` = `withPartnerSession`, `hitRateLimit`),
// a REAL operator session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as
// `edge_partner` through SET LOCAL ROLE). The exports bucket is the one thing not real: the harness has no Supabase Storage, so the storage port is a recorder that keeps what the handler uploads.
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port that returns the lines it is told to, and the pgTAP matrix calls the definer directly. Neither runs the Edge's own binding of the month (`${month}::date`,
// typed `YYYY-MM-DD` and truncated by the database), the way the aggregates come back over the wire (bigint counts and a numeric total) into the lines and the CSV, the order of the lines, or the write the A3 export makes inside
// a route that reads: an offline redemption past its confirm-by time is marked ONCE as a fraud signal. This file seeds redeemed offer codes with the OWNER, exports through the handler and reads the table back.
//
// The same shortcut as the other partner integration files: a session's step-up state (aal 2 and a live `mfa_until`, class A3) is written by the OWNER with the guard trigger off for that statement only; TOTP itself is proved elsewhere.

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  createTestUser,
  freshUuid,
  rawOwnerSql,
  withTemporaryOwnerAccess as withOwnerAccess,
} from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import {
  handleSettlementExportRequest,
  SETTLEMENT_SIGNED_URL_SECONDS,
} from "../../functions/_shared/partner/settlement-handler.ts";
import type { ExportsStoragePort } from "../../functions/_shared/partner/ports.ts";
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
const TRAIL = "trl_t"; // seeded by the harness (helpers.sql); fac_x and fac_y are on it
/** A month no other integration file redeems in: every redemption of this file is dated here, so the aggregates are this file's alone. */
const MARCH = "2031-03";
const EMPTY_MONTH = "2031-05-01";

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

/** A member of a fresh org with a real credential and a session from the real mint: an operator of the trail (operator org, trail scope), or a manager of fac_x (facility org). */
async function newMember(kind: "operator" | "manager"): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `stl-${kind}-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, ${kind === "operator" ? "operator" : "facility"}, ${"settlement org " + seq})`,
  );
  if (kind === "operator")
    await rows(
      "app.partner_scope",
      (sql) =>
        sql`insert into app.partner_scope (org_id, trail_id) values (${org}, ${TRAIL})`,
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

/** Step-up state a session cannot be BORN with: the guard trigger is off for this one statement (aal 2 and a live second factor, class A3). `mfaSeconds` may be negative (a lapsed factor). */
async function stepUp(m: Member, aal = 2, mfaSeconds = 240): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = ${aal}, mfa_until = clock_timestamp() + ${mfaSeconds} * interval '1 second' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}

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

async function exportCall(
  m: Member | null,
  body: unknown,
  o: { stepUp?: boolean } = {},
): Promise<Response> {
  if (m !== null && o.stepUp !== false) await stepUp(m);
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
  });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  return await handleSettlementExportRequest(
    new Request(
      "https://project.example.test/functions/v1/settlement-export/export",
      { method: "POST", headers, body: JSON.stringify(body) },
    ),
    { db: partnerDb, storage, allowedOrigin: RP.origin },
  );
}
const errOf = async (res: Response) => (await res.json()).error?.code as string;

/** A live offer on the trail at `facility` with a face value (numeric, so a fraction is carried over the wire). */
async function newOffer(facility: string, faceValue: number): Promise<string> {
  const id = freshUuid();
  await rows(
    "app.offer",
    (sql) =>
      sql`insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
          values (${id}, ${TRAIL}, ${facility}, '{}'::jsonb, 'operator', 1000, ${faceValue}, '2031-01-01', '2031-12-31', 'live')`,
  );
  return id;
}
/** One code of `offerId` for a new player (`(user, offer)` is unique): 'redeemed' at `redeemedAt`, offline or not, with a confirm-by `confirmInDays` from now (negative: overdue); or 'issued' (never redeemed). */
async function newCode(
  offerId: string,
  facility: string,
  o: {
    state?: "redeemed" | "issued";
    redeemedAt?: string;
    offline?: boolean;
    confirmInDays?: number | null;
  } = {},
): Promise<{ id: string }> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `stl-plr-${seq}`);
  const id = freshUuid();
  const state = o.state ?? "redeemed";
  const redeemedAt =
    state === "redeemed" ? (o.redeemedAt ?? `${MARCH}-15T12:00:00Z`) : null;
  const confirmBy =
    o.confirmInDays === undefined || o.confirmInDays === null
      ? null
      : o.confirmInDays;
  await rows(
    "app.offer_code",
    (sql) =>
      sql`insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, redeemed_at, redeemed_offline, offline_confirm_by)
          values (${id}, ${offerId}, ${uid}, ${facility}, ${state}, now() - interval '1 day', ${redeemedAt}, ${o.offline ?? false},
                  ${confirmBy === null ? null : sql`now() + ${confirmBy} * interval '1 day'`})`,
  );
  return { id };
}
const unconfirmedSignals = async (codeId: string): Promise<number> =>
  Number(
    (
      await rows(
        "app.fraud_signal",
        (sql) =>
          sql`select count(*)::int as n from app.fraud_signal where kind = 'offer_offline_unconfirmed' and detail ->> 'offer_code_id' = ${codeId}`,
      )
    )[0]!.n,
  );

Deno.test(
  "S6 / AT(17), AT(20): an operator's export aggregates the month's redeemed codes by facility (the counts, the offline and unconfirmed counts, the numeric face-value total), orders the lines, uploads a CSV with the same lines under a 7-day signed URL, and marks an overdue offline redemption as a fraud signal exactly once",
  DT,
  async () => {
    const op = await newMember("operator");
    // fac_x: offer A (10.00): 1 online, 1 offline still within its confirm-by, 1 offline OVERDUE; offer B (7.50): 2 online; plus rows the month must leave out
    const a = await newOffer("fac_x", 10);
    const b = await newOffer("fac_x", 7.5);
    await newCode(a, "fac_x");
    await newCode(a, "fac_x", { offline: true, confirmInDays: 5 });
    const overdue = await newCode(a, "fac_x", {
      offline: true,
      confirmInDays: -2,
    });
    await newCode(b, "fac_x");
    await newCode(b, "fac_x");
    await newCode(a, "fac_x", { redeemedAt: "2031-04-15T12:00:00Z" }); // another month
    await newCode(a, "fac_x", { state: "issued" }); // never redeemed
    // fac_y: offer D (4.25): 1 online
    const d = await newOffer("fac_y", 4.25);
    await newCode(d, "fac_y");

    // a facility that is not in the trail's programme is not exported (the redeemed-code policy is keyed on facility_programme): only fac_x so far, and that first export writes the fraud signal
    const before = await exportCall(op, {
      trailId: TRAIL,
      month: `${MARCH}-15`,
    });
    assertEquals(before.status, 200, await before.clone().text());
    assertEquals(
      ((await before.json()).data.lines as Array<{ facilityId: string }>).map(
        (l) => l.facilityId,
      ),
      ["fac_x"],
      "fac_y is not in the programme",
    );
    assertEquals(
      await unconfirmedSignals(overdue.id),
      1,
      "the first export wrote the fraud signal",
    );

    // put fac_y into the programme for the rest of this cell (and take it out again: the row is shared state)
    await rows(
      "app.facility_programme",
      (sql) =>
        sql`insert into app.facility_programme (trail_id, facility_id, participation) values (${TRAIL}, 'fac_y', 'accepted')`,
    );
    try {
      puts.length = 0;
      const res = await exportCall(op, {
        trailId: TRAIL,
        month: `${MARCH}-15`,
      });
      assertEquals(res.status, 200, await res.clone().text());
      const data = (await res.json()).data as {
        path: string;
        signedUrl: string;
        expiresAt: string;
        lines: Array<Record<string, unknown>>;
      };
      assertEquals(data.lines, [
        {
          facilityId: "fac_x",
          month: `${MARCH}-01`,
          funder: "operator",
          sponsorshipId: null,
          redemptions: 5,
          offlineCount: 2,
          unconfirmedCount: 1,
          faceValueTotal: 45,
        },
        {
          facilityId: "fac_y",
          month: `${MARCH}-01`,
          funder: "operator",
          sponsorshipId: null,
          redemptions: 1,
          offlineCount: 0,
          unconfirmedCount: 0,
          faceValueTotal: 4.25,
        },
      ]);

      // the upload: the path carries the month as typed, the bytes are the CSV of the same lines, the URL is good for 7 days
      assertEquals(puts.length, 1);
      const put = puts[0]!;
      assert(
        new RegExp(
          `^settlement/${TRAIL}/${MARCH}-15/[0-9a-f-]{36}\\.csv$`,
        ).test(put.path),
        put.path,
      );
      assertEquals(
        [put.contentType, put.expiresInSeconds, data.path],
        ["text/csv", SETTLEMENT_SIGNED_URL_SECONDS, put.path],
      );
      assertEquals(SETTLEMENT_SIGNED_URL_SECONDS, 604_800);
      assertEquals(
        put.body,
        "facility_id,month,funder,sponsorship_id,redemptions,offline_count,unconfirmed_count,face_value_total\n" +
          `fac_x,${MARCH}-01,operator,,5,2,1,45\n` +
          `fac_y,${MARCH}-01,operator,,1,0,0,4.25\n`,
      );
      assert(
        data.signedUrl.includes(put.path) &&
          !Number.isNaN(Date.parse(data.expiresAt)),
        "a signed URL and an ISO expiry",
      );

      // the A3 export wrote one fraud signal for the overdue offline redemption, and a second export writes no second one
      assertEquals(await unconfirmedSignals(overdue.id), 1);
      const again = await exportCall(op, {
        trailId: TRAIL,
        month: `${MARCH}-01`,
      });
      assertEquals(again.status, 200, await again.clone().text());
      assertEquals(
        (await again.json()).data.lines,
        data.lines,
        "the same month typed as its first day gives the same lines",
      );
      assertEquals(
        await unconfirmedSignals(overdue.id),
        1,
        "the signal is written once",
      );
    } finally {
      await rows(
        "app.facility_programme",
        (sql) =>
          sql`delete from app.facility_programme where trail_id = ${TRAIL} and facility_id = 'fac_y'`,
      );
    }
  },
);

Deno.test(
  "S6: a month with no redemptions is 404 empty and nothing is uploaded",
  DT,
  async () => {
    const op = await newMember("operator");
    puts.length = 0;
    const res = await exportCall(op, { trailId: TRAIL, month: EMPTY_MONTH });
    assertEquals([res.status, await errOf(res)], [404, "empty"]);
    assertEquals(puts.length, 0);
  },
);

Deno.test(
  "S6 / A3: the export needs an operator of the trail AND aal 2 with a live second factor: a manager, an operator at aal 1, one whose factor has lapsed and an unknown trail are each 403 with nothing uploaded; a malformed body is 400; no bearer is 401",
  DT,
  async () => {
    const op = await newMember("operator");
    const mgr = await newMember("manager");
    const body = { trailId: TRAIL, month: `${MARCH}-01` };
    // the control first: the same operator, with the step-up, gets in
    puts.length = 0;
    assertEquals((await exportCall(op, body)).status, 200);
    assertEquals(puts.length, 1);

    puts.length = 0;
    const asManager = await exportCall(mgr, body);
    assertEquals(
      [asManager.status, await errOf(asManager)],
      [403, "forbidden"],
    );
    await stepUp(op, 1, 240);
    assertEquals(
      (await exportCall(op, body, { stepUp: false })).status,
      403,
      "aal 1",
    );
    await stepUp(op, 2, -5);
    assertEquals(
      (await exportCall(op, body, { stepUp: false })).status,
      403,
      "a lapsed second factor",
    );
    assertEquals(
      (await exportCall(op, { trailId: "trl_none", month: `${MARCH}-01` }))
        .status,
      403,
      "a trail the operator has no scope on",
    );
    assertEquals(puts.length, 0, "nothing was uploaded by a refusal");

    for (const bad of [
      { trailId: TRAIL, month: "2031-3-1" },
      { trailId: TRAIL, month: "March 2031" },
      { trailId: TRAIL },
      { trailId: TRAIL, month: `${MARCH}-01`, extra: 1 },
    ])
      assertEquals(
        (await exportCall(op, bad)).status,
        400,
        JSON.stringify(bad),
      );
    assertEquals((await exportCall(null, body)).status, 401);
  },
);

Deno.test(
  "S6 / design 32: 60 exports an hour per member, then 429 with a Retry-After; the cap is the member's own",
  DT,
  async () => {
    const busy = await newMember("operator");
    const calm = await newMember("operator");
    for (let i = 0; i < 60; i++) {
      const res = await exportCall(busy, {
        trailId: TRAIL,
        month: EMPTY_MONTH,
      });
      if (res.status !== 404)
        assertEquals(
          res.status,
          404,
          `export ${i + 1}: ${await res.clone().text()}`,
        );
      await res.arrayBuffer();
    }
    const over = await exportCall(busy, { trailId: TRAIL, month: EMPTY_MONTH });
    assertEquals([over.status, await errOf(over)], [429, "rate_limited"]);
    assert(
      Number(over.headers.get("retry-after")) >= 1,
      "a Retry-After in seconds",
    );
    assertEquals(
      (await exportCall(calm, { trailId: TRAIL, month: EMPTY_MONTH })).status,
      404,
      "another member is not slowed",
    );
  },
);
