// supabase/tests/integration/partner-stock.deno.test.ts
//
// Slice S5 / 0058 (docs/security/partner-auth-design.md 4.5, 6.3, 12, 28, 131): the REAL `stock-admin` handler over the REAL privileged.ts (`partnerDb.withStock` = `withPartnerSession`, `hitRateLimit`), a REAL staff session minted by the
// REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port, and the pgTAP file (36_partner_stock_handover.sql) calls the definer directly. Neither runs the Edge's own binding of a movement (`${qty}::int`,
// `${kind}::text`, `${note}::text`), the closed list of statuses `privileged.ts` validates before the handler maps them, the sign of a movement (a `damaged` or `transfer_out` of 7 is a movement of -7; only a count_adjustment may be
// negative), the availability projection a movement refreshes (`out` at 0, `low` at or under the threshold, `in_stock` above it), or the PIN grant being CONSUMED by the movement: one PIN per action. This file drives every kind
// of movement through the handler and reads the stock row, the movement row and the availability row back as the owner.
//
// The same shortcut as the other partner integration files: a PIN grant (one per action, 50 s) is written by the OWNER with the session-guard trigger off for that one statement; the PIN itself is proved elsewhere.

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
import { handlePartnerStockRequest } from "../../functions/_shared/partner/stock-handler.ts";
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
const FAC = "fac_x"; // seeded by the harness (helpers.sql), on trail trl_t
const OTHER_FAC = "fac_y";
const TRAIL = "trl_t";

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

/** A staff member of a fresh org scoped to `facilityId` (created 60 days ago: no cold-start cap), with a real credential and a session from the real mint. */
async function newStaff(
  facilityId: string,
  role: "staff" | "manager" = "staff",
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `stk-${role}-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"stock org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${facilityId})`,
  );
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${role}, now() - interval '60 days')`,
  );
  return await signInAs(uid);
}

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
const grantOf = async (m: Member): Promise<Date | null> =>
  (
    await rows(
      "app.partner_session",
      (sql) =>
        sql`select pin_grant_until from app.partner_session where token_hash = ${m.hash}`,
    )
  )[0]!.pin_grant_until as Date | null;

async function stockCall(
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  withGrant = method === "POST",
): Promise<Response> {
  if (m !== null && withGrant) await grant(m);
  const headers = new Headers({ origin: RP.origin });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handlePartnerStockRequest(
    new Request(
      `https://project.example.test/functions/v1/stock-admin/${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    ),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
const move = (
  m: Member,
  kind: string,
  qty: number,
  extra: Record<string, unknown> = {},
  withGrant = true,
) =>
  stockCall(
    m,
    "POST",
    "stock/move",
    { facilityId: FAC, trailId: TRAIL, kind, qty, ...extra },
    withGrant,
  );
const errOf = async (res: Response) => (await res.json()).error?.code as string;

/** The one stock row (trl_t, fac_x) every cell shares, set exactly (every integration file shares the database), with its availability row removed so the projection starts from nothing. */
async function setStock(onHand: number, lowThreshold = 3): Promise<void> {
  await rows(
    "app.special_marker_stock",
    (sql) =>
      sql`insert into app.special_marker_stock (trail_id, facility_id, on_hand, low_threshold, last_counted_at) values (${TRAIL}, ${FAC}, ${onHand}, ${lowThreshold}, null) on conflict (trail_id, facility_id) do update set on_hand = excluded.on_hand, low_threshold = excluded.low_threshold, last_counted_at = null`,
  );
  await rows(
    "app.special_marker_availability",
    (sql) =>
      sql`delete from app.special_marker_availability where trail_id = ${TRAIL} and facility_id = ${FAC}`,
  );
}
const stockRow = async () =>
  (
    await rows(
      "app.special_marker_stock",
      (sql) =>
        sql`select on_hand::int as on_hand, last_counted_at from app.special_marker_stock where trail_id = ${TRAIL} and facility_id = ${FAC}`,
    )
  )[0] as unknown as { on_hand: number; last_counted_at: Date | null };
const availability = async (): Promise<string | null> => {
  const r = await rows(
    "app.special_marker_availability",
    (sql) =>
      sql`select status::text as status from app.special_marker_availability where trail_id = ${TRAIL} and facility_id = ${FAC}`,
  );
  return r.length === 0 ? null : String(r[0]!.status);
};
const movementsBy = async (uid: string) =>
  (
    await rows(
      "app.special_marker_stock_movement",
      (sql) =>
        sql`select kind::text as kind, qty::int as qty, entitlement_id, note from app.special_marker_stock_movement where by_member = ${uid} and trail_id = ${TRAIL} and facility_id = ${FAC} order by at, id`,
    )
  ).map((r) => ({
    kind: String(r.kind),
    qty: Number(r.qty),
    entitlement: r.entitlement_id,
    note: r.note === null ? null : String(r.note),
  }));

Deno.test(
  "S5: a facility's staff reads the stock rows with the on-hand, the threshold, the projected availability and the last count; staff of another facility, a missing facility and no bearer are refused",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const other = await newStaff(OTHER_FAC);
    await setStock(7, 3);

    const res = await stockCall(staff, "GET", `stock?facilityId=${FAC}`);
    assertEquals(res.status, 200, await res.clone().text());
    const stock = (await res.json()).data.stock as Array<
      Record<string, unknown>
    >;
    const mine = stock.find((r) => r.trailId === TRAIL)!;
    assert(mine, "the facility's stock row is listed");
    assertEquals(
      [mine.onHand, mine.lowThreshold, mine.status, mine.lastCountedAt],
      [7, 3, null, null],
      "no movement yet: no projected availability, never counted",
    );

    // after a movement the projection and the count time are filled in
    const ok = await move(staff, "count_adjustment", 1);
    assertEquals(ok.status, 200, await ok.clone().text());
    const after = (
      (await (await stockCall(staff, "GET", `stock?facilityId=${FAC}`)).json())
        .data.stock as Array<Record<string, unknown>>
    ).find((r) => r.trailId === TRAIL)!;
    assertEquals([after.onHand, after.status], [8, "in_stock"]);
    assert(
      typeof after.lastCountedAt === "string" &&
        !Number.isNaN(Date.parse(after.lastCountedAt)),
      "an ISO last-counted time",
    );

    // a manager of the facility may read and move stock too (the definer's roles are staff and manager)
    const mgr = await newStaff(FAC, "manager");
    const mgrRead = await stockCall(mgr, "GET", `stock?facilityId=${FAC}`);
    assertEquals(mgrRead.status, 200, await mgrRead.clone().text());
    const mgrMove = await move(mgr, "delivered", 1);
    assertEquals(mgrMove.status, 200, await mgrMove.clone().text());
    assertEquals((await stockRow()).on_hand, 9);

    const theirs = await stockCall(other, "GET", `stock?facilityId=${FAC}`);
    assertEquals([theirs.status, await errOf(theirs)], [403, "forbidden"]);
    assertEquals(
      (await stockCall(staff, "GET", "stock")).status,
      400,
      "a facility is required",
    );
    assertEquals(
      (await stockCall(staff, "GET", `stock?facilityId=${FAC}&x=1`)).status,
      400,
    );
    assertEquals(
      (await stockCall(null, "GET", `stock?facilityId=${FAC}`)).status,
      401,
    );
  },
);

Deno.test(
  "S5: every kind of movement through the handler: the sign (damaged and transfer_out take away, a count_adjustment may be negative), the stock row, one movement row per call with the signed quantity and the note, and the availability projection (in_stock above the threshold, low at or under it, out at zero)",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    await setStock(10, 3);
    const steps: Array<[string, number, number, string, string | null]> = [
      // kind, qty, expected on-hand, expected availability, note
      ["delivered", 5, 15, "in_stock", "pallet 4"],
      ["transfer_in", 1, 16, "in_stock", null],
      ["transfer_out", 6, 10, "in_stock", null],
      ["damaged", 7, 3, "low", "water damage"],
      ["count_adjustment", 4, 7, "in_stock", null],
      ["count_adjustment", -4, 3, "low", "recount"],
      ["damaged", 3, 0, "out", null],
    ];
    const expectMovements: Array<{
      kind: string;
      qty: number;
      entitlement: unknown;
      note: string | null;
    }> = [];
    for (const [kind, qty, onHand, avail, note] of steps) {
      const res = await move(staff, kind, qty, note === null ? {} : { note });
      assertEquals(
        res.status,
        200,
        `${kind} ${qty}: ${await res.clone().text()}`,
      );
      assertEquals(
        (await res.json()).data,
        { onHand, availability: avail },
        `${kind} ${qty}`,
      );
      assertEquals(
        [(await stockRow()).on_hand, await availability()],
        [onHand, avail],
        `${kind} ${qty}: the stock row and the availability row`,
      );
      expectMovements.push({
        kind,
        qty: kind === "damaged" || kind === "transfer_out" ? -qty : qty,
        entitlement: null,
        note,
      });
    }
    assertEquals(
      await movementsBy(staff.uid),
      expectMovements,
      "one movement per call, signed, with its note, none tied to an entitlement",
    );
    const counted = await stockRow();
    assert(
      counted.last_counted_at instanceof Date,
      "a count_adjustment stamps the last-counted time",
    );
  },
);

Deno.test(
  "S5: a movement that would go below zero is 422 short, one over the cap is 422 over_cap, a trail with no stock row is 422 no_stock_row: in each the stock is unchanged and no movement is written; only a count_adjustment may be negative",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    await setStock(5, 3);
    const short = await move(staff, "transfer_out", 6);
    assertEquals([short.status, await errOf(short)], [422, "short"]);
    const shortC = await move(staff, "count_adjustment", -6);
    assertEquals([shortC.status, await errOf(shortC)], [422, "short"]);
    assertEquals(
      [(await stockRow()).on_hand, await availability()],
      [5, null],
      "short: nothing changed, nothing projected",
    );

    await setStock(999_999, 3);
    const over = await move(staff, "delivered", 2);
    assertEquals([over.status, await errOf(over)], [422, "over_cap"]);
    assertEquals((await stockRow()).on_hand, 999_999);
    const exact = await move(staff, "delivered", 1);
    assertEquals(exact.status, 200, "exactly the cap is allowed");
    assertEquals((await stockRow()).on_hand, 1_000_000);

    const none = await stockCall(staff, "POST", "stock/move", {
      facilityId: FAC,
      trailId: "trl_none",
      kind: "delivered",
      qty: 1,
    });
    assertEquals([none.status, await errOf(none)], [422, "no_stock_row"]);
    assertEquals(
      await movementsBy(staff.uid),
      [{ kind: "delivered", qty: 1, entitlement: null, note: null }],
      "only the one successful movement was written",
    );
  },
);

Deno.test(
  "S5 / A1: a movement needs a PIN grant and CONSUMES it (one PIN per action: the next movement needs its own); without one it is 403 and nothing changes; staff of another facility with a grant are 403; a malformed body is 400",
  DT,
  async () => {
    const staff = await newStaff(FAC);
    const other = await newStaff(OTHER_FAC);
    await setStock(10, 3);

    const noGrant = await move(staff, "delivered", 1, {}, false);
    assertEquals(noGrant.status, 403, await noGrant.clone().text());
    assertEquals((await stockRow()).on_hand, 10);

    await grant(staff);
    assert((await grantOf(staff)) !== null, "the grant is on the session");
    const ok = await move(staff, "delivered", 1, {}, false);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await grantOf(staff), null, "the movement consumed the grant");
    const again = await move(staff, "delivered", 1, {}, false);
    assertEquals(again.status, 403, "the next movement needs its own PIN");
    assertEquals(
      (await stockRow()).on_hand,
      11,
      "only the first of the two moved the stock",
    );

    const foreign = await move(other, "delivered", 5);
    assertEquals([foreign.status, await errOf(foreign)], [403, "forbidden"]);
    assertEquals(
      (await stockRow()).on_hand,
      11,
      "another facility's staff moved nothing",
    );

    for (const body of [
      { facilityId: FAC, trailId: TRAIL, kind: "delivered", qty: 0 },
      { facilityId: FAC, trailId: TRAIL, kind: "delivered", qty: -1 },
      { facilityId: FAC, trailId: TRAIL, kind: "redeemed", qty: 1 },
      { facilityId: FAC, trailId: TRAIL, kind: "delivered", qty: 1.5 },
      { facilityId: FAC, trailId: TRAIL, kind: "delivered", qty: 100_001 },
      {
        facilityId: FAC,
        trailId: TRAIL,
        kind: "delivered",
        qty: 1,
        note: "x".repeat(201),
      },
      {
        facilityId: FAC,
        trailId: TRAIL,
        kind: "delivered",
        qty: 1,
        extra: true,
      },
    ]) {
      const res = await stockCall(staff, "POST", "stock/move", body);
      assertEquals(res.status, 400, JSON.stringify(body).slice(0, 80));
    }
    assertEquals(
      (await stockRow()).on_hand,
      11,
      "a malformed body moved nothing",
    );
  },
);

Deno.test(
  "S5 / design 28: 240 reads an hour per member, then 429 with a Retry-After; the cap is the member's own",
  DT,
  async () => {
    const busy = await newStaff(FAC);
    const calm = await newStaff(FAC);
    await setStock(5, 3);
    for (let i = 0; i < 240; i++) {
      const res = await stockCall(busy, "GET", `stock?facilityId=${FAC}`);
      if (res.status !== 200)
        assertEquals(
          res.status,
          200,
          `read ${i + 1}: ${await res.clone().text()}`,
        );
      await res.arrayBuffer();
    }
    const over = await stockCall(busy, "GET", `stock?facilityId=${FAC}`);
    assertEquals([over.status, await errOf(over)], [429, "rate_limited"]);
    assert(
      Number(over.headers.get("retry-after")) >= 1,
      "a Retry-After in seconds",
    );
    const movedOver = await move(busy, "delivered", 1);
    assertEquals(
      movedOver.status,
      429,
      "a movement counts against the same bucket",
    );
    assertEquals((await stockRow()).on_hand, 5);
    assertEquals(
      (await stockCall(calm, "GET", `stock?facilityId=${FAC}`)).status,
      200,
      "another member is not slowed",
    );
  },
);
