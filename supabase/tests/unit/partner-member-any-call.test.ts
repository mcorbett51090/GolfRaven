// supabase/tests/unit/partner-member-any-call.test.ts
//
// P5 §70: focused cells for `alertMemberAnyCall` (handler-kit) and one authenticated
// session-handler path. Soft-cap trips must never become 429; writer faults are swallowed.

import { describe, expect, it } from "vitest";
import {
  alertMemberAnyCall,
  MEMBER_ANY_CALL_BUCKET,
  MEMBER_ANY_CALL_PER_HOUR,
  type MemberAnyCallDb,
} from "../../functions/_shared/partner/handler-kit.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { authed, makeFakes, req, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const HASH = "a".repeat(64);

describe("alertMemberAnyCall (§70)", () => {
  it("under the soft-cap hits partner-any-call and does not raise", async () => {
    const hits: Array<{ bucket: string; max: number }> = [];
    let raised = 0;
    const db: MemberAnyCallDb = {
      async hitRateLimit(_h, bucket, _w, max) {
        hits.push({ bucket, max });
        return { ok: true, retryAfterSeconds: 0 };
      },
      async withSession(_h, op) {
        await op({
          async raiseMemberRateAlarm() {
            raised += 1;
          },
        });
      },
    };
    await alertMemberAnyCall(db, HASH);
    expect(hits).toEqual([{ bucket: MEMBER_ANY_CALL_BUCKET, max: MEMBER_ANY_CALL_PER_HOUR }]);
    expect(raised).toBe(0);
  });

  it("when soft-cap trips, raises via withSession and never throws", async () => {
    const details: unknown[] = [];
    const db: MemberAnyCallDb = {
      async hitRateLimit() {
        return { ok: false, retryAfterSeconds: 3600 };
      },
      async withSession(_h, op) {
        await op({
          async raiseMemberRateAlarm(detail) {
            details.push(detail);
          },
        });
      },
    };
    await expect(alertMemberAnyCall(db, HASH)).resolves.toBeUndefined();
    expect(details).toEqual([{ stage: "partner-any-call" }]);
  });

  it("swallows writer errors (alert-only)", async () => {
    const db: MemberAnyCallDb = {
      async hitRateLimit() {
        return { ok: false, retryAfterSeconds: 3600 };
      },
      async withSession() {
        throw new Error("writer fault: secret database text");
      },
    };
    await expect(alertMemberAnyCall(db, HASH)).resolves.toBeUndefined();
  });

  it("CourseQrDb path uses withCourseQr when withSession is absent", async () => {
    let raised = 0;
    const db: MemberAnyCallDb = {
      async hitRateLimit() {
        return { ok: false, retryAfterSeconds: 3600 };
      },
      async withCourseQr(_h, op) {
        await op({
          async raiseMemberRateAlarm() {
            raised += 1;
          },
        });
      },
    };
    await alertMemberAnyCall(db, HASH);
    expect(raised).toBe(1);
  });
});

describe("session-handler §70 soft-cap", () => {
  it("GET session records partner-any-call and still succeeds under the soft-cap", async () => {
    const f = makeFakes();
    const res = await handlePartnerSessionRequest(req("GET", "session", { headers: authed() }), f.deps);
    expect(res.status).toBe(200);
    expect(f.rateLimitHits).toContainEqual({
      hash: await sha256Hex(SESSION_TOKEN),
      bucket: MEMBER_ANY_CALL_BUCKET,
      windowSeconds: 3600,
      max: MEMBER_ANY_CALL_PER_HOUR,
    });
    expect(f.calls).not.toContain("session.raiseMemberRateAlarm");
  });

  it("tripped soft-cap still returns 200 (never 429) and raises rate_member", async () => {
    const f = makeFakes({ memberAnyCallLimitOk: false });
    const res = await handlePartnerSessionRequest(req("GET", "session", { headers: authed() }), f.deps);
    expect(res.status).toBe(200);
    expect(res.headers.get("retry-after")).toBeNull();
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.raiseMemberRateAlarm", "db.withSession", "session.whoami"]);
  });
});
