import { describe, expect, it } from "vitest";
import {
  InvalidTransition,
  OUTBOX_POLICY,
  applyAnswer,
  beginSend,
  classifyAnswer,
  completeRematch,
  createItem,
  isDue,
  isExpiredDeadLetter,
  isStaleSent,
  markReported,
  playedStatus,
  recoverInterrupted,
  resolveQueued,
  resolveUnlisted,
  retryDelayMs,
  type NewOutboxItem,
  type OutboxItem,
  type ServerAnswer,
} from "../src/outbox";

const T0 = 1_800_000_000_000;
const draft = (over: Partial<NewOutboxItem> = {}): NewOutboxItem => ({
  id: "o1",
  sourceRef: "health:abc",
  ownerUserId: "user-a",
  courseId: "crs_01M39GMFJZ2P89V3ZZXPPH671T",
  catalogVersion: "20260101-aaaaaaa",
  payload: { insideRatio: 0.97 },
  ...over,
});
const fresh = (over: Partial<NewOutboxItem> = {}): OutboxItem => createItem(draft(over), T0);
const sent = (item = fresh(), now = T0): OutboxItem => beginSend(item, now);
const resp = (status: number, code?: string, retryAfterSeconds?: number): ServerAnswer => ({ kind: "response", status, code, retryAfterSeconds });
const fixedRng = (v: number) => () => v;

describe("§7.6 answer table", () => {
  it.each([
    [resp(201), "accepted"],
    [resp(409, "duplicate"), "accepted"],
    [resp(202, "queued_catalog"), "queued"],
    [resp(429), "retry"],
    [resp(500), "retry"],
    [resp(502), "retry"],
    [resp(503, undefined, 120), "retry"],
    [{ kind: "network_error" } as ServerAnswer, "retry"],
    [resp(400), "needs_attention"],
    [resp(401), "needs_attention"],
    [resp(403), "needs_attention"],
    [resp(404), "needs_attention"],
    [resp(422, "unknown_id"), "needs_attention"],
    [resp(422, "catalog_forged"), "needs_attention"],
    [resp(409), "needs_attention"],
    [resp(409, "something_else"), "needs_attention"],
  ] as const)("%j => %s", (answer, want) => {
    const out = applyAnswer(sent(), answer, T0 + 1, fixedRng(0.5));
    expect(out.status).toBe(want);
  });

  it("422 catalog_stale => pending, flagged for re-match, due immediately", () => {
    const out = applyAnswer(sent(), resp(422, "catalog_stale"), T0 + 1, fixedRng(0.5));
    expect(out).toMatchObject({ status: "pending", rematch: true, nextAttemptAt: null });
  });

  it("a status the contract does not define is surfaced, never treated as success", () => {
    expect(classifyAnswer(resp(200))).toEqual({ to: "needs_attention", reason: "unexpected_status" });
    expect(classifyAnswer(resp(202))).toEqual({ to: "needs_attention", reason: "unexpected_status" });
    expect(classifyAnswer(resp(302))).toEqual({ to: "needs_attention", reason: "unexpected_status" });
    expect(classifyAnswer(resp(100))).toEqual({ to: "needs_attention", reason: "unexpected_status" });
  });

  it("keeps the server's own code and status on the item", () => {
    const out = applyAnswer(sent(), resp(422, "unknown_id"), T0 + 1, fixedRng(0));
    expect(out).toMatchObject({ lastHttpStatus: 422, lastServerCode: "unknown_id", reason: "rejected", deadLetteredAt: T0 + 1 });
  });
});

describe("retry backoff", () => {
  it("grows exponentially, with jitter in [d/2, d], and is capped", () => {
    const lo = (n: number) => retryDelayMs(n, fixedRng(0));
    const hi = (n: number) => retryDelayMs(n, fixedRng(0.999999));
    expect(lo(1)).toBe(7_500);
    expect(hi(1)).toBeLessThanOrEqual(15_000);
    expect(lo(2)).toBe(15_000);
    expect(lo(3)).toBe(30_000);
    expect(hi(30)).toBeLessThanOrEqual(OUTBOX_POLICY.backoffCapMs);
    expect(lo(30)).toBe(OUTBOX_POLICY.backoffCapMs / 2);
  });

  it("honours Retry-After as a floor, but never beyond the 24 h ceiling", () => {
    expect(retryDelayMs(1, fixedRng(0), 600)).toBe(600_000);
    expect(retryDelayMs(1, fixedRng(0), 1)).toBe(7_500); // backoff already longer
    expect(retryDelayMs(1, fixedRng(0), 10 * 365 * 86_400)).toBe(OUTBOX_POLICY.retryAfterCapMs);
    expect(retryDelayMs(1, fixedRng(0), -5)).toBe(7_500);
    expect(retryDelayMs(1, fixedRng(0), Number.NaN)).toBe(7_500);
  });

  it("an item answered 429 with Retry-After is not due until that time", () => {
    const out = applyAnswer(sent(), resp(429, undefined, 300), T0, fixedRng(0));
    expect(out.status).toBe("retry");
    expect(out.nextAttemptAt).toBe(T0 + 300_000);
    expect(isDue(out, T0 + 299_999)).toBe(false);
    expect(isDue(out, T0 + 300_000)).toBe(true);
  });

  it("successive failures back off further (attempt counter)", () => {
    let item = fresh();
    const delays: number[] = [];
    let now = T0;
    for (let i = 0; i < 5; i += 1) {
      item = applyAnswer(beginSend(item, now), resp(500), now, fixedRng(0));
      delays.push(item.nextAttemptAt! - now);
      now = item.nextAttemptAt!;
    }
    expect(delays).toEqual([7_500, 15_000, 30_000, 60_000, 120_000]);
  });
});

describe("unlisted course (§7.4, G3-01)", () => {
  const unlisted = (): OutboxItem => fresh({ courseId: null });

  it("is never due, never sendable", () => {
    expect(isDue(unlisted(), T0 + 10 * 86_400_000)).toBe(false);
    expect(() => beginSend(unlisted(), T0)).toThrow(InvalidTransition);
    expect(playedStatus(unlisted(), T0)).toBe("unlisted_course");
  });

  it("becomes an ordinary sendable item once a catalog carries the course", () => {
    const out = resolveUnlisted(unlisted(), "crs_01M39GMFJZ2P89V3ZZXPPH671T", "20260201-bbbbbbb", T0 + 5);
    expect(out).toMatchObject({ status: "pending", courseId: "crs_01M39GMFJZ2P89V3ZZXPPH671T", catalogVersion: "20260201-bbbbbbb" });
    expect(isDue(out, T0 + 5)).toBe(true);
    expect(playedStatus(out, T0 + 5)).toBe("saving");
  });

  it("cannot resolve an item that already has a course", () => {
    expect(() => resolveUnlisted(fresh(), "crs_x", "v", T0)).toThrow(InvalidTransition);
  });
});

describe("422 catalog_stale re-match", () => {
  const stale = (): OutboxItem => applyAnswer(sent(), resp(422, "catalog_stale"), T0 + 1, fixedRng(0));

  it("must be re-matched before it can be sent again", () => {
    expect(() => beginSend(stale(), T0 + 2)).toThrow(InvalidTransition);
  });

  it("a successful re-match updates course, catalogVersion and payload, then it is sendable", () => {
    const out = completeRematch(stale(), { ok: true, courseId: "crs_new", catalogVersion: "20260301-ccccccc", payload: { insideRatio: 0.9 } }, T0 + 2);
    expect(out).toMatchObject({ status: "pending", rematch: false, courseId: "crs_new", catalogVersion: "20260301-ccccccc", payload: { insideRatio: 0.9 } });
    expect(isDue(out, T0 + 2)).toBe(true);
  });

  it("a re-match that finds no course is not a failure: the item becomes 'Unlisted course' and waits", () => {
    const out = completeRematch(stale(), { ok: true, courseId: null, catalogVersion: "20260301-ccccccc", payload: {} }, T0 + 2);
    expect(out.status).toBe("pending");
    expect(playedStatus(out, T0 + 2)).toBe("unlisted_course");
  });

  it("a re-match that cannot run at all is needs_attention(rematch_failed)", () => {
    const out = completeRematch(stale(), { ok: false }, T0 + 2);
    expect(out).toMatchObject({ status: "needs_attention", reason: "rematch_failed", deadLetteredAt: T0 + 2 });
  });

  it("completeRematch is refused when no re-match was requested", () => {
    expect(() => completeRematch(fresh(), { ok: false }, T0)).toThrow(InvalidTransition);
  });
});

describe("Played display states (§7.6 right-hand column)", () => {
  it("maps each state", () => {
    expect(playedStatus(applyAnswer(sent(), resp(201), T0, fixedRng(0)), T0)).toBe("accepted");
    expect(playedStatus(applyAnswer(sent(), resp(202, "queued_catalog"), T0, fixedRng(0)), T0)).toBe("queued");
    expect(playedStatus(applyAnswer(sent(), resp(400), T0, fixedRng(0)), T0)).toBe("needs_attention");
    expect(playedStatus(fresh(), T0)).toBe("saving");
    expect(playedStatus(sent(), T0)).toBe("saving");
  });

  it("a retrying item shows 'Waiting to sync' only after 24 h", () => {
    const retrying = applyAnswer(sent(), resp(503), T0, fixedRng(0));
    expect(playedStatus(retrying, T0 + 24 * 3_600_000 - 1)).toBe("saving");
    expect(playedStatus(retrying, T0 + 24 * 3_600_000)).toBe("waiting_to_sync");
  });
});

describe("dead letters and interrupted sends", () => {
  it("a dead letter is kept 90 days, then expires", () => {
    const dead = applyAnswer(sent(), resp(400), T0, fixedRng(0));
    expect(isExpiredDeadLetter(dead, T0 + OUTBOX_POLICY.deadLetterRetentionMs - 1)).toBe(false);
    expect(isExpiredDeadLetter(dead, T0 + OUTBOX_POLICY.deadLetterRetentionMs)).toBe(true);
    expect(isExpiredDeadLetter(fresh(), T0 + 1e13)).toBe(false);
  });

  it("'Report a problem' is remembered once", () => {
    const dead = applyAnswer(sent(), resp(400), T0, fixedRng(0));
    const reported = markReported(dead, T0 + 1);
    expect(reported.reported).toBe(true);
    expect(markReported(reported, T0 + 2)).toBe(reported);
    expect(() => markReported(fresh(), T0)).toThrow(InvalidTransition);
  });

  it("an item stuck in 'sent' (process killed mid-request) returns to retry", () => {
    const s = sent(fresh(), T0);
    expect(isStaleSent(s, T0 + OUTBOX_POLICY.sentStaleMs - 1)).toBe(false);
    expect(isStaleSent(s, T0 + OUTBOX_POLICY.sentStaleMs)).toBe(true);
    const back = recoverInterrupted(s, T0 + 999_999);
    expect(back).toMatchObject({ status: "retry", attempts: 1 });
    expect(isDue(back, T0 + 999_999)).toBe(true);
  });

  it("a queued item resolves to accepted, or to needs_attention after the server's 7-day expiry", () => {
    const queued = applyAnswer(sent(), resp(202, "queued_catalog"), T0, fixedRng(0));
    expect(resolveQueued(queued, "accepted", T0 + 1).status).toBe("accepted");
    expect(resolveQueued(queued, "queue_expired", T0 + 1)).toMatchObject({ status: "needs_attention", reason: "queue_expired" });
  });
});

describe("transition guards", () => {
  it("rejects illegal moves loudly", () => {
    const accepted = applyAnswer(sent(), resp(201), T0, fixedRng(0));
    expect(() => beginSend(accepted, T0)).toThrow(InvalidTransition);
    expect(() => applyAnswer(fresh(), resp(201), T0, fixedRng(0))).toThrow(InvalidTransition); // not 'sent'
    expect(() => resolveQueued(fresh(), "accepted", T0)).toThrow(InvalidTransition);
    expect(() => recoverInterrupted(fresh(), T0)).toThrow(InvalidTransition);
  });

  it("is pure: the input item is never mutated", () => {
    const item = fresh();
    const snapshot = JSON.stringify(item);
    beginSend(item, T0);
    expect(JSON.stringify(item)).toBe(snapshot);
    const s = sent(item);
    const snap2 = JSON.stringify(s);
    applyAnswer(s, resp(500), T0, fixedRng(0));
    expect(JSON.stringify(s)).toBe(snap2);
  });
});
