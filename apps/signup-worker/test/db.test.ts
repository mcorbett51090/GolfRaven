import { describe, expect, it } from "vitest";
import {
  createPendingSignup,
  deleteStaleUnconfirmed,
  deleteStaleUnsubscribed,
  recordConfirmation,
} from "../src/db";
import { FakeD1 } from "./fakes";

const NEW_ROW = {
  id: "id-1",
  emailLc: "player@example.com",
  consentVersion: "2026-09-23",
  source: null,
  createdAt: "2026-01-01T00:00:00.000Z",
  confirmTokenHash: "hash-1",
  confirmExpiresAt: "2026-01-03T00:00:00.000Z",
  unsubscribeTokenHash: "unsub-hash-1",
};

describe("createPendingSignup — race safety (F3)", () => {
  it("inserts a brand-new row and reports inserted: true", async () => {
    const db = new FakeD1();
    const result = await createPendingSignup(db, NEW_ROW);
    expect(result.inserted).toBe(true);
    expect(db.rows).toHaveLength(1);
  });

  it("a second insert for the SAME email_lc (simulating a concurrent signup) does NOT throw, does NOT create a second row, and reports inserted: false", async () => {
    const db = new FakeD1();
    await createPendingSignup(db, NEW_ROW);
    const second = await createPendingSignup(db, { ...NEW_ROW, id: "id-2", confirmTokenHash: "hash-2" });
    expect(second.inserted).toBe(false);
    expect(db.rows).toHaveLength(1);
    // The original row (from the "winning" insert) is untouched.
    expect(db.rows[0]?.id).toBe("id-1");
    expect(db.rows[0]?.confirm_token_hash).toBe("hash-1");
  });
});

describe("recordConfirmation — single-use token (F4)", () => {
  it("clears confirm_token_hash and confirm_expires_at on success", async () => {
    const db = new FakeD1();
    await createPendingSignup(db, NEW_ROW);
    await recordConfirmation(db, "id-1", "2026-01-02T00:00:00.000Z");
    expect(db.rows[0]?.confirmed_at).toBe("2026-01-02T00:00:00.000Z");
    expect(db.rows[0]?.confirm_token_hash).toBeNull();
    expect(db.rows[0]?.confirm_expires_at).toBeNull();
  });

  it("never moves confirmed_at on a later re-confirmation of the same row (COALESCE, load-bearing for K2)", async () => {
    const db = new FakeD1();
    await createPendingSignup(db, NEW_ROW);
    await recordConfirmation(db, "id-1", "2026-01-02T00:00:00.000Z");
    await recordConfirmation(db, "id-1", "2026-03-01T00:00:00.000Z");
    expect(db.rows[0]?.confirmed_at).toBe("2026-01-02T00:00:00.000Z");
  });
});

describe("retention cron deletes (F11)", () => {
  it("deleteStaleUnconfirmed removes only unconfirmed rows older than the cutoff", async () => {
    const db = new FakeD1();
    await createPendingSignup(db, { ...NEW_ROW, id: "old-unconfirmed", createdAt: "2026-01-01T00:00:00.000Z" });
    await createPendingSignup(db, {
      ...NEW_ROW,
      id: "recent-unconfirmed",
      emailLc: "other@example.com",
      createdAt: "2026-06-01T00:00:00.000Z",
    });
    await createPendingSignup(db, {
      ...NEW_ROW,
      id: "old-confirmed",
      emailLc: "confirmed@example.com",
      createdAt: "2026-01-01T00:00:00.000Z",
    });
    await recordConfirmation(db, "old-confirmed", "2026-01-02T00:00:00.000Z");

    const deleted = await deleteStaleUnconfirmed(db, "2026-03-01T00:00:00.000Z");
    expect(deleted).toBe(1);
    const remainingIds = db.rows.map((r) => r.id).sort();
    expect(remainingIds).toEqual(["old-confirmed", "recent-unconfirmed"].sort());
  });

  it("deleteStaleUnsubscribed removes only rows unsubscribed before the cutoff", async () => {
    const db = new FakeD1();
    await createPendingSignup(db, { ...NEW_ROW, id: "a", emailLc: "a@example.com" });
    await createPendingSignup(db, { ...NEW_ROW, id: "b", emailLc: "b@example.com" });
    await recordConfirmation(db, "a", "2026-01-01T00:00:00.000Z");
    await recordConfirmation(db, "b", "2026-01-01T00:00:00.000Z");
    db.rows.find((r) => r.id === "a")!.unsubscribed_at = "2026-01-05T00:00:00.000Z";
    db.rows.find((r) => r.id === "b")!.unsubscribed_at = "2026-06-01T00:00:00.000Z";

    const deleted = await deleteStaleUnsubscribed(db, "2026-03-01T00:00:00.000Z");
    expect(deleted).toBe(1);
    expect(db.rows.map((r) => r.id)).toEqual(["b"]);
  });
});
