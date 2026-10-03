// supabase/tests/unit/retention-purge-handler.test.ts
//
// Edge role PR4b (E5): the pure core of `retention-purge`. The database half (each purge purges its class, the bounds are the database's, the run is
// safe to repeat and to overlap) is supabase/tests/integration/retention-purge.deno.test.ts; this file pins the HANDLER's contract with fake steps.

import { describe, expect, it, vi } from "vitest";
import {
  handleRetentionPurgeRequest,
  MAX_BATCHES_PER_STEP,
  RETENTION_REQUEST_TIMEOUT_MS,
  RETENTION_RATE_BUCKET,
  RETENTION_RATE_MAX_PER_WINDOW,
  RETENTION_RATE_WINDOW_SECONDS,
  RUN_BUDGET_MS,
  type RetentionDeps,
} from "../../functions/_shared/retention/purge-handler.ts";
import type { RetentionStep } from "../../functions/_shared/types.ts";

const post = (headers: Record<string, string> = {}) => new Request("https://x.test/retention-purge", { method: "POST", headers });
const GOOD = { authorization: "Bearer scheduler-key" };

interface Probe {
  deps: RetentionDeps;
  rate: Array<[string, number, number]>;
  logs: Array<Record<string, unknown>>;
  calls: string[];
  clock: { now: number };
}

/** A step whose batches return `script` in order (then 0), recording each call. */
function step(name: RetentionStep["name"], batchLimit: number | null, script: Array<number | null | Error>, calls: string[], onBatch?: () => void): RetentionStep {
  let i = 0;
  return {
    name,
    batchLimit,
    async runBatch() {
      calls.push(name);
      onBatch?.();
      const next = i < script.length ? script[i++]! : 0;
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

function probe(make: (calls: string[], clock: { now: number }) => RetentionStep[], over: Partial<RetentionDeps> = {}): Probe {
  const calls: string[] = [];
  const rate: Probe["rate"] = [];
  const logs: Probe["logs"] = [];
  const clock = { now: 1_000_000 };
  const deps: RetentionDeps = {
    isAuthorized: (req) => req.headers.get("authorization") === GOOD.authorization,
    hitRateLimit: async (k, w, m) => {
      rate.push([k, w, m]);
      return { ok: true, count: 1 };
    },
    steps: make(calls, clock),
    nowMs: () => clock.now,
    log: (e) => logs.push(e),
    ...over,
  };
  return { deps, rate, logs, calls, clock };
}

const SIX = (calls: string[], script: Partial<Record<RetentionStep["name"], Array<number | null | Error>>> = {}): RetentionStep[] => [
  step("fix_coords", 5000, script.fix_coords ?? [3], calls),
  step("install_link_tombstones", 5000, script.install_link_tombstones ?? [2], calls),
  step("signin_email_proofs", 5000, script.signin_email_proofs ?? [1], calls),
  step("signin_revocation_queue", 5000, script.signin_revocation_queue ?? [4], calls),
  step("consumed_nonce", 5000, script.consumed_nonce ?? [5], calls),
  step("rate_limit_buckets", 5000, script.rate_limit_buckets ?? [6], calls),
];

async function body(res: Response): Promise<any> {
  return await res.json();
}

describe("retention-purge: authentication, method and rate limit come BEFORE any work", () => {
  it("only POST: GET is 405 and runs nothing", async () => {
    const p = probe((c) => SIX(c));
    const res = await handleRetentionPurgeRequest(new Request("https://x.test/", { method: "GET", headers: GOOD }), p.deps);
    expect(res.status).toBe(405);
    expect(p.calls).toEqual([]);
    expect(p.rate).toEqual([]);
  });

  for (const [label, headers] of [
    ["no Authorization header", {}],
    ["a wrong bearer", { authorization: "Bearer not-the-key" }],
    ["a bearer with the right text but the wrong scheme", { authorization: "Basic scheduler-key" }],
    ["an empty bearer", { authorization: "Bearer " }],
  ] as const) {
    it(`${label} is 401: no rate-limit hit (an unauthenticated caller spends nothing) and no step runs`, async () => {
      const p = probe((c) => SIX(c));
      const res = await handleRetentionPurgeRequest(post(headers), p.deps);
      expect(res.status).toBe(401);
      expect(p.rate).toEqual([]);
      expect(p.calls).toEqual([]);
    });
  }

  it("a rate-limited run is 429 with the retry hint and runs no step", async () => {
    const p = probe((c) => SIX(c), { hitRateLimit: async () => ({ ok: false, count: 13, retryAfterSeconds: 3600 }) });
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect(res.status).toBe(429);
    expect((await body(res)).error.details).toEqual({ retryAfterSeconds: 3600 });
    expect(p.calls).toEqual([]);
  });

  it("the documented bounds are the numbers in the code (the runbook and the design doc quote them): 10 batches per step, 30 s to start a batch, 55 s request race", () => {
    expect([MAX_BATCHES_PER_STEP, RUN_BUDGET_MS, RETENTION_REQUEST_TIMEOUT_MS]).toEqual([10, 30_000, 55_000]);
  });

  it("hits ONE coarse system bucket: 12 per hour", async () => {
    const p = probe((c) => SIX(c));
    await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect(p.rate).toEqual([[RETENTION_RATE_BUCKET, RETENTION_RATE_WINDOW_SECONDS, RETENTION_RATE_MAX_PER_WINDOW]]);
    expect([RETENTION_RATE_BUCKET, RETENTION_RATE_WINDOW_SECONDS, RETENTION_RATE_MAX_PER_WINDOW]).toEqual(["retention-purge", 3600, 12]);
  });
});

describe("retention-purge: what a run does", () => {
  it("runs every retention class once, in order, and reports each", async () => {
    const p = probe((c) => SIX(c));
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect(res.status).toBe(200);
    expect(p.calls).toEqual(["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"]);
    expect((await body(res)).data).toEqual({
      complete: true,
      steps: [
        { name: "fix_coords", status: "done", purged: 3, batches: 1 },
        { name: "install_link_tombstones", status: "done", purged: 2, batches: 1 },
        { name: "signin_email_proofs", status: "done", purged: 1, batches: 1 },
        { name: "signin_revocation_queue", status: "done", purged: 4, batches: 1 },
        { name: "consumed_nonce", status: "done", purged: 5, batches: 1 },
        { name: "rate_limit_buckets", status: "done", purged: 6, batches: 1 },
      ],
    });
  });

  it("a batched step repeats while a batch comes back FULL and stops at the first short one", async () => {
    const p = probe((c) => SIX(c, { fix_coords: [5000, 5000, 120] }));
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    const steps = (await body(res)).data.steps;
    expect(steps[0]).toEqual({ name: "fix_coords", status: "done", purged: 10120, batches: 3 });
    expect(p.calls.filter((c) => c === "fix_coords")).toHaveLength(3);
  });

  it("is BOUNDED per run: a step whose every batch is full stops after MAX_BATCHES_PER_STEP and reports `truncated`", async () => {
    const p = probe((c) => SIX(c, { fix_coords: Array.from({ length: 50 }, () => 5000) }));
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    const data = (await body(res)).data;
    expect(p.calls.filter((c) => c === "fix_coords")).toHaveLength(MAX_BATCHES_PER_STEP);
    expect(data.steps[0]).toEqual({ name: "fix_coords", status: "truncated", purged: 5000 * MAX_BATCHES_PER_STEP, batches: MAX_BATCHES_PER_STEP });
    expect(data.complete).toBe(false);
    // the other steps still ran after it
    expect(p.calls).toContain("signin_revocation_queue");
  });

  it("is bounded in TIME too: no new batch STARTS once the run budget is spent (the first batch of a step always may)", async () => {
    const p = probe(
      (c, clock) => [
        step("fix_coords", 5000, [5000, 5000, 5000], c, () => (clock.now += RUN_BUDGET_MS / 2 + 1)),
        step("install_link_tombstones", 5000, [7], c),
      ],
    );
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    const steps = (await body(res)).data.steps;
    expect(steps[0].status).toBe("truncated");
    expect(steps[0].batches).toBe(2); // the third batch was not started: the budget was spent after the second
    expect(steps[1]).toEqual({ name: "install_link_tombstones", status: "done", purged: 7, batches: 1 }); // a later step still gets its first batch
  });

  it("an UNBATCHED step is one pass whatever it returns (its definer has no row bound to be 'full' against)", async () => {
    // (no step the real wiring builds is unbatched any more since 0040 gave the sign-in purges their own bound; the handler still supports it)
    const p = probe((c) => [step("signin_email_proofs", null, [999_999], c)]);
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect((await body(res)).data.steps[0]).toEqual({ name: "signin_email_proofs", status: "done", purged: 999_999, batches: 1 });
    expect(p.calls.filter((c) => c === "signin_email_proofs")).toHaveLength(1);
  });

  it("a step another run holds is `busy` (skipped, not failed, not waited for) and the run is not `complete`; the rest still run", async () => {
    const p = probe((c) => SIX(c, { install_link_tombstones: [null] }));
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect(res.status).toBe(200);
    const data = (await body(res)).data;
    expect(data.steps[1]).toEqual({ name: "install_link_tombstones", status: "busy", purged: 0, batches: 0 });
    expect(data.complete).toBe(false);
    expect(p.calls).toEqual(["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"]);
  });

  it("a step that becomes busy MID-run keeps what its earlier batches removed", async () => {
    const p = probe((c) => SIX(c, { fix_coords: [5000, null] }));
    const data = (await body(await handleRetentionPurgeRequest(post(GOOD), p.deps))).data;
    expect(data.steps[0]).toEqual({ name: "fix_coords", status: "busy", purged: 5000, batches: 1 });
  });

  it("running it again after everything is purged removes nothing and still succeeds (idempotent shape)", async () => {
    const p = probe((c) => SIX(c, { fix_coords: [0], install_link_tombstones: [0], signin_email_proofs: [0], signin_revocation_queue: [0], consumed_nonce: [0], rate_limit_buckets: [0] }));
    const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
    const data = (await body(res)).data;
    expect(data.complete).toBe(true);
    expect(data.steps.every((s: { purged: number }) => s.purged === 0)).toBe(true);
  });
});

describe("retention-purge: one class failing does not stop the others", () => {
  it("answers 500 `retention_step_failed` with EVERY step's result, after running the remaining steps", async () => {
    const boom = Object.assign(new Error("permission denied for function purge_fix_coords (SECRET-TEXT-FROM-THE-DATABASE)"), { code: "42501" });
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const p = probe((c) => SIX(c, { fix_coords: [boom] }));
      const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
      expect(res.status).toBe(500);
      const text = await res.text();
      const json = JSON.parse(text);
      expect(json.error.code).toBe("retention_step_failed");
      expect(json.error.details.steps[0]).toEqual({ name: "fix_coords", status: "failed", purged: 0, batches: 0, error: "42501" });
      expect(json.error.details.steps.slice(1).map((s: { status: string }) => s.status)).toEqual(["done", "done", "done", "done", "done"]);
      expect(p.calls).toEqual(["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"]);
      // only the code leaves the server; the database's own text never does
      expect(text).not.toContain("SECRET-TEXT");
      expect(text).not.toContain("permission denied");
      // ... and it is in the server log
      expect(spy).toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("an error with no SQLSTATE is reported as `error`", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const p = probe((c) => SIX(c, { signin_revocation_queue: [new Error("x")] }));
      const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
      expect((await body(res)).error.details.steps[3].error).toBe("error");
    } finally {
      spy.mockRestore();
    }
  });

  it("a failure after earlier batches keeps the count of what those batches removed", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const p = probe((c) => SIX(c, { fix_coords: [5000, new Error("x")] }));
      const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
      expect((await body(res)).error.details.steps[0]).toMatchObject({ status: "failed", purged: 5000, batches: 1 });
    } finally {
      spy.mockRestore();
    }
  });
});

describe("retention-purge: the two TTL hygiene steps (0040) behave like every other step", () => {
  it("a hygiene step failing is reported alone: the four retention classes before it ran, and the other hygiene step still runs", async () => {
    const boom = Object.assign(new Error("db text"), { code: "42501" });
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const p = probe((c) => SIX(c, { consumed_nonce: [boom] }));
      const res = await handleRetentionPurgeRequest(post(GOOD), p.deps);
      expect(res.status).toBe(500);
      const steps = (await body(res)).error.details.steps as Array<{ name: string; status: string; error?: string }>;
      expect(steps.map((s) => [s.name, s.status])).toEqual([
        ["fix_coords", "done"],
        ["install_link_tombstones", "done"],
        ["signin_email_proofs", "done"],
        ["signin_revocation_queue", "done"],
        ["consumed_nonce", "failed"],
        ["rate_limit_buckets", "done"],
      ]);
      expect(steps[4]!.error).toBe("42501");
    } finally {
      spy.mockRestore();
    }
  });

  it("a backlog larger than one batch is cleared over several batches: a FULL batch repeats the step, a short one ends it", async () => {
    const p = probe((c) => SIX(c, { rate_limit_buckets: [5000, 5000, 4999], consumed_nonce: [5000, 17], signin_email_proofs: [5000, 5000, 1], signin_revocation_queue: [5000, 3] }));
    const data = (await body(await handleRetentionPurgeRequest(post(GOOD), p.deps))).data;
    const by = Object.fromEntries((data.steps as Array<{ name: string; purged: number; batches: number; status: string }>).map((s) => [s.name, s]));
    expect(by.rate_limit_buckets).toEqual({ name: "rate_limit_buckets", status: "done", purged: 14_999, batches: 3 });
    expect(by.consumed_nonce).toEqual({ name: "consumed_nonce", status: "done", purged: 5017, batches: 2 });
    expect(by.signin_email_proofs).toEqual({ name: "signin_email_proofs", status: "done", purged: 10_001, batches: 3 });
    expect(by.signin_revocation_queue).toEqual({ name: "signin_revocation_queue", status: "done", purged: 5003, batches: 2 });
    expect(p.calls.filter((c) => c === "signin_email_proofs")).toHaveLength(3);
  });

  it("every step is bounded per run, the sign-in and hygiene ones included: a backlog that never shrinks is truncated at MAX_BATCHES_PER_STEP, not run forever", async () => {
    const forever = Array.from({ length: 50 }, () => 5000);
    const p = probe((c) => SIX(c, { signin_revocation_queue: forever, consumed_nonce: forever, rate_limit_buckets: forever, signin_email_proofs: forever }));
    const data = (await body(await handleRetentionPurgeRequest(post(GOOD), p.deps))).data;
    for (const name of ["signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"]) {
      expect(data.steps.find((s: { name: string }) => s.name === name)).toMatchObject({ status: "truncated", batches: MAX_BATCHES_PER_STEP });
    }
    expect(data.complete).toBe(false);
  });
});

describe("retention-purge: logging", () => {
  it("logs one summary event with counts and codes only", async () => {
    const p = probe((c) => SIX(c));
    await handleRetentionPurgeRequest(post(GOOD), p.deps);
    expect(p.logs).toHaveLength(1);
    expect(p.logs[0]).toMatchObject({ event: "retention_purge", complete: true });
    // counts, names and codes only: the event carries exactly these keys, and each step exactly these
    expect(Object.keys(p.logs[0]!).sort()).toEqual(["complete", "event", "steps"]);
    for (const st of p.logs[0]!.steps as Array<Record<string, unknown>>) expect(Object.keys(st).sort()).toEqual(["batches", "error", "name", "purged", "status"]);
  });
});
