/**
 * P5.1a S2a: the client half of `POST marker-scan` (`api.scanMarker`), against the REAL handler's recorded answers (`test/fixtures/edge-contract.json`, `markerscan_*`, recorded by
 * `scripts/record-edge-contract.rec.ts`). What is proved: the URL, the strict body (compared with the request the real parser accepted), the owner's token, one request and no retry (a
 * scan is single-use), the answer schema, the mapping of every recorded refusal, and that NOTHING in the app calls it yet (`MARKER_COSIGNAL_UI_ENABLED` is false, and no sender exists).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError, createHttpApiClient, createUnconfiguredApi, type MarkerScanRequest, type MarkerScanResult } from "../src/api";
import { createMockApi } from "../src/api/mock";
import { devOnly } from "../src/dev-guard";
import { MARKER_COSIGNAL_UI_ENABLED } from "../src/features";
import { jwt } from "./support/fakes";
import { recorded, recordedRequest, scriptedFetch } from "./support/edge-fixtures";

const USER = "11111111-aaaa-4aaa-8aaa-111111111111";
const BASE = "https://x.test/functions/v1";
const creds = { userId: USER, accessToken: jwt({ sub: USER, role: "authenticated" }) };
const client = (fetch: ReturnType<typeof scriptedFetch>["fetch"]) => createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: async () => "session-token", sleep: async () => undefined });
const answerOf = (name: string): MarkerScanResult => JSON.parse(recorded(name).body).data as MarkerScanResult;
const failure = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => e as ApiError,
  );

describe("api.scanMarker against the real handler's recorded answers", () => {
  it("a scan: POST <base>/marker-scan with the strict body the real parser accepted, as the OWNER's token; 201 parses", async () => {
    const f = scriptedFetch({ respond: "markerscan_201_rotating_credited" });
    const out = await client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>("markerscan_201_rotating_credited"), creds);
    expect(out).toEqual(answerOf("markerscan_201_rotating_credited"));
    expect(out).toMatchObject({ outcome: "credited", cosignal: "counted" });
    expect(f.seen).toHaveLength(1);
    expect(f.seen[0]).toMatchObject({ url: `${BASE}/marker-scan`, method: "POST", body: recordedRequest("markerscan_201_rotating_credited"), redirect: "error", credentials: "omit" });
    expect(f.seen[0]!.headers.Authorization).toBe(`Bearer ${creds.accessToken}`);
  });

  it("every recorded success shape parses: a printed-QR scan, a pending scan, an unattestable (held_review) scan, and the co-signal intake (200, only the fix)", async () => {
    for (const [name, outcome] of [
      ["markerscan_201_static_pin_credited", "credited"],
      ["markerscan_201_rotating_pending_no_fix", "pending"],
      ["markerscan_201_held_review_unattestable", "held_review"],
      ["markerscan_200_cosignal_credited", "credited"],
    ] as const) {
      const f = scriptedFetch({ respond: name });
      const out = await client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>(name), creds);
      expect(out.outcome, name).toBe(outcome);
      expect(f.seen[0]!.body, name).toEqual(recordedRequest(name));
    }
    expect(answerOf("markerscan_200_cosignal_credited").localDate).toBeNull();
    expect(answerOf("markerscan_201_rotating_pending_no_fix").purchases.map((p) => p.credit.status)).toEqual(["pending", "pending"]);
  });

  it("the request is built from its fields only: an absent qr / fix / device / jti is ABSENT on the wire (the server's parser is strict about shape)", async () => {
    const f = scriptedFetch({ respond: "markerscan_200_cosignal_credited" });
    const req = recordedRequest<MarkerScanRequest>("markerscan_200_cosignal_credited");
    await client(f.fetch).scanMarker({ facilityId: req.facilityId, ...(req.deviceId ? { deviceId: req.deviceId } : {}), ...(req.fix ? { fix: req.fix } : {}), ...(req.jti ? { jti: req.jti } : {}) }, creds);
    expect(Object.keys(f.seen[0]!.body as object).sort()).toEqual(["deviceId", "facilityId", "fix", "jti"]);
    expect((f.seen[0]!.body as Record<string, unknown>).qr).toBeUndefined();
  });

  it("every recorded refusal is mapped, and NONE is retried (a scan is single-use: the request goes out once)", async () => {
    const cases: Array<[string, string, number, string]> = [
      ["markerscan_409_fix_already_used", "conflict", 409, "fix_already_used"],
      ["markerscan_409_qr_used", "conflict", 409, "qr_used"],
      ["markerscan_409_qr_used_retry", "conflict", 409, "qr_used"],
      ["markerscan_422_invalid_pin", "rejected", 422, "invalid_pin"],
      ["markerscan_429_pin_locked", "rate_limited", 429, "rate_limited"],
      ["markerscan_422_qr_expired", "rejected", 422, "qr_expired"],
      ["markerscan_422_invalid_qr_forged", "rejected", 422, "invalid_qr"],
      ["markerscan_422_no_pending_purchase", "rejected", 422, "no_pending_purchase"],
      ["markerscan_422_not_a_cosignal", "rejected", 422, "not_a_cosignal"],
      ["markerscan_422_fix_out_of_window", "rejected", 422, "fix_out_of_window"],
      ["markerscan_422_programme_inactive", "rejected", 422, "marker_programme_inactive"],
      ["markerscan_422_invalid_cosignal", "rejected", 422, "invalid_cosignal"],
      ["markerscan_400_unknown_key", "rejected", 400, "bad_request"],
      ["markerscan_400_fix_without_device", "rejected", 400, "bad_request"],
      ["markerscan_503_pin_unavailable", "unavailable", 503, "course_pin_unavailable"],
      ["markerscan_429_rate_limited", "rate_limited", 429, "rate_limited"],
    ];
    for (const [name, kind, status, code] of cases) {
      const f = scriptedFetch({ respond: name });
      const err = await failure(client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>(name), creds));
      expect(err, name).toMatchObject({ kind, status, code });
      expect(f.seen, name).toHaveLength(1);
    }
  });

  it("a PIN lockout carries its Retry-After (the player is told when to try again)", async () => {
    const f = scriptedFetch({ respond: "markerscan_429_pin_locked" });
    const err = await failure(client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>("markerscan_429_pin_locked"), creds));
    expect(err?.retryAfterSeconds).toBe(3600);
  });

  it("an answer the client cannot interpret is bad_response, never a purchase: an unknown outcome, a missing purchases list, a malformed date", async () => {
    const good = answerOf("markerscan_201_rotating_credited");
    for (const patch of [{ outcome: "paid" }, { purchases: undefined }, { localDate: "June 1" }, { cosignal: "yes" }, { purchases: [{ ...good.purchases[0], status: "valid ", credit: good.purchases[0]!.credit }] }, { purchases: [{ ...good.purchases[0], credit: { id: "x", status: "refunded" } }] }]) {
      const f = scriptedFetch({ status: 201, body: JSON.stringify({ data: { ...good, ...patch } }) });
      const err = await failure(client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>("markerscan_201_rotating_credited"), creds));
      expect(err, JSON.stringify(patch)).toMatchObject({ kind: "bad_response" });
    }
    // and a success status the contract does not name
    const f = scriptedFetch({ status: 202, body: JSON.stringify({ data: good }) });
    expect(await failure(client(f.fetch).scanMarker(recordedRequest<MarkerScanRequest>("markerscan_201_rotating_credited"), creds))).toMatchObject({ kind: "bad_response" });
  });

  it("the unconfigured build refuses, and the demo answers an obviously fake pending purchase", async () => {
    expect(await failure(createUnconfiguredApi().scanMarker({ facilityId: "fac_x" }, creds))).toMatchObject({ kind: "not_configured" });
    const mock = createMockApi(devOnly(true));
    expect((await mock.scanMarker({ facilityId: "fac_x" }, creds)).outcome).toBe("pending");
    expect(mock.calls).toEqual([{ op: "marker_scan", req: { facilityId: "fac_x" } }]);
  });
});

describe("scanMarker callers (P5 §52)", () => {
  it("MARKER_COSIGNAL_UI_ENABLED is false; only marker/send.ts outside src/api calls scanMarker", () => {
    expect(MARKER_COSIGNAL_UI_ENABLED).toBe(false);
    const root = fileURLToPath(new URL("../src", import.meta.url));
    const walk = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : n.endsWith(".ts") || n.endsWith(".tsx") ? [join(dir, n)] : []));
    const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    const callers = walk(root)
      .filter((f) => !f.startsWith(join(root, "api")) && /\.scanMarker\b|scanMarker\s*\(/.test(strip(readFileSync(f, "utf8"))))
      .map((f) => f.slice(root.length + 1))
      .sort();
    expect(callers).toEqual(["marker/send.ts"]);
  });
});

describe("the gitleaks allowlist for the recorded course-QR tokens is anchored", () => {
  const toml = readFileSync(fileURLToPath(new URL("../../../.gitleaks.toml", import.meta.url)), "utf8");
  const entry = toml.split("[[allowlists]]").find((e) => /course-QR rotating token/i.test(e)) ?? "";
  const regex = /regexes = \['''(.+)'''\]/.exec(entry)?.[1] ?? "";
  const re = new RegExp(regex);
  const lines = JSON.stringify(JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/edge-contract.json", import.meta.url)), "utf8")), null, 2).split("\n");
  const tokenLines = lines.filter((l) => /^\s*"token": "eyJ/.test(l));

  it("the entry exists, has no `paths` (gitleaks would skip the whole file) and anchors the WHOLE line", () => {
    expect(regex).not.toBe("");
    expect(entry).not.toMatch(/^paths\s*=/m);
    expect(regex.startsWith("^")).toBe(true);
    expect(regex.endsWith("$")).toBe(true);
  });

  it("it matches every recorded token line of the fixture, and nothing wider", () => {
    expect(tokenLines.length).toBeGreaterThanOrEqual(10);
    for (const l of tokenLines) expect(re.test(l), l.slice(0, 60)).toBe(true);
    const sample = tokenLines[0]!;
    const [head, rest] = [sample.slice(0, sample.indexOf("eyJ")), sample.slice(sample.indexOf("eyJ"))];
    const body = rest.replace(/",?$/, "");
    for (const wider of [
      `${sample} "x": "ghp_${"a1B2".repeat(9)}"`,
      `x ${sample}`,
      `${head}${body.replace("eyJhbGciOiJFZERTQSIsImtpZCI6InJrMSIs", "eyJhbGciOiJFZERTQSIsImtpZCI6InJrMiIs")}"`, // another kid
      `${head}"eyJhbGciOiJSUzI1NiJ9.${body.split(".")[1]}.${body.split(".")[2]}"`, // another header
      `${head}${body}A"`, // a longer signature
      `${head}"${body.split(".").slice(0, 2).join(".")}.${"a".repeat(60)}"`, // a shorter signature
    ]) {
      expect(re.test(wider), wider.slice(0, 80)).toBe(false);
    }
  });
});
