/**
 * P4.2b-3b: what a reward activation ends in, and what is (not) reachable. Every answer the REAL handler gave (`activate_*` in the recorded fixture) is mapped here explicitly; the HTTP call is
 * checked against it (URL, bearer, body, no retry); the service's own paths (signed out, no token, ...) have outcomes; every outcome has copy in both languages; and with the flags off nothing
 * of the Wallet card or the offline code can be reached from a release build.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createHttpApiClient, createUnconfiguredApi } from "../src/api";
import { AttestationDeferred, PlainActivator, ActivationUnsupportedPlatform } from "../src/attest";
import { CHECKIN_UI_ENABLED, MARKER_COSIGNAL_UI_ENABLED, OFFLINE_CODE_UI_ENABLED, WALLET_ACTIVATION_UI_ENABLED } from "../src/features";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";
import { activateReward, activationMessage, isRetryableActivation, outcomeFromAnswer, outcomeFromError, type ActivationOutcome, type ActivationOutcomeStatus } from "../src/rewards";
import { RECORDED, recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { apiError, jwt } from "./support/fakes";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (rel: string): string => readFileSync(join(root, rel), "utf8");
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx)$/.test(n) ? [p] : [];
  });
}

const USER = "11111111-aaaa-4aaa-8aaa-111111111111";
const OTHER = "22222222-bbbb-4bbb-8bbb-222222222222";
const DEVICE = "11111111-1111-4111-8111-111111111111";
const R1 = "aaaaaaaa-0000-4000-8000-000000000001";
const BASE = "https://x.test/functions/v1";
const ownerToken = jwt({ sub: USER, role: "authenticated" });

class Session {
  current: string | null = USER;
  token: string | null = ownerToken;
  throwOnToken = false;
  fetched: string[] = [];
  currentUserId(): string | null {
    return this.current;
  }
  accessTokenFor(userId: string): Promise<string | null> {
    this.fetched.push(userId);
    return this.throwOnToken ? Promise.reject(new Error("refresh failed")) : Promise.resolve(this.token);
  }
}

function setup(activator = new PlainActivator("ios"), ...steps: Step[]) {
  const f = scriptedFetch(...steps);
  const session = new Session();
  const api = createHttpApiClient({ baseUrl: BASE, fetch: f.fetch, getAccessToken: async () => "session-token", sleep: async () => undefined, activator });
  return { ...f, session, api, run: (id = R1) => activateReward({ api, session, deviceId: async () => DEVICE }, id) };
}

/** EVERY recorded activation answer, and what the Wallet must make of it. A new `activate_*` entry in the fixture fails the completeness test below until it is mapped here on purpose. */
const TABLE: Record<string, ActivationOutcome> = {
  activate_200_issued_ios: { status: "activated", kind: "offer_code", state: "issued", alreadyActive: false },
  activate_200_replay_already_active: { status: "activated", kind: "offer_code", state: "issued", alreadyActive: true },
  activate_200_redeemable_ios_entitlement: { status: "activated", kind: "entitlement", state: "redeemable", alreadyActive: false },
  activate_200_issued_android: { status: "activated", kind: "offer_code", state: "issued", alreadyActive: false },
  activate_200_issued_android_after_503: { status: "activated", kind: "offer_code", state: "issued", alreadyActive: false },
  activate_200_held_review_bit0_new_account: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_replay: { status: "held_review", kind: "offer_code", alreadyHeld: true },
  activate_200_held_review_bit1: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_unattestable_none_ios: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_failed_claim_without_token: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_failed_attested_before_no_token: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_android_no_install_link: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_200_held_unattestable_none_android: { status: "held_review", kind: "offer_code", alreadyHeld: false },
  activate_409_not_activatable: { status: "not_activatable" },
  activate_409_expired: { status: "expired" },
  activate_404_foreign_reward: { status: "not_found" },
  activate_404_unknown_reward: { status: "not_found" },
  activate_404_unparseable_path: { status: "not_found" },
  activate_403_demo_account: { status: "not_allowed" },
  activate_422_platform_mismatch: { status: "platform_mismatch" },
  activate_422_device_limit: { status: "device_limit" },
  activate_422_challenge_not_consumable: { status: "challenge_expired" },
  activate_429_rate_limited: { status: "rate_limited", retryAfterSeconds: expect.any(Number) as unknown as number },
  activate_503_attestation_unavailable: { status: "vendor_unavailable" },
  activate_503_attestation_not_configured: { status: "not_available" },
  activate_400_reward_id_in_body: { status: "rejected", code: "bad_request" },
  activate_400_install_link_on_ios: { status: "rejected", code: "bad_request" },
  activate_400_attestation_without_challenge: { status: "rejected", code: "bad_request" },
};

describe("every answer the real handler gave is mapped (§7.5 decision table outcomes included)", () => {
  it("the table is complete: every recorded activate_* entry has a mapping, and nothing is mapped that was not recorded", () => {
    expect(Object.keys(TABLE).sort()).toEqual(Object.keys(RECORDED).filter((k) => k.startsWith("activate_")).sort());
    expect(Object.keys(TABLE).length).toBeGreaterThanOrEqual(28);
  });

  it.each(Object.keys(TABLE))("%s", async (name) => {
    const t = setup(undefined, { respond: name });
    const outcome = await t.run();
    expect(outcome).toEqual(TABLE[name]);
    expect(t.seen, "one request: an activation is never retried by the client").toHaveLength(1);
  });

  it("held_review is 'under review', NOT an error: a distinct outcome, not retryable, with its own copy that names no failure; and the idempotent answers are successes", async () => {
    for (const name of Object.keys(TABLE).filter((k) => k.startsWith("activate_200_held"))) {
      const o = await setup(undefined, { respond: name }).run();
      expect(o.status, name).toBe("held_review");
      expect(isRetryableActivation(o), name).toBe(false);
      const m = activationMessage(o);
      expect(m.key).toMatch(/held_review/);
      expect(en[m.key]).toMatch(/under review/i);
      expect(frCA[m.key]).toMatch(/vérification/i);
      for (const text of [en[m.key], frCA[m.key]]) expect(text).not.toMatch(/\berror\b|\bfailed\b|could not|couldn't|impossible|erreur|échou/i);
    }
    const replay = await setup(undefined, { respond: "activate_200_replay_already_active" }).run();
    expect(replay).toMatchObject({ status: "activated", alreadyActive: true });
    expect(en[activationMessage(replay).key]).toMatch(/already activated/i);
  });

  it("the idempotent 'already activated' answer is a 200 with replay:true, NOT a 409 (a 409 means the reward can no longer be activated)", () => {
    expect(recorded("activate_200_replay_already_active").status).toBe(200);
    expect(JSON.parse(recorded("activate_200_replay_already_active").body).data.replay).toBe(true);
    expect(recorded("activate_409_not_activatable").status).toBe(409);
    expect(outcomeFromError(apiError("conflict", 409, "reward_not_activatable"))).toEqual({ status: "not_activatable" });
    expect(outcomeFromError(apiError("conflict", 409, "something_new"))).toEqual({ status: "conflict" });
  });

  it("429 carries the server's Retry-After into the outcome, and the line says how long", async () => {
    const o = await setup(undefined, { respond: "activate_429_rate_limited" }).run();
    expect(o).toMatchObject({ status: "rate_limited", retryAfterSeconds: expect.any(Number) });
    const m = activationMessage(o);
    expect(m.key).toBe("wallet.activate.outcome.rate_limited");
    expect(m.params).toEqual({ minutes: expect.any(Number) });
    expect(activationMessage({ status: "rate_limited", retryAfterSeconds: 90 }).params).toEqual({ minutes: 2 });
    expect(activationMessage({ status: "rate_limited", retryAfterSeconds: null }).key).toBe("wallet.activate.outcome.rate_limited.later");
  });

  it("an answer with a state the client does not know is `unexpected_state` (look again), never a silent success", () => {
    expect(outcomeFromAnswer({ id: R1, kind: "offer_code", state: "void", held: false, replay: false })).toEqual({ status: "unexpected_state", state: "void" });
    expect(outcomeFromAnswer({ id: R1, kind: "entitlement", state: "held_review", held: false, replay: false })).toMatchObject({ status: "held_review" }); // either signal says held
    expect(outcomeFromAnswer({ id: R1, kind: "offer_code", state: "issued", held: true, replay: false })).toMatchObject({ status: "held_review" });
  });
});

describe("the transport and the account, before and after a send", () => {
  const cases: Array<[string, Step, ActivationOutcome]> = [
    ["a network failure after the send: the outcome is UNKNOWN (a retry is safe at the server)", { network: "offline" }, { status: "unknown_outcome" }],
    ["500", { status: 500, body: JSON.stringify({ error: { code: "internal_error", message: "x" } }) }, { status: "unknown_outcome" }],
    ["a gateway 502", { status: 502, body: "<html>bad gateway</html>" }, { status: "unknown_outcome" }],
    ["a gateway 504", { status: 504, body: "" }, { status: "unknown_outcome" }],
    ["a bare 503 (not the attestation_* rollback)", { status: 503, body: JSON.stringify({ error: { code: "service_unavailable" } }) }, { status: "unknown_outcome" }],
    ["a 200 whose body is not an activation result", { status: 200, body: JSON.stringify({ data: { id: R1 } }) }, { status: "unknown_outcome" }],
    ["a 200 that is not JSON", { status: 200, body: "ok" }, { status: "unknown_outcome" }],
    ["401: the session is no longer valid", { status: 401, body: JSON.stringify({ error: { code: "unauthorized" } }) }, { status: "sign_in_required" }],
    ["501", { status: 501, body: JSON.stringify({ error: { code: "not_supported" } }) }, { status: "not_available" }],
    ["an unknown 4xx", { status: 418, body: JSON.stringify({ error: { code: "teapot" } }) }, { status: "rejected", code: "teapot" }],
    ["an unknown 422", { status: 422, body: JSON.stringify({ error: { code: "something_else" } }) }, { status: "rejected", code: "something_else" }],
  ];
  it.each(cases)("%s", async (_name, step, expected) => {
    const t = setup(undefined, step);
    expect(await t.run()).toEqual(expected);
    expect(t.seen).toHaveLength(1);
  });

  it("an unconfigured build (no API) is `not_configured`", async () => {
    const session = new Session();
    expect(await activateReward({ api: createUnconfiguredApi(), session, deviceId: async () => DEVICE }, R1)).toEqual({ status: "not_configured" });
  });

  it("signed out: nothing is requested and no token is fetched", async () => {
    const t = setup();
    t.session.current = null;
    expect(await t.run()).toEqual({ status: "signed_out" });
    expect(t.session.fetched).toEqual([]);
    expect(t.seen).toEqual([]);
  });

  it("no token for the signed-in user: sign in again; the user changed under us: signed out; a refresh that fails: offline; nothing is sent in any of them", async () => {
    const a = setup();
    a.session.token = null;
    expect(await a.run()).toEqual({ status: "sign_in_required" });
    const b = setup();
    b.session.token = null;
    b.session.accessTokenFor = async () => {
      b.session.current = OTHER;
      return null;
    };
    expect(await b.run()).toEqual({ status: "signed_out" });
    const c = setup();
    c.session.throwOnToken = true;
    expect(await c.run()).toEqual({ status: "offline" });
    for (const t of [a, b, c]) expect(t.seen).toEqual([]);
  });

  it("a malformed reward id is refused locally (the server names a reward by a UUID in the path only)", async () => {
    const t = setup();
    expect(await t.run("not-a-uuid")).toEqual({ status: "rejected", code: null });
    expect(await t.run(`${R1}/../x`)).toEqual({ status: "rejected", code: null });
    expect(t.seen).toEqual([]);
  });

  it("the request: POST <base>/rewards-activate/<id lower-case>, the OWNER's token as the bearer, the id in the path and not the body, redirects refused, no cookies", async () => {
    const t = setup(undefined, { respond: "activate_200_held_unattestable_none_ios" });
    await t.run(R1.toUpperCase());
    expect(t.seen[0]).toMatchObject({ url: `${BASE}/rewards-activate/${R1}`, method: "POST", redirect: "error", credentials: "omit" });
    expect(t.seen[0]!.headers.Authorization).toBe(`Bearer ${ownerToken}`);
    expect(t.session.fetched).toEqual([USER]);
    expect(t.seen[0]!.body).toEqual({ deviceId: DEVICE, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } });
    expect(JSON.stringify(t.seen[0]!.body)).not.toContain(R1);
  });

  it("local failures of the attestation are `deferred` with nothing sent; an unsupported platform and an unclassified error have outcomes of their own", async () => {
    const deferring = {
      activate: async () => {
        throw new AttestationDeferred("assertion_unavailable");
      },
    };
    const t = setup(deferring as never, { respond: "activate_200_issued_ios" });
    expect(await t.run()).toEqual({ status: "deferred", reason: "assertion_unavailable" });
    expect(t.seen).toEqual([]);
    expect(await setup(new PlainActivator("web"), { respond: "activate_200_issued_ios" }).run()).toEqual({ status: "unsupported_platform" });
    expect(outcomeFromError(new Error("???"))).toEqual({ status: "failed" });
    expect(outcomeFromError(new ActivationUnsupportedPlatform())).toEqual({ status: "unsupported_platform" });
  });
});

describe("every outcome has copy in both languages, and the retry set is exactly the 'nothing changed / safe to repeat' ones", () => {
  const EXAMPLES: Record<ActivationOutcomeStatus, ActivationOutcome> = {
    activated: { status: "activated", kind: "offer_code", state: "issued", alreadyActive: false },
    held_review: { status: "held_review", kind: "offer_code", alreadyHeld: false },
    unexpected_state: { status: "unexpected_state", state: "x" },
    not_activatable: { status: "not_activatable" },
    expired: { status: "expired" },
    conflict: { status: "conflict" },
    not_found: { status: "not_found" },
    not_allowed: { status: "not_allowed" },
    platform_mismatch: { status: "platform_mismatch" },
    device_limit: { status: "device_limit" },
    challenge_expired: { status: "challenge_expired" },
    rate_limited: { status: "rate_limited", retryAfterSeconds: 60 },
    vendor_unavailable: { status: "vendor_unavailable" },
    not_available: { status: "not_available" },
    sign_in_required: { status: "sign_in_required" },
    signed_out: { status: "signed_out" },
    rejected: { status: "rejected", code: null },
    unknown_outcome: { status: "unknown_outcome" },
    deferred: { status: "deferred", reason: "x" },
    offline: { status: "offline" },
    not_configured: { status: "not_configured" },
    unsupported_platform: { status: "unsupported_platform" },
    failed: { status: "failed" },
  };

  it("all 23 statuses have a line in en and fr-CA (the example table is a Record over the status type, so a new status does not compile until it is listed)", () => {
    expect(Object.keys(EXAMPLES)).toHaveLength(23);
    for (const o of Object.values(EXAMPLES)) {
      const { key, params } = activationMessage(o);
      expect(en[key], o.status).toBeTruthy();
      expect(frCA[key], o.status).toBeTruthy();
      for (const text of [en[key], frCA[key]]) for (const p of [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!)) expect(params, `${o.status} needs {${p}}`).toHaveProperty(p);
    }
    for (const alt of [{ status: "activated", kind: "entitlement", state: "redeemable", alreadyActive: true }, { status: "held_review", kind: "entitlement", alreadyHeld: true }] as ActivationOutcome[]) {
      expect(en[activationMessage(alt).key]).toBeTruthy();
      expect(frCA[activationMessage(alt).key]).toBeTruthy();
    }
  });

  it("retryable: the ones where nothing changed or a repeat is safe; never an activated, held, refused or expired reward", () => {
    const retry = Object.values(EXAMPLES).filter(isRetryableActivation).map((o) => o.status).sort();
    expect(retry).toEqual(["challenge_expired", "conflict", "deferred", "offline", "rate_limited", "unexpected_state", "unknown_outcome", "vendor_unavailable"]);
  });
});

describe("the real client's other new calls", () => {
  it("listEarnedRewards answers [] with NO request (no endpoint lists earned rewards yet), like the other reads", async () => {
    const f = scriptedFetch({ status: 500, body: "" });
    const api = createHttpApiClient({ baseUrl: BASE, fetch: f.fetch, getAccessToken: async () => "t" });
    expect(await api.listEarnedRewards()).toEqual([]);
    expect(f.seen).toEqual([]);
  });

  it("the unconfigured API refuses both network calls with not_configured and lists nothing", async () => {
    const api = createUnconfiguredApi();
    await expect(api.activateReward({ rewardId: R1, deviceId: DEVICE }, { userId: USER, accessToken: "t" })).rejects.toMatchObject({ kind: "not_configured" });
    await expect(api.provisionOfflineSeed({ deviceId: DEVICE }, { userId: USER, accessToken: "t" })).rejects.toMatchObject({ kind: "not_configured" });
    expect(await api.listEarnedRewards()).toEqual([]);
  });
});

describe("FLAGS OFF: nothing of the offline code or the Wallet activation is reachable in a release build", () => {
  const app = [...files(join(root, "src")), ...files(join(root, "app"))];
  const rel = (f: string): string => relative(root, f);
  const users = (needle: RegExp): string[] => app.filter((f) => needle.test(strip(readFileSync(f, "utf8")))).map(rel).sort();

  it("the three switches are literally false", () => {
    expect([CHECKIN_UI_ENABLED, OFFLINE_CODE_UI_ENABLED, WALLET_ACTIVATION_UI_ENABLED, MARKER_COSIGNAL_UI_ENABLED]).toEqual([false, false, false, false]);
    const features = strip(read("src/features.ts"));
    for (const name of ["CHECKIN_UI_ENABLED", "OFFLINE_CODE_UI_ENABLED", "WALLET_ACTIVATION_UI_ENABLED", "MARKER_COSIGNAL_UI_ENABLED"]) expect(features).toMatch(new RegExp(`export const ${name} = false;`));
    expect(features.match(/export const \w+ =/g)).toHaveLength(4);
  });

  it("each switch is read in exactly the places that gate on it", () => {
    expect(users(/\bOFFLINE_CODE_UI_ENABLED\b/)).toEqual(["app/(tabs)/me.tsx", "src/features.ts", "src/offline-code/gate.ts"]);
    expect(users(/\bWALLET_ACTIVATION_UI_ENABLED\b/)).toEqual(["app/(tabs)/wallet.tsx", "src/features.ts"]);
    // P4.2c: the check-in screen reads the switch through `checkinUiAvailable()` (`src/checkin/gate.ts`), the one place besides the prefetch gate; `test/checkin-flag.test.ts` pins the rest.
    expect(users(/\bCHECKIN_UI_ENABLED\b/)).toEqual(["src/challenges/prefetch-gate.ts", "src/checkin/gate.ts", "src/features.ts"]);
    expect(users(/\bMARKER_COSIGNAL_UI_ENABLED\b/)).toEqual(["src/checkin/gate.ts", "src/features.ts"]);
  });

  it("the cards are rendered only behind their switch, and imported by no one else", () => {
    expect(strip(read("app/(tabs)/me.tsx"))).toMatch(/\{OFFLINE_CODE_UI_ENABLED && session \? <OfflineCodeCard \/> : null\}/);
    expect(strip(read("app/(tabs)/wallet.tsx"))).toMatch(/\{WALLET_ACTIVATION_UI_ENABLED \? <EarnedRewards \/> : null\}/);
    expect(users(/\bOfflineCodeCard\b/)).toEqual(["app/(tabs)/me.tsx", "src/screens/OfflineCodeCard.tsx"]);
    expect(users(/\bEarnedRewards\b/)).toEqual(["app/(tabs)/wallet.tsx", "src/screens/EarnedRewards.tsx"]);
  });

  it("the seed is provisioned on its own only through the gate (`provisionOfflineSeedOnLaunch`), whose default is the switch; nothing else calls the manager's provisioning without a player action", () => {
    expect(users(/\bprovisionOfflineSeedOnLaunch\b/)).toEqual(["src/offline-code/gate.ts", "src/runtime/AppProvider.tsx"]);
    expect(strip(read("src/offline-code/gate.ts"))).toMatch(/enabled: boolean = OFFLINE_CODE_UI_ENABLED/);
    expect(users(/\.provisionIfMissing\(/)).toEqual(["src/offline-code/gate.ts"]);
    // the player-initiated callers are the card's two buttons
    expect(users(/offlineCode\.provision\(/)).toEqual(["src/screens/OfflineCodeCard.tsx"]);
  });

  it("an activation is started only by the Wallet card's button: `services.activateReward` has one caller, and the service function is built in one place", () => {
    expect(users(/\bservices\.activateReward\(/)).toEqual(["src/screens/EarnedRewards.tsx"]);
    expect(users(/\.activateReward\(/)).toEqual(["src/rewards/service.ts", "src/screens/EarnedRewards.tsx"]);
    expect(users(/import \{[^}]*\bactivateReward\b[^}]*\} from "\.\.\/rewards"/)).toEqual(["src/runtime/services.ts"]);
  });

  it("the new lanes ship no mock, fixture or test string and never log (a seed or a token must not reach a console)", () => {
    const lane = ["src/offline-code", "src/rewards"].flatMap((d) => files(join(root, d))).concat(join(root, "src/attest/activator.ts"), join(root, "src/screens/OfflineCodeCard.tsx"), join(root, "src/screens/EarnedRewards.tsx"));
    expect(lane.length).toBeGreaterThanOrEqual(15);
    for (const f of lane) {
      const code = strip(readFileSync(f, "utf8"));
      expect(code, rel(f)).not.toMatch(/createMock|MockApi|api\/mock|MOCK_|vitest|\bfixtures?\b|demo[-_]|console\./i);
      expect(code, rel(f)).not.toMatch(/from\s*["'][^"']*\/test\//);
    }
  });
});
