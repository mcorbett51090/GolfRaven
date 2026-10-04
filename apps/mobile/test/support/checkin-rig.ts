/** Test doubles and builders for the P4.2c check-in and marker tests: a catalog with facilities at known coordinates, a scriptable `LocationPort`, a challenge API that can go offline, and
 * a rig that wires the REAL challenge manager / store, `enqueueEvidence` and outbox store around them. */
import type { Facility } from "@golfraven/catalog";
import { ApiError, type CheckinApi, type CheckinChallengeRequest, type CheckinTokenResult, type IssuedChallenge } from "../../src/api";
import { buildIndex, type CatalogIndex, type CourseEntry } from "../../src/browse";
import { ChallengeManager, MemoryChallengeStore, type ChallengeStore } from "../../src/challenges";
import { CHECKIN_TIMING, picksFromItems, runCheckIn, type CheckInDeps, type FixAttempt, type LocationPermission, type LocationPort } from "../../src/checkin";
import { enqueueEvidence, type EvidenceInput } from "../../src/evidence";
import { MemoryOutboxStore, enqueueOutboxItem, type OutboxStore } from "../../src/outbox";

export const DEVICE = "11111111-1111-4111-8111-111111111111";
export const SITE_VERSION = "20260520-a000001";
/** 2026-06-01 12:00 in America/Chicago (17:00Z). */
export const NOW0 = Date.parse("2026-06-01T17:00:00.000Z");
export const NASHVILLE = { lat: 36.1467, lng: -86.7816 };

export function facility(o: { id?: string; lat?: number | null; lng?: number | null; status?: "unverified" | "listed-verified" | "play-verified"; approx?: boolean; tz?: string; courses?: { id: string; holes?: number }[]; name?: string } = {}): Facility {
  const status = o.status ?? "listed-verified";
  const f: Record<string, unknown> = {
    id: o.id ?? "fac_x",
    slug: (o.id ?? "fac_x").replace("fac_", "f-"),
    region: "US-TN",
    tz: o.tz ?? "America/Chicago",
    name: o.name ?? "Test Golf Club",
    verification: status === "unverified" ? { status } : { status, basis: "operator-source", verifiedAt: "2026-05-01", source: { url: "https://example.test", retrievedAt: "2026-05-01" } },
    seed: { origin: "osm" },
    booking: [],
    courses: (o.courses ?? [{ id: "crs_x1", holes: 18 }]).map((c) => ({ id: c.id, slug: c.id.replace("crs_", "c-"), ...(c.holes !== undefined ? { holes: c.holes } : {}) })),
  };
  if (o.lat !== null) f["lat"] = o.lat ?? NASHVILLE.lat;
  if (o.lng !== null) f["lng"] = o.lng ?? NASHVILLE.lng;
  if (o.approx !== undefined) f["approx"] = o.approx;
  return f as unknown as Facility;
}

export const entryOf = (f: Facility, i = 0): CourseEntry => ({ course: f.courses[i]!, facility: f });

export function indexOf(...facilities: Facility[]): CatalogIndex {
  return buildIndex({ catalogVersion: SITE_VERSION, generatedAt: "2026-05-20T00:00:00.000Z", trails: [], facilities });
}

/** A RawFix at the facility, `t` ms. */
export const rawFix = (t: number, over: Partial<{ latitude: number; longitude: number; accuracyMeters: number | null; simulated: boolean }> = {}) => ({
  latitude: NASHVILLE.lat,
  longitude: NASHVILLE.lng,
  accuracyMeters: 8 as number | null,
  timestamp: t,
  simulated: false,
  ...over,
});

export class FakeLocation implements LocationPort {
  perm: LocationPermission = { status: "granted", approximate: false };
  /** What the system prompt answers when `permission()` was `undetermined`. */
  prompt: LocationPermission = { status: "granted", approximate: false };
  services = true;
  fixes: FixAttempt[] = [];
  readonly calls = { permission: 0, request: 0, services: 0, fix: 0 };
  /** Resolves a pending `currentFix` by hand (a fix that takes a while). */
  onFix: (() => Promise<void>) | null = null;
  permission(): Promise<LocationPermission> {
    this.calls.permission += 1;
    return Promise.resolve(this.perm);
  }
  requestPermission(): Promise<LocationPermission> {
    this.calls.request += 1;
    this.perm = this.prompt;
    return Promise.resolve(this.prompt);
  }
  servicesEnabled(): Promise<boolean> {
    this.calls.services += 1;
    return Promise.resolve(this.services);
  }
  async currentFix(): Promise<FixAttempt> {
    this.calls.fix += 1;
    if (this.onFix) await this.onFix();
    const next = this.fixes.length > 1 ? this.fixes.shift()! : this.fixes[0];
    return next ?? { ok: false, reason: "unavailable" };
  }
}

/** The challenge endpoints, scriptable and able to go offline (`online = false` rejects like a transport failure). */
export class FakeCheckinApi implements CheckinApi {
  online = true;
  readonly requests: CheckinChallengeRequest[] = [];
  readonly redeemed: string[] = [];
  /** The clock the challenges are stamped with (the server's `issued_at`). */
  issueAt: () => number = () => NOW0;
  private n = 0;
  failRedeem: ApiError | null = null;
  requestCheckinChallenges(req: CheckinChallengeRequest): Promise<IssuedChallenge[]> {
    this.requests.push(req);
    if (!this.online) return Promise.reject(new ApiError({ kind: "network", message: "offline" }));
    const count = req.prefetchCount ?? 0;
    const at = this.issueAt();
    if (count === 0) {
      this.n += 1;
      return Promise.resolve([{ id: `live${this.n}`, nonce: `bGl2ZW5vbmNl${this.n}`, expiresAt: new Date(at + 120_000).toISOString(), kind: "live" }]);
    }
    return Promise.resolve(
      Array.from({ length: count }, () => {
        this.n += 1;
        return { id: `pre${this.n}`, nonce: `cHJlbm9uY2U${this.n}`, expiresAt: new Date(at + 24 * 3600_000).toISOString(), kind: "prefetched" as const };
      }),
    );
  }
  redeemCheckinChallenge(req: { challengeId: string }): Promise<CheckinTokenResult> {
    if (!this.online) return Promise.reject(new ApiError({ kind: "network", message: "offline" }));
    if (this.failRedeem) return Promise.reject(this.failRedeem);
    this.redeemed.push(req.challengeId);
    return Promise.resolve({ jti: `jti_${req.challengeId}`, expiresAt: new Date(NOW0 + 900_000).toISOString(), attestationGrade: "unattestable" });
  }
}

export interface Rig {
  clock: { now: number };
  who: { user: string | null };
  location: FakeLocation;
  api: FakeCheckinApi;
  challengeStore: ChallengeStore;
  challenges: ChallengeManager;
  outbox: OutboxStore;
  enqueued: EvidenceInput[];
  enqueue: (input: EvidenceInput) => ReturnType<typeof enqueueEvidence>;
  deps: (over?: Partial<CheckInDeps>) => CheckInDeps;
  fixIds: string[];
  /** Puts `n` prefetched challenges in the signed-in user's pool, received at `at` and expiring `ttl` later (the store stamps its own `issuedAt` = `at`). */
  seedPool: (n: number, at?: number, ttl?: number, prefix?: string) => Promise<number>;
  run: (entry: CourseEntry, over?: Partial<CheckInDeps>, extra?: { index?: CatalogIndex | null; catalogVersion?: string }) => ReturnType<typeof runCheckIn>;
}

export function makeRig(o: { challengeStore?: ChallengeStore; outbox?: OutboxStore; user?: string | null } = {}): Rig {
  const clock = { now: NOW0 };
  const who = { user: o.user === undefined ? "user-a" : o.user };
  const location = new FakeLocation();
  const api = new FakeCheckinApi();
  api.issueAt = () => clock.now;
  const challengeStore = o.challengeStore ?? new MemoryChallengeStore();
  const outbox = o.outbox ?? new MemoryOutboxStore();
  const session = {
    currentUserId: () => who.user,
    accessTokenFor: (u: string) => Promise.resolve(who.user === u ? `token-${u}` : null),
  };
  const challenges = new ChallengeManager({ store: challengeStore, api, session, deviceId: () => Promise.resolve(DEVICE), now: () => clock.now });
  const enqueued: EvidenceInput[] = [];
  let ids = 0;
  const enqueue = (input: EvidenceInput): ReturnType<typeof enqueueEvidence> => {
    enqueued.push(input);
    return enqueueEvidence(
      {
        challenges,
        currentUserId: () => who.user,
        deviceId: () => Promise.resolve(DEVICE),
        enqueue: (draft) => enqueueOutboxItem({ store: outbox, currentUserId: () => who.user, now: () => clock.now }, draft),
        existing: (owner) => outbox.listByOwner(owner),
        newId: () => `item-${(ids += 1)}`,
      },
      input,
    );
  };
  const fixIds: string[] = [];
  let fx = 0;
  const deps = (over: Partial<CheckInDeps> = {}): CheckInDeps => ({
    enabled: true,
    location,
    currentUserId: () => who.user,
    challenges,
    enqueueEvidence: enqueue,
    existingPicks: async (owner) => picksFromItems(await outbox.listByOwner(owner)),
    manifestSig: () => Promise.resolve(null),
    newFixId: () => {
      fx += 1;
      const id = `fixId${fx}`;
      fixIds.push(id);
      return id;
    },
    now: () => clock.now,
    timing: { ...CHECKIN_TIMING, liveBudgetMs: 2_000 },
    ...over,
  });
  return {
    clock,
    who,
    location,
    api,
    challengeStore,
    challenges,
    outbox,
    enqueued,
    enqueue,
    deps,
    fixIds,
    seedPool: (n, at = clock.now, ttl = 24 * 3600_000, prefix = "pool") =>
      challengeStore.insertMany(
        who.user ?? "user-a",
        DEVICE,
        Array.from({ length: n }, (_, i) => ({ id: `${prefix}${i + 1}`, nonce: `cG9vbG5vbmNl${i + 1}`, kind: "prefetched" as const, facilityId: null, expiresAt: at + ttl })),
        at,
      ),
    run: (entry, over, extra) => runCheckIn(deps(over), { entry, catalogVersion: extra?.catalogVersion ?? SITE_VERSION, index: extra?.index ?? null }),
  };
}
