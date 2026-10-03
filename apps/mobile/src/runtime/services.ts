/**
 * The composition root: builds every service the screens use from the
 * config + the app database. Everything here is wiring; the logic lives in
 * the modules it composes (and is tested there).
 */
import { fetch as expoFetch } from "expo/fetch";
import {
  AGE_FLAG_KEY,
  AgeGate,
  MemoryDeviceFlagStore,
  SecureDeviceFlagStore,
  SqliteDeviceFlagStore,
  failClosedAgeFlags,
  migrateAgeFlag,
  type DeviceFlagStore,
} from "../age";
import type { ApiClient } from "../api";
import { createAttestation, type AttestStateStore, type Attestor } from "../attest";
import { loadNativeAttestModule } from "../attest/native-module-loader";
import { OfflineCodeManager, OfflineSeedStore, deviceRegistrationFor } from "../offline-code";
import { activateReward, type ActivationOutcome } from "../rewards";
import { ChallengeManager, MemoryChallengeStore, SqliteChallengeStore, type ChallengeStore } from "../challenges";
import { enqueueEvidence, newFixId, type EvidenceEnqueued, type EvidenceInput } from "../evidence";
import { checkinUiAvailable, markerCosignalUiAvailable, picksFromItems, runCheckIn, type CheckInInput, type CheckInOutcome } from "../checkin";
import { createExpoLocationPort } from "../checkin/expo-location";
import { MemoryMarkerCosignalStore, SqliteMarkerCosignalStore, captureMarkerCoSignal, type MarkerCaptureInput, type MarkerCaptureOutcome, type MarkerCosignalStore } from "../marker";
import type { AuthService } from "../auth";
import { createSupabaseAuth } from "../auth/supabase-auth";
import { createExpoFileSharer } from "../account/expo-share";
import type { FileSharer } from "../account";
import { nobleCatalogCrypto } from "../catalog/crypto";
import { resolveTrustAnchors, TRUSTED_KEYSET } from "../catalog/keys";
import { CatalogManager, createFetchBytes } from "../catalog/manager";
import { MemoryCatalogCacheStore, SqliteCatalogCacheStore } from "../catalog/store";
import { readAppConfig, type AppConfig } from "../config";
import { openAppDatabase } from "../db/expo-sqlite-adapter";
import {
  MemoryOutboxStore,
  OutboxRunner,
  SqliteOutboxStore,
  enqueueOutboxItem,
  type OutboxDraft,
  type OutboxItem,
  type OutboxStore,
  type RematchResult,
} from "../outbox";
import { unavailablePushAdapter, type PushAdapter } from "../push";
import { createExpoSecureStore } from "../secure/expo-secure-store";
import type { SecureStore } from "../secure";
import { createExpoAppleAdapter } from "../signin/apple-expo";
import { expoRandomBytes } from "../signin/expo-random";
import { randomUuid } from "../signin/nonce";
import { notConfiguredGoogle, type AppleAdapter, type GoogleAdapter, type RandomBytes } from "../signin";
import { buildIndex } from "../browse";
import { Platform } from "react-native";
import { createBackend, type BackendKind } from "./backend";
import { createDeviceIdProvider } from "./device-id";
import { loadDevMocks } from "./dev-backend";

export interface AppServices {
  config: AppConfig;
  catalog: CatalogManager;
  outboxStore: OutboxStore;
  outboxRunner: OutboxRunner;
  /** The only way the UI adds to the outbox: the owner is the signed-in user (from the auth session), and signed out throws `OutboxEnqueueError`. */
  enqueueOutbox: (draft: OutboxDraft) => ReturnType<typeof enqueueOutboxItem>;
  /** Prefetched check-in challenges, per owner (`challenges/store.ts`). */
  challengeStore: ChallengeStore;
  /** Prefetch and consume check-in challenges (`challenges/manager.ts`). */
  challenges: ChallengeManager;
  /** The device-attestation seam (P4.2b-2): `NativeAttestor` where the local module is linked and the device supports it, `UnattestableAttestor` otherwise
   * (Expo Go, web, an iOS simulator, an Android build with no Play Cloud project number). */
  attestor: Attestor;
  /** What this install remembers about its attestation, per user and device (`attest/state-store.ts`); account deletion wipes the deleted user's. */
  attestState: AttestStateStore;
  /** The offline staff code (P4.2b-3b): provisioning the per-(account, device) seed into the secure store, and the 6-digit code computed from it with no network. Nothing user-visible
   * uses it while `OFFLINE_CODE_UI_ENABLED` is false (`src/features.ts`). */
  offlineCode: OfflineCodeManager;
  /** Activates one earned reward on this device (P4.2b-3b; `POST rewards-activate`) under the assertion lock check-in shares. Never throws. Nothing user-visible uses it while
   * `WALLET_ACTIVATION_UI_ENABLED` is false. */
  activateReward: (rewardId: string) => Promise<ActivationOutcome>;
  /** The foreground check-in (P4.2c, `checkin/flow.ts`): location, matching, challenge, evidence, outbox. Called from the "I'm here" button only; refuses (`disabled`, no prompt) while `CHECKIN_UI_ENABLED` is false. */
  checkin: (input: CheckInInput) => Promise<CheckInOutcome>;
  /** "Buying a marker" (P4.2c, `marker/capture.ts`): captures a co-signal into the LOCAL queue; nothing sends it (no server path yet). Refuses while `MARKER_COSIGNAL_UI_ENABLED` or `CHECKIN_UI_ENABLED` is false. */
  markerCosignal: (input: MarkerCaptureInput) => Promise<MarkerCaptureOutcome>;
  /** The local marker co-signal records (account deletion wipes the deleted user's). */
  markerStore: MarkerCosignalStore;
  /** The only way a play enters the outbox: builds the payload, consumes one challenge per fix, enqueues for the signed-in user. */
  enqueueEvidence: (input: EvidenceInput) => Promise<EvidenceEnqueued>;
  /** The real client, the unconfigured stand-in (release without server config), or, in a `__DEV__` build with none, the demo mock. */
  api: ApiClient;
  auth: AuthService;
  backend: BackendKind;
  /** The dev mock API (a `MockApi`) in the `demo` backend; `null` everywhere else (the dev panel narrows it). */
  devHandle: unknown;
  ageGate: AgeGate;
  /** Preferences (language). NOT the age flag: that is in the secure store (`ageGate`). */
  flags: DeviceFlagStore;
  secure: SecureStore;
  apple: AppleAdapter;
  google: GoogleAdapter;
  random: RandomBytes;
  push: PushAdapter;
  deviceId: () => Promise<string>;
  sharer: FileSharer;
  /** `Platform.OS`. */
  platform: string;
  /** True when the age flag could not be moved to / read from the secure store: sign-in is blocked (fail closed). */
  ageStoreProblem: boolean;
  /** False when SQLite could not be opened and the app fell back to memory. */
  persistent: boolean;
  /** Why the compiled-in keyset was refused (release builds only), or `null`.
   * When set the catalog is untrusted and network refresh is off (fail closed;
   * `resolveTrustAnchors`). */
  keysetProblem: string | null;
}

export async function createServices(): Promise<AppServices> {
  const config = readAppConfig();
  let persistent = true;
  let catalogStore: ConstructorParameters<typeof CatalogManager>[0]["store"];
  let outboxStore: OutboxStore;
  let challengeStore: ChallengeStore;
  let markerStore: MarkerCosignalStore;
  let flags: DeviceFlagStore;
  try {
    const db = await openAppDatabase();
    catalogStore = new SqliteCatalogCacheStore(db);
    outboxStore = new SqliteOutboxStore(db);
    challengeStore = new SqliteChallengeStore(db);
    markerStore = new SqliteMarkerCosignalStore(db);
    flags = new SqliteDeviceFlagStore(db);
  } catch {
    // Never lose the app to a storage failure: browse with a memory cache.
    // (An unopenable database is surfaced in Me → Catalog; plays cannot be
    // recorded safely without persistence, which is why this path is
    // reachable only for guest browse in practice.)
    persistent = false;
    catalogStore = new MemoryCatalogCacheStore();
    outboxStore = new MemoryOutboxStore();
    challengeStore = new MemoryChallengeStore();
    markerStore = new MemoryMarkerCosignalStore();
    flags = new MemoryDeviceFlagStore();
  }

  // LOW-12: `assertReleaseKeyset`, applied without throwing. A release build whose keyset
  // is not releasable (today: empty, until the P3 gate) trusts NOTHING and does not fetch.
  const anchors = resolveTrustAnchors(TRUSTED_KEYSET, __DEV__);

  const catalog = new CatalogManager({
    baseUrl: anchors.problem === null ? config.catalogBaseUrl : null,
    store: catalogStore,
    crypto: nobleCatalogCrypto,
    trustedKeys: anchors.trustedKeys,
    appVersion: config.appVersion,
    supportedContractMajor: config.supportedContractMajor,
    // LOW-C: RN's default `fetch` is believed to expose no body stream, so a byte cap there could
    // only apply AFTER the download. `expo/fetch` streams the body natively, so `createFetchBytes`
    // cancels an over-cap download mid-flight. `[unverified — device: streaming + redirect:"error" on iOS/Android]`
    fetchBytes: createFetchBytes(expoFetch),
  });

  // The secure store holds the session, the age flag and the device id. The age flag used to live in SQLite (`device_flags`): move it once,
  // then delete it from SQLite. If that, or the secure store itself, fails, the age gate FAILS CLOSED (sign-in blocked, guest browse works)
  // rather than reading an unreadable store as "no flag".
  const secure = createExpoSecureStore();
  const secureFlags = new SecureDeviceFlagStore(secure);
  let ageFlags: DeviceFlagStore = secureFlags;
  let ageStoreProblem = false;
  try {
    if (persistent) await migrateAgeFlag(flags, secureFlags);
    await secureFlags.get(AGE_FLAG_KEY); // proves the store is readable before the gate relies on it
  } catch {
    ageFlags = failClosedAgeFlags();
    ageStoreProblem = true;
  }

  const attestation = await createAttestation({
    module: loadNativeAttestModule(),
    platform: Platform.OS,
    playCloudProjectNumber: config.playCloudProjectNumber,
    secure,
  });
  const attestor = attestation.attestor;
  const backend = createBackend({
    evidence: {
      redeemer: attestation.redeemer,
      // The check-in token a send redeems is written into the item's row before the evidence request (crash safety, `evidence/send.ts`).
      persistEvidencePayload: async (item, payload) => {
        const stored = await outboxStore.get(item.id);
        if (stored) await outboxStore.update({ ...stored, payload });
      },
    },
    rewards: { activator: attestation.activator, platform: Platform.OS },
    isDev: __DEV__,
    config,
    secure,
    fetch: expoFetch,
    createAuth: createSupabaseAuth,
    loadDevMocks,
  });
  const api = backend.api;

  // The owner of an outbox item is the Supabase session's user (`AuthService.current()`: the user of the GoTrue session, cleared by sign-out), read
  // fresh at every use. The runner's token comes from the same service and is requested FOR the item's owner (`forUserId`).
  const auth = backend.auth;
  const currentUserId = (): string | null => auth.current()?.userId ?? null;
  const session = {
    currentUserId,
    accessTokenFor: (userId: string, o?: { forceRefresh?: boolean }) => auth.getAccessToken({ forUserId: userId, ...(o?.forceRefresh ? { forceRefresh: true } : {}) }),
  };
  const deviceId = createDeviceIdProvider(secure, expoRandomBytes);
  const challenges = new ChallengeManager({ store: challengeStore, api, session, deviceId, now: () => Date.now() });
  const registerDevice = deviceRegistrationFor(api); // `undefined` while OFFLINE_CODE_UI_ENABLED is false (`offline-code/gate.ts`)
  const offlineCode = new OfflineCodeManager({ store: new OfflineSeedStore(secure), api, session, deviceId, now: () => Date.now(), ...(registerDevice ? { registerDevice } : {}) });
  // Foreground location: constructing the port asks for nothing. The permission prompt is `requestPermission()`, called only from `runCheckIn` / `captureMarkerCoSignal`, i.e. from a button.
  const location = createExpoLocationPort(Platform.OS);
  const enqueueEvidenceNow = (input: EvidenceInput): Promise<EvidenceEnqueued> =>
    enqueueEvidence(
      {
        challenges,
        currentUserId,
        deviceId,
        enqueue: (draft) => enqueueOutboxItem({ store: outboxStore, currentUserId, now: () => Date.now() }, draft),
        existing: (owner) => outboxStore.listByOwner(owner),
        newId: () => randomUuid(expoRandomBytes),
      },
      input,
    );
  const outboxRunner = new OutboxRunner({
    store: outboxStore,
    api,
    session,
    now: () => Date.now(),
    rng: Math.random,
    refreshCatalog: async () => {
      await catalog.refresh();
    },
    // P4.1 STUBS — what they do, and what that means on a device:
    //  * `rematch`: the on-device matcher (`@golfraven/matching`) is wired in a later
    //    slice. Until then a re-match only checks that the stored course still exists in
    //    the current catalog, and it never invents a match. With NO verified snapshot —
    //    which is every build until the production keyset exists, because an empty
    //    keyset verifies nothing — it returns `{ ok: false }`, so a 422 `catalog_stale`
    //    answer DEAD-LETTERS the item (`needs_attention` / `rematch_failed`) rather than
    //    re-matching it.
    //  * `findCourseForUnlisted` always answers `null`: an "Unlisted course" item never
    //    becomes sendable on the device (§7.6, G3-01).
    //  * `resolveQueued` (outbox/machine.ts) has no caller: nothing observes the server
    //    resolving a `queued_catalog` item, so on the device a queued play stays `queued`
    //    (it never becomes `accepted` or `queue_expired`).
    rematch: (item: OutboxItem): Promise<RematchResult> => {
      const snap = catalog.getState().snapshot;
      if (!snap) return Promise.resolve({ ok: false });
      const index = buildIndex(snap);
      const courseId = item.courseId !== null && index.courses.has(item.courseId) ? item.courseId : null;
      return Promise.resolve({ ok: true, courseId, catalogVersion: snap.catalogVersion, payload: item.payload });
    },
    findCourseForUnlisted: () => Promise.resolve(null), // P4.1 STUB, see above
  });

  // A data export left in the cache for the receiving app to read is deleted at the next export and here, at start (`account/export.ts`). Best effort.
  const sharer = createExpoFileSharer();
  void sharer.purgeStale().catch(() => undefined);

  return {
    config,
    catalog,
    outboxStore,
    outboxRunner,
    enqueueOutbox: (draft) => enqueueOutboxItem({ store: outboxStore, currentUserId, now: () => Date.now() }, draft),
    challengeStore,
    challenges,
    attestor,
    attestState: attestation.state,
    offlineCode,
    activateReward: (rewardId) => activateReward({ api, session, deviceId }, rewardId),
    enqueueEvidence: enqueueEvidenceNow,
    checkin: (input) =>
      runCheckIn(
        {
          enabled: checkinUiAvailable(),
          location,
          currentUserId,
          challenges,
          enqueueEvidence: enqueueEvidenceNow,
          existingPicks: async (owner) => picksFromItems(await outboxStore.listByOwner(owner)),
          manifestSig: (catalogVersion) => catalog.cachedManifestSig(catalogVersion),
          newFixId: () => newFixId(expoRandomBytes),
          now: () => Date.now(),
        },
        input,
      ),
    markerCosignal: (input) =>
      captureMarkerCoSignal(
        {
          enabled: markerCosignalUiAvailable(),
          location,
          currentUserId,
          challenges,
          store: markerStore,
          deviceId,
          newId: () => randomUuid(expoRandomBytes),
          newFixId: () => newFixId(expoRandomBytes),
          now: () => Date.now(),
        },
        input,
      ),
    markerStore,
    api,
    auth,
    backend: backend.kind,
    devHandle: backend.devHandle,
    ageGate: new AgeGate(ageFlags),
    flags,
    secure,
    apple: backend.demoAdapters?.apple ?? createExpoAppleAdapter(Platform.OS),
    google: backend.demoAdapters?.google ?? notConfiguredGoogle(),
    random: expoRandomBytes,
    push: unavailablePushAdapter(),
    deviceId,
    sharer,
    platform: Platform.OS,
    ageStoreProblem,
    persistent,
    keysetProblem: anchors.problem,
  };
}
