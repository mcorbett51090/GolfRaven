/**
 * Turns a check-in (or a historic import) into an outbox item: the single place a play's `EvidencePayload` is built.
 *
 *  - Fails closed when signed out BEFORE touching a challenge (a challenge is never consumed for nobody).
 *  - For each fix, `ChallengeManager.acquireForFix` consumes exactly one challenge (or reports why there is none); a duplicate of an item already
 *    in the outbox (same `sourceRef`, derived like the server's) consumes nothing and returns the existing item.
 *  - The owner of the item is the signed-in user, taken inside `enqueueOutboxItem`; this module never chooses it.
 */
import type { ChallengeManager } from "../challenges";
import { bytesToBase64Url } from "../attest/binding";
import { OutboxEnqueueError, type InsertResult, type OutboxDraft, type OutboxItem } from "../outbox";
import type { RandomBytes } from "../signin/nonce";
import {
  EVIDENCE_PAYLOAD_VERSION,
  buildEvidenceBody,
  evidencePenaltyApplies,
  fixesOf,
  parseEvidencePayload,
  toJsonValue,
  type EvidencePayload,
  type FixChallenge,
  type FixTemplate,
  type SubmissionTemplate,
} from "./payload";
import { deriveEvidenceSourceRef } from "./source-ref";

export interface EvidenceEnqueueDeps {
  challenges: Pick<ChallengeManager, "acquireForFix">;
  currentUserId: () => string | null;
  deviceId: () => Promise<string>;
  /** The outbox write (`enqueueOutboxItem` bound to the store and the session). */
  enqueue: (draft: OutboxDraft) => Promise<InsertResult>;
  /** The owner's existing items, to recognise a duplicate before a challenge is spent on it. */
  existing: (ownerUserId: string) => Promise<readonly OutboxItem[]>;
  newId: () => string;
}

export interface EvidenceInput {
  origin: "live" | "import";
  facilityId: string;
  /** A listed course: the evidence endpoint needs one (an "Unlisted course" play is enqueued by the matcher flow, G3-01). */
  courseId: string;
  /** The `yyyymmdd-gitsha7` site version the match was made against. */
  catalogVersion: string;
  localDate: string;
  submission: SubmissionTemplate;
  manifestSig?: EvidencePayload["manifestSig"];
  /** Online: ask for a live challenge first. NOT for a fix that was already taken (the live challenge would be issued after the fix, outside its window: see
   * `AcquireOptions.live`); use `challenge` for that. */
  live?: boolean;
  /** P4.2c: a challenge acquired BEFORE the fix was taken (`ChallengeManager.acquireLive`, or `none`), used for the one fix of a `foreground_checkin` instead of
   * asking the manager. Refused for any other source (a dwell has two fixes and each needs its own single-use challenge). */
  challenge?: FixChallenge;
  /** P4.2c-1: whose challenge `challenge` is and which device it was issued to (`LiveChallenge.ownerUserId` / `.deviceId`). Required with `challenge`: it is refused for any other signed-in user or device. */
  challengeFor?: { ownerUserId: string; deviceId: string };
  /** P4.2c-1: the user the caller started this play for (a check-in binds the owner for its whole run: the fix can take seconds). When present and not the signed-in user NOW, nothing is
   * written and no challenge is spent (`OutboxEnqueueError("account_changed")`). */
  owner?: string;
}

export interface EvidenceEnqueued {
  inserted: boolean;
  item: OutboxItem;
  /** True when some fix of the item goes with no challenge (the server applies the x0.6 penalty). */
  penalty: boolean;
}

export function newFixId(random: RandomBytes): string {
  return bytesToBase64Url(random(16));
}

export async function enqueueEvidence(deps: EvidenceEnqueueDeps, input: EvidenceInput): Promise<EvidenceEnqueued> {
  const owner = deps.currentUserId();
  if (owner === null || owner === "") throw new OutboxEnqueueError("signed_out");
  if (input.owner !== undefined && input.owner !== owner) throw new OutboxEnqueueError("account_changed");
  const deviceId = await deps.deviceId();
  if (input.challenge !== undefined) {
    if (input.submission.source !== "foreground_checkin") throw new Error("a pre-acquired challenge covers the one fix of a foreground_checkin only");
    if (input.challengeFor === undefined) throw new Error("a pre-acquired challenge must name its owner and device");
    if (input.challengeFor.ownerUserId !== owner) throw new OutboxEnqueueError("account_changed");
    if (input.challengeFor.deviceId !== deviceId) throw new Error("the pre-acquired challenge was issued to another device");
  }
  const fixes: FixTemplate[] = fixesOf(input.submission);
  if (input.origin === "import" && fixes.length > 0) throw new Error("a historic import carries no fixes");

  // Build the body once with no challenges to learn the sourceRef (it does not depend on them) and to refuse an unsendable shape early.
  const base: EvidencePayload = {
    v: EVIDENCE_PAYLOAD_VERSION,
    origin: input.origin,
    deviceId,
    facilityId: input.facilityId,
    localDate: input.localDate,
    ...(input.manifestSig ? { manifestSig: input.manifestSig } : {}),
    submission: input.submission,
    challenges: Object.fromEntries(fixes.map((f): [string, FixChallenge] => [f.fixId, { state: "none", reason: "none_available" }])),
  };
  const checked = parseEvidencePayload(base);
  if (!checked.ok) throw new Error(checked.message);
  const built = buildEvidenceBody({ courseId: input.courseId, catalogVersion: input.catalogVersion }, checked.payload);
  if (!built.ok) throw new Error(built.message);
  const sourceRef = deriveEvidenceSourceRef(built.body);

  const dup = (await deps.existing(owner)).find((i) => i.sourceRef === sourceRef);
  if (dup) return { inserted: false, item: dup, penalty: penaltyOf(dup) };

  const challenges: Record<string, FixChallenge> = {};
  for (const f of fixes) {
    challenges[f.fixId] = input.challenge ?? (await deps.challenges.acquireForFix(owner, f.capturedAt, { live: input.live ?? false, facilityId: input.facilityId }));
  }
  const payload: EvidencePayload = { ...base, challenges };
  const result = await deps.enqueue({ id: deps.newId(), sourceRef, courseId: input.courseId, catalogVersion: input.catalogVersion, payload: toJsonValue(payload) });
  return { inserted: result.inserted, item: result.item, penalty: evidencePenaltyApplies(payload) };
}

function penaltyOf(item: OutboxItem): boolean {
  const p = parseEvidencePayload(item.payload);
  return p.ok && evidencePenaltyApplies(p.payload);
}
