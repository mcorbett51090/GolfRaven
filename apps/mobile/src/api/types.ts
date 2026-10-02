/**
 * The app's view of the backend, `api.*` (build plan §3.3, §4.7): player-plane
 * reads through `security_invoker` views, plus `POST /v1/evidence`. P4.1 ships
 * only the interface and a mock (`mock.ts`); the Supabase-backed client is
 * P4.2 and replaces the mock without touching a screen.
 */
import type { EvidenceSubmitter } from "../outbox";
import type { ProgrammeStatus } from "../wallet";
import type { SignInProviderId } from "../signin";

export type PlayConfidence = "hard" | "badge" | "pending_verification";

export interface PlaySummary {
  id: string;
  courseId: string;
  /** ISO timestamp. */
  playedAt: string;
  confidence: PlayConfidence;
}

export type AchievementState = "earned" | "in_progress" | "locked";
export interface AchievementSummary {
  id: string;
  name: string;
  state: AchievementState;
  progress?: { k: number; n: number };
}

export interface Session {
  userId: string;
  provider: SignInProviderId;
  /** The mock only: there is no real account behind it. */
  stub: boolean;
}

export interface ApiClient extends EvidenceSubmitter {
  /** Server policy constants the app must not hard-code (`MIN_AGE`, §7.8). */
  getPolicy(): Promise<{ minAge: number }>;
  getSession(): Session | null;
  /** Mock only: stand in for the provider's id-token exchange. */
  startMockSession(provider: SignInProviderId): Session;
  endSession(): void;
  listPlays(): Promise<PlaySummary[]>;
  listAchievements(): Promise<AchievementSummary[]>;
  /** `trail_programme.status` per trail id (O17). */
  listTrailProgrammes(): Promise<Record<string, ProgrammeStatus>>;
}
