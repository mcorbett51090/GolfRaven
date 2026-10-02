/**
 * An in-memory `ApiClient` for P4.1 ("a mock of `api.*`", build plan §10
 * P4.1). Deterministic and scriptable so tests and the dev panel can drive
 * the §7.6 outbox states without a server.
 */
import type { OutboxItem, ServerAnswer } from "../outbox";
import type { SignInProviderId } from "../signin";
import type { ProgrammeStatus } from "../wallet";
import type { AchievementSummary, ApiClient, PlaySummary, Session } from "./types";

export interface MockApiOptions {
  minAge?: number;
  plays?: PlaySummary[];
  achievements?: AchievementSummary[];
  programmes?: Record<string, ProgrammeStatus>;
  /** Answers handed out, in order, to `submitEvidence`; then `defaultAnswer`. */
  evidenceScript?: ServerAnswer[];
  defaultAnswer?: ServerAnswer;
}

export interface MockApi extends ApiClient {
  /** Every `submitEvidence` call, in order. */
  readonly submissions: readonly OutboxItem[];
  script(...answers: ServerAnswer[]): void;
}

export function createMockApi(options: MockApiOptions = {}): MockApi {
  let session: Session | null = null;
  const queue: ServerAnswer[] = [...(options.evidenceScript ?? [])];
  const submissions: OutboxItem[] = [];
  const fallback: ServerAnswer = options.defaultAnswer ?? { kind: "response", status: 201 };
  return {
    submissions,
    script: (...answers) => void queue.push(...answers),
    getPolicy: () => Promise.resolve({ minAge: options.minAge ?? 16 }),
    getSession: () => session,
    startMockSession(provider: SignInProviderId): Session {
      session = { userId: `mock-user-${provider}`, provider, stub: true };
      return session;
    },
    endSession() {
      session = null;
    },
    listPlays: () => Promise.resolve(session ? [...(options.plays ?? [])] : []),
    listAchievements: () => Promise.resolve(session ? [...(options.achievements ?? [])] : []),
    listTrailProgrammes: () => Promise.resolve({ ...(options.programmes ?? {}) }),
    submitEvidence(item: OutboxItem): Promise<ServerAnswer> {
      submissions.push(item);
      return Promise.resolve(queue.shift() ?? fallback);
    },
  };
}
