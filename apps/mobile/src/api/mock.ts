/**
 * An in-memory `ApiClient` for tests and the `__DEV__` demo ("a mock of `api.*`", build plan §10 P4.1). Deterministic and scriptable so tests
 * and the dev panel can drive the §7.6 outbox states and the account endpoints without a server.
 *
 * NEVER constructed in a release build: it needs a `DevOnly` token (`dev-guard.ts`), and nothing imports this file statically
 * (`runtime/dev-backend.ts` `require`s it under `__DEV__`; `api/index.ts` does not re-export it).
 */
import { assertDevOnly, type DevOnly } from "../dev-guard";
import type { OutboxItem, ServerAnswer } from "../outbox";
import type { ProgrammeStatus } from "../wallet";
import { ApiError } from "./errors";
import type {
  AchievementSummary,
  ApiClient,
  DeleteAccountResult,
  ExportResult,
  LinkSignInRequest,
  LinkSignInResult,
  PlaySummary,
  PushTokenRequest,
  PushTokenResult,
  SignInMethod,
  UnlinkSignInResult,
} from "./types";

export interface MockApiOptions {
  minAge?: number;
  plays?: PlaySummary[];
  achievements?: AchievementSummary[];
  programmes?: Record<string, ProgrammeStatus>;
  /** Answers handed out, in order, to `submitEvidence`; then `defaultAnswer`. */
  evidenceScript?: ServerAnswer[];
  defaultAnswer?: ServerAnswer;
  /** The caller's sign-in methods (default: email only). */
  methods?: SignInMethod[];
}

export type MockCall =
  | { op: "link"; req: LinkSignInRequest }
  | { op: "unlink"; provider: string }
  | { op: "delete" }
  | { op: "export" }
  | { op: "push"; req: PushTokenRequest }
  | { op: "list" };

export interface MockApi extends ApiClient {
  /** Every `submitEvidence` call, in order. */
  readonly submissions: readonly OutboxItem[];
  /** Every account call, in order. */
  readonly calls: readonly MockCall[];
  script(...answers: ServerAnswer[]): void;
  /** Make the next account call fail with this error (once). */
  failNext(error: ApiError): void;
  /** Replace what `linkSignInMethod` returns next (once). */
  scriptLink(result: LinkSignInResult): void;
}

const iso = "2026-01-01T00:00:00.000Z";

export function createMockApi(guard: DevOnly, options: MockApiOptions = {}): MockApi {
  assertDevOnly(guard);
  const queue: ServerAnswer[] = [...(options.evidenceScript ?? [])];
  const submissions: OutboxItem[] = [];
  const calls: MockCall[] = [];
  const failures: ApiError[] = [];
  const links: LinkSignInResult[] = [];
  let methods: SignInMethod[] = options.methods ?? [{ provider: "email", linkedAt: iso, isPrivateRelay: false, canUnlink: false }];
  const fallback: ServerAnswer = options.defaultAnswer ?? { kind: "response", status: 201 };
  const refresh = (): void => {
    methods = methods.map((m) => ({ ...m, canUnlink: methods.length > 1 }));
  };
  const maybeFail = (): void => {
    const f = failures.shift();
    if (f) throw f;
  };
  return {
    submissions,
    calls,
    script: (...answers) => void queue.push(...answers),
    failNext: (e) => void failures.push(e),
    scriptLink: (r) => void links.push(r),
    getPolicy: () => Promise.resolve({ minAge: options.minAge ?? 16 }),
    listPlays: () => Promise.resolve([...(options.plays ?? [])]),
    listAchievements: () => Promise.resolve([...(options.achievements ?? [])]),
    listTrailProgrammes: () => Promise.resolve({ ...(options.programmes ?? {}) }),
    submitEvidence(item: OutboxItem): Promise<ServerAnswer> {
      submissions.push(item);
      return Promise.resolve(queue.shift() ?? fallback);
    },
    listSignInMethods() {
      calls.push({ op: "list" });
      maybeFail();
      return Promise.resolve(methods.map((m) => ({ ...m })));
    },
    linkSignInMethod(req): Promise<LinkSignInResult> {
      calls.push({ op: "link", req });
      maybeFail();
      const scripted = links.shift();
      if (scripted) return Promise.resolve(scripted);
      const created = !methods.some((m) => m.provider === req.provider);
      if (created) methods.push({ provider: req.provider, linkedAt: iso, isPrivateRelay: false, canUnlink: true });
      refresh();
      return Promise.resolve({ linked: { provider: "apple", created, isPrivateRelay: false }, linkedTo: "self", methods: methods.map((m) => ({ ...m })) });
    },
    unlinkSignInMethod(provider): Promise<UnlinkSignInResult> {
      calls.push({ op: "unlink", provider });
      maybeFail();
      if (!methods.some((m) => m.provider === provider)) return Promise.reject(new ApiError({ kind: "not_found", status: 404, code: "not_found" }));
      if (methods.length <= 1) return Promise.reject(new ApiError({ kind: "rejected", status: 422, code: "last_sign_in_method" }));
      methods = methods.filter((m) => m.provider !== provider);
      refresh();
      return Promise.resolve({ methods: methods.map((m) => ({ ...m })), revocation: [] });
    },
    deleteAccount(): Promise<DeleteAccountResult> {
      calls.push({ op: "delete" });
      maybeFail();
      return Promise.resolve({ userId: "mock-user", deletedAt: iso, authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [] });
    },
    exportData(): Promise<ExportResult> {
      calls.push({ op: "export" });
      maybeFail();
      return Promise.resolve({ generatedAt: iso, userId: "mock-user", data: { demo: true } });
    },
    registerPushToken(req): Promise<PushTokenResult> {
      calls.push({ op: "push", req });
      maybeFail();
      return Promise.resolve({ deviceId: req.deviceId, updatedAt: iso });
    },
  };
}
