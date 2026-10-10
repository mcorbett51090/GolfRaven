/**
 * The app's state types, in one DOM-free file so the controller, its flows and the renderer share them without importing each other.
 *
 * The session token is not here (it is inside the API client's closure). Neither are the digits of a PIN, an emailed code, an invite token or a
 * challenge: those are held by a flow only for the length of one call, and what is drawn is only "which step, busy or not, which notice".
 */

import type {
  FacilityProgramme,
  OfferAdmin,
  OperatorRollup,
  ReviewQueueItem,
  ReviewSla,
  SettlementExport,
  SponsorRollup,
  Sponsorship,
  TrailProgramme,
} from "../api/admin-routes";
import type { EnrolmentKind } from "../api/client";
import type {
  AttestKind,
  AttestResult,
  CoursePin,
  EntitlementQueueRow,
  HandoverMinted,
  MintedToken,
  OfferQueueRow,
  OfferRedeemResult,
  PrintedQr,
  RedeemMethod,
  RedeemResult,
  ShiftLogEntry,
  StaffActivityRow,
  StockRow,
} from "../api/work-routes";
import type { SessionGrant, TotpEnrolment, WhoAmI } from "../api/types";
import type { ActionClass, PinProblem } from "../auth/step-up";
import type { PinSetupMode } from "../auth/pin-setup";
import type { UiMessage } from "./messages";

export type Notice =
  | { readonly kind: "locked" | "signed-out" | "expired" | "sign-out-offline" | "lock-offline" }
  /** Outcomes of accepting an invite or enrolment: already a member with a passkey, needs a manager's recovery, passkey saved but the first session could not be shown, or a code was sent. */
  | { readonly kind: "enrol-existing-member" | "enrol-recover-required" | "enrol-saved" | "enrol-code-sent" }
  /** Success notices of the signed-in screens. */
  | {
      readonly kind:
        | "pin-set"
        | "pin-changed"
        | "totp-confirmed"
        | "totp-verified"
        | "attest-ok"
        | "pin-rotated"
        | "token-minted"
        | "printed-ok"
        | "stock-moved"
        | "handover-minted"
        | "redeem-ok"
        | "voucher-ok"
        | "programme-saved"
        | "offer-saved"
        | "offer-approved"
        | "offer-ended"
        | "sponsorship-saved"
        | "sponsorship-approved"
        | "review-resolved"
        | "offer-redeem-ok"
        | "settlement-exported";
    }
  | { readonly kind: "error"; readonly message: UiMessage };

/** Which step of accepting an invite or an enrolment token the person is on. `token`: asks for the token (or, when it came in a link, for a press of "email me a code"). */
export interface EnrolState {
  readonly screen: "enrol";
  readonly step: "token" | "code" | "passkey";
  /** The token is held privately (it came in a link or was accepted): the page does not draw it. */
  readonly hasToken: boolean;
  readonly kind: EnrolmentKind | null;
  readonly busy: boolean;
  readonly notice: Notice | null;
}

/** A PIN prompt opened by `requirePin` (an A1 or A2 action asks for the person's PIN). */
export interface PinPromptPanel {
  readonly kind: "pin-prompt";
  readonly actionClass: ActionClass;
  readonly problem: PinProblem | null;
  readonly retryAfterSeconds: number;
  /** The PIN was submitted and is being derived and checked. */
  readonly busy: boolean;
}

/** Setting a first PIN (or a new one after a reset) or changing one. `forced`: the first PIN after an enrolment, which cannot be skipped. */
export interface PinSetupPanel {
  readonly kind: "pin-setup";
  readonly mode: Exclude<PinSetupMode, "locked">;
  readonly forced: boolean;
  /** A forced first PIN may be left once the server has refused to give THIS person a PIN (an operator or admin has none). */
  readonly canSkip: boolean;
  readonly busy: boolean;
  readonly notice: Notice | null;
}

/** The email proof (a one-time code to the member's own address) that a PIN set or change, or a first TOTP enrolment, needs when the session has no enrolment window. */
export interface EmailProofPanel {
  readonly kind: "email-proof";
  readonly step: "send" | "code";
  readonly purpose: "pin" | "totp";
  readonly busy: boolean;
  readonly notice: Notice | null;
}

/** The second factor of operators and admins: enter the current code, or enrol an authenticator first. */
export interface TotpPanel {
  readonly kind: "totp";
  readonly step: "verify" | "enrol-start" | "enrol-confirm";
  /** The seed, shown once while the person adds it to an authenticator app; dropped when the panel closes. */
  readonly enrolment: TotpEnrolment | null;
  readonly busy: boolean;
  readonly notice: Notice | null;
}

export type Panel = PinPromptPanel | PinSetupPanel | EmailProofPanel | TotpPanel;

/** The S7b–S7 work screens drawn in place of the signed-in home (design 24.3 → S7b/S7c/S7d/S7). `null` means home. */
export type WorkView =
  | {
      readonly kind: "attest";
      readonly facilityId: string;
      readonly mode: "online" | "offline";
      readonly attestKind: AttestKind;
      readonly busy: boolean;
      readonly lastResult: AttestResult | null;
      readonly shiftLog: readonly ShiftLogEntry[] | null;
      readonly staffActivity: readonly StaffActivityRow[] | null;
    }
  | {
      readonly kind: "course-qr";
      readonly facilityId: string;
      readonly busy: boolean;
      readonly pin: CoursePin | null;
      readonly sale: MintedToken | null;
      readonly refreshLeft: number | null;
      readonly printed: PrintedQr | null;
    }
  | {
      readonly kind: "stock";
      readonly facilityId: string;
      readonly busy: boolean;
      readonly rows: readonly StockRow[] | null;
      readonly lastOnHand: number | null;
    }
  | {
      readonly kind: "handover";
      readonly facilityId: string;
      readonly busy: boolean;
      readonly queue: readonly EntitlementQueueRow[] | null;
      /** Plaintext `gr_ho_…` shown once after mint; cleared when the person leaves or dismisses. Never logged. */
      readonly minted: HandoverMinted | null;
      readonly redeemMethod: RedeemMethod;
      readonly lastRedeem: RedeemResult | null;
    }
  | {
      readonly kind: "offer-redeem";
      readonly facilityId: string;
      readonly busy: boolean;
      readonly queue: readonly OfferQueueRow[] | null;
      /** Offer code id chosen from the queue (or typed); cleared after a successful redeem. */
      readonly selectedOfferCodeId: string;
      readonly lastRedeem: OfferRedeemResult | null;
    }
  | {
      readonly kind: "programme";
      readonly trailId: string;
      readonly busy: boolean;
      readonly trail: TrailProgramme | null;
      readonly facilities: readonly FacilityProgramme[] | null;
    }
  | {
      readonly kind: "offers";
      readonly trailId: string;
      readonly busy: boolean;
      readonly offers: readonly OfferAdmin[] | null;
      readonly lastId: string | null;
    }
  | {
      readonly kind: "sponsorships";
      readonly trailId: string;
      readonly busy: boolean;
      readonly sponsorships: readonly Sponsorship[] | null;
      readonly lastId: string | null;
    }
  | {
      readonly kind: "review";
      readonly busy: boolean;
      readonly items: readonly ReviewQueueItem[] | null;
      readonly sla: ReviewSla | null;
      readonly lastState: string | null;
    }
  | {
      readonly kind: "rollups";
      readonly trailId: string;
      readonly sponsorshipId: string;
      readonly busy: boolean;
      readonly operator: readonly OperatorRollup[] | null;
      readonly sponsor: readonly SponsorRollup[] | null;
    }
  | {
      readonly kind: "settlement";
      readonly trailId: string;
      readonly month: string;
      readonly busy: boolean;
      /** Signed URL held only for display; never logged (AT(17)). */
      readonly export: SettlementExport | null;
    };

export type AppState =
  /** `retryUntilMs`: after a 429 with a readable Retry-After, the sign-in button stays disabled until this time (epoch ms). */
  | { readonly screen: "signed-out"; readonly notice: Notice | null; readonly retryUntilMs?: number }
  | { readonly screen: "signing-in" }
  | EnrolState
  | {
      readonly screen: "signed-in";
      readonly grant: SessionGrant;
      readonly session: WhoAmI;
      /** "refresh": a `GET session`; "panel": reading what a panel needs to open; "work": an A1/A2/A3 action on a work screen. */
      readonly busy: "refresh" | "panel" | "work" | null;
      readonly notice: Notice | null;
      /** What is drawn instead of the home / work screen, or null. */
      readonly panel: Panel | null;
      /** Shop-floor or manager/operator/admin work; null draws the home screen. */
      readonly work: WorkView | null;
    };

export type SignedInState = Extract<AppState, { screen: "signed-in" }>;

/** What a flow needs from the controller: the current state and the one way to change it. */
export interface Host {
  getState(): AppState;
  set(next: AppState): void;
}
