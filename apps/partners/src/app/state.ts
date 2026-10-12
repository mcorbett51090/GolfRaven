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
  PartnerAuthAlarm,
  ReceiptCrossUserPreview,
  ReviewQueueItem,
  ReviewSla,
  SettlementExport,
  SponsorRollup,
  Sponsorship,
  TrailProgramme,
} from "../api/admin-routes";
import type { EnrolmentKind } from "../api/client";
import type { InviteCreated, InviteRole, PartnerInvite } from "../api/invites-routes";
import type {
  CredentialAddNotice,
  CredentialAddNoticeReach,
  MemberRecovered,
  PartnerCredential,
  PartnerMember,
} from "../api/members-routes";
import type {
  AttestKind,
  AttestResult,
  CoursePin,
  CoursePinAlarm,
  CourseStaticPinCap,
  EntitlementQueueRow,
  HandoverMinted,
  MintedToken,
  OfferQueueRow,
  OfferRedeemMode,
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
        | "settlement-exported"
        | "credential-note-saved"
        | "credential-revoked"
        | "credential-added"
        | "member-pin-reset"
        | "member-recovered"
        | "member-revoked"
        | "org-revoke-all"
        | "member-totp-reset"
        | "admin-enrolment"
        | "invite-created"
        | "invite-revoked"
        | "invite-accept-pending"
        | "invite-accepted"
        | "credential-notice-acked";
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

/** U1 blocking interstitial (§93): a credential was added; ack (A0) or revoke then ack (A2). Cannot be dismissed. */
export interface CredentialAddNoticePanel {
  readonly kind: "credential-add-notice";
  readonly notice: CredentialAddNotice;
  readonly busy: boolean;
  /** Inline error / status on the interstitial (distinct from the signed-in home `notice`). */
  readonly panelNotice: Notice | null;
}

export type Panel = PinPromptPanel | PinSetupPanel | EmailProofPanel | TotpPanel | CredentialAddNoticePanel;

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
      readonly alarms: readonly CoursePinAlarm[] | null;
      readonly capAlerts: readonly CourseStaticPinCap[] | null;
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
      /** staff_scan = check-in jti on POST redeem; offline = handle + code + nameConfirmed on POST redeem/offline. */
      readonly mode: OfferRedeemMode;
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
      readonly authAlarms: readonly PartnerAuthAlarm[] | null;
      readonly lastState: string | null;
      /** Signed preview URLs by review id; never log (AT(17) / §51). */
      readonly previews: Readonly<Record<string, ReceiptCrossUserPreview>>;
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
    }
  | {
      readonly kind: "members";
      readonly busy: boolean;
      readonly rows: readonly PartnerMember[] | null;
      /** Unacked credential-add notices for people under reach (§94 / U1 condition 2). Null until load. */
      readonly credentialAddNotices: readonly CredentialAddNoticeReach[] | null;
      /** Plaintext `gr_enr_…` / enrolUrl shown once after recover; cleared on dismiss or leave. Never logged. */
      readonly recovered: MemberRecovered | null;
      /** Optional UTC instant draft for revoke-all credential cut-off (`…Z`). */
      readonly createdAfterDraft: string;
      /** Counts from the last org revoke-all; cleared on dismiss or leave. */
      readonly lastRevokeAll: {
        readonly orgId: string;
        readonly sessions: number;
        readonly credentials: number;
      } | null;
      /** Target user id draft for admin enrolment issue (§87). */
      readonly adminEnrolUserIdDraft: string;
      /** Plaintext `gr_enr_…` / enrolUrl shown once after admin enrolment issue; cleared on dismiss or leave. */
      readonly adminEnrolment: MemberRecovered | null;
    }
  | {
      readonly kind: "invites";
      readonly busy: boolean;
      readonly rows: readonly PartnerInvite[] | null;
      /** Org for list/create (manager/operator membership or admin-picked). */
      readonly orgIdDraft: string;
      readonly emailDraft: string;
      readonly roleDraft: InviteRole;
      /** Plaintext `gr_inv_…` / inviteUrl shown once after create; cleared on dismiss or leave. Never logged. */
      readonly created: InviteCreated | null;
    }
  | {
      readonly kind: "credentials";
      readonly busy: boolean;
      readonly rows: readonly PartnerCredential[] | null;
      readonly lastSavedId: string | null;
      /** null = own passkeys (add + last-active refuse). Set = manage under reach (no add). */
      readonly targetUserId: string | null;
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
      /** True when a `gr_inv_` token is held for branch E accept (§89). The token itself is never in state. */
      readonly pendingInviteAccept: boolean;
    };

export type SignedInState = Extract<AppState, { screen: "signed-in" }>;

/** What a flow needs from the controller: the current state and the one way to change it. */
export interface Host {
  getState(): AppState;
  set(next: AppState): void;
}
