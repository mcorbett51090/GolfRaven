/** Notices: the one place a `Notice` becomes text, and the one element that shows it (`role="alert"` for an error, `role="status"` for anything else). */

import { translate, type Locale, type MessageKey } from "../i18n";
import type { Notice } from "../app/state";
import { h } from "./dom";

const NOTICE_KEY: Record<Exclude<Notice["kind"], "error">, MessageKey> = {
  locked: "notice.locked",
  "signed-out": "notice.signedOut",
  expired: "notice.expired",
  "sign-out-offline": "notice.signOutOffline",
  "lock-offline": "notice.lockOffline",
  "enrol-existing-member": "notice.enrolExistingMember",
  "enrol-recover-required": "notice.enrolRecoverRequired",
  "enrol-saved": "notice.enrolSaved",
  "enrol-code-sent": "notice.enrolCodeSent",
  "pin-set": "notice.pinSet",
  "pin-changed": "notice.pinChanged",
  "totp-confirmed": "notice.totpConfirmed",
  "totp-verified": "notice.totpVerified",
};

export function noticeText(n: Notice, locale: Locale): string {
  if (n.kind === "error") return translate(locale, n.message.key, n.message.params);
  return translate(locale, NOTICE_KEY[n.kind]);
}

export function noticeElement(n: Notice | null, locale: Locale): HTMLElement | null {
  if (n === null) return null;
  return h("p", { class: n.kind === "error" ? "notice error" : "notice", role: n.kind === "error" ? "alert" : "status", "data-testid": "notice" }, noticeText(n, locale));
}
