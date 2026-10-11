/**
 * Review auth-alarms row labels (§96): closed kind → catalogue key; unknown kinds stay raw.
 * Optional `detail.subject` (uuid text) for totp_reset / credential_add rows without a credential id.
 */

import { translate, type Locale, type MessageKey } from "../i18n";
import { en } from "../i18n/messages/en";

export function authAlarmKindLabel(locale: Locale, kind: string): string {
  const key = `review.authAlarms.kind.${kind}`;
  if (Object.hasOwn(en, key)) return translate(locale, key as MessageKey);
  return kind;
}

/** First 8 chars of `detail.subject` when present; never invents a value. */
export function authAlarmSubjectPrefix(detail: unknown): string | null {
  if (detail === null || typeof detail !== "object" || Array.isArray(detail)) return null;
  const subject = (detail as Record<string, unknown>)["subject"];
  return typeof subject === "string" && subject.length > 0 ? subject.slice(0, 8) : null;
}
