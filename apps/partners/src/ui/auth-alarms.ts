/**
 * Review auth-alarms row labels (§96): closed kind → catalogue key; unknown kinds stay raw.
 * Optional `detail.subject` (person uid) or `detail.org` (org id) for credential-less rows.
 */

import { translate, type Locale, type MessageKey } from "../i18n";
import { en } from "../i18n/messages/en";

export function authAlarmKindLabel(locale: Locale, kind: string): string {
  const key = `review.authAlarms.kind.${kind}`;
  if (Object.hasOwn(en, key)) return translate(locale, key as MessageKey);
  return kind;
}

/** First 8 chars of `detail.subject` or `detail.org` when present; never invents a value. */
export function authAlarmSubjectPrefix(detail: unknown): string | null {
  if (detail === null || typeof detail !== "object" || Array.isArray(detail)) return null;
  const record = detail as Record<string, unknown>;
  const subject = record["subject"] ?? record["org"];
  return typeof subject === "string" && subject.length > 0 ? subject.slice(0, 8) : null;
}
