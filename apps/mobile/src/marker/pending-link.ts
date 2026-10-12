/**
 * P5 §54: park a course-QR universal link opened via associatedDomains / App Links
 * (or a future custom scheme) until the facility MarkerCard can paste it into the
 * scan field. No network, no CAMERA, no location prompt — park only.
 *
 * In-memory for the process lifetime. Cleared on take. Malformed input is ignored
 * (same refusal as `parseCourseQrLink`).
 */
import { parseCourseQrLink } from "./link";

let pending: string | null = null;

/** Park a raw URL if it parses as a course QR link. Returns whether it was parked. */
export function parkCourseQrLink(raw: string): boolean {
  if (parseCourseQrLink(raw) === null) return false;
  pending = raw.trim();
  return true;
}

/** Peek without clearing. */
export function peekCourseQrLink(): string | null {
  return pending;
}

/** Take and clear. */
export function takeCourseQrLink(): string | null {
  const out = pending;
  pending = null;
  return out;
}

/** Test helper. */
export function clearCourseQrLink(): void {
  pending = null;
}
