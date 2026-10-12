/**
 * P5 §52: parse a course-QR universal link into the parts the player lane will eventually hand to
 * `POST marker-scan` (design "Course QR token format"; Edge `_shared/course-qr/format.ts`).
 *
 * Pure string work. No CAMERA and no network. Paste / OS-camera → open-URL / associatedDomains
 * (P5 §54) all land here first. Malformed input is `null` (one refusal; no probeable distinction).
 */

export type ParsedCourseQrLink =
  | { kind: "rotating"; token: string }
  | { kind: "static_pin"; facilitySlug: string; kid: string; sig: string };

const PATH_ROTATING = /^\/q\/m\/?$/i;
const PATH_STATIC = /^\/q\/f\/([^/]+)\/?$/i;
/** Same kid shape the Edge format module accepts. */
const KID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** Ed25519 sig is 64 bytes → 86 unpadded base64url chars. */
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** Rotating token is a compact JWS: three unpadded base64url segments. */
const TOKEN_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_TOKEN_CHARS = 640;

/**
 * Parse `https://…/q/m#<token>` or `https://…/q/f/<slug>#<kid>.<sig>`.
 * Host is not pinned (preview / staging / production share the path contract); scheme must be https.
 */
export function parseCourseQrLink(raw: string): ParsedCourseQrLink | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (PATH_ROTATING.test(url.pathname)) {
    const token = url.hash.startsWith("#") ? url.hash.slice(1) : "";
    if (token.length === 0 || token.length > MAX_TOKEN_CHARS || !TOKEN_RE.test(token)) return null;
    return { kind: "rotating", token };
  }
  const m = PATH_STATIC.exec(url.pathname);
  if (m === null) return null;
  const facilitySlug = decodeURIComponent(m[1] ?? "");
  if (!SLUG_RE.test(facilitySlug)) return null;
  const frag = url.hash.startsWith("#") ? url.hash.slice(1) : "";
  const dot = frag.indexOf(".");
  if (dot <= 0 || dot === frag.length - 1) return null;
  const kid = frag.slice(0, dot);
  const sig = frag.slice(dot + 1);
  if (!KID_RE.test(kid) || !SIG_RE.test(sig)) return null;
  return { kind: "static_pin", facilitySlug, kid, sig };
}
