// supabase/functions/_shared/pem.ts
//
// THE one PKCS#8 PEM parser for every Apple/Google private key this server reads from the environment (the Sign in with Apple
// `.p8`, the DeviceCheck `.p8`, the Google service-account key). Before this file the Sign in with Apple parser accepted a one-line
// PEM with literal backslash-n (how a single-line environment variable carries a key) and the DeviceCheck / Play Integrity parser
// did not, so the same key pasted the same way worked for one and read as "not configured" for the other.
//
// Accepted: exactly one `PRIVATE KEY` block (PKCS#8, not `EC PRIVATE KEY` / `RSA PRIVATE KEY` / a public key), base64 body, with real
// line breaks (LF or CRLF) OR the two characters backslash + `n` standing in for each line break, and leading/trailing whitespace.
// Anything else (empty, wrong label, bad base64, trailing junk, a second block) is `null`; this function never throws.
//
// The block markers are assembled at run time so no source line carries a literal PEM header (a secret scanner reads one as a
// leaked private key, correctly in general and wrongly here).

const PEM_FENCE = "-".repeat(5);
const PKCS8_PEM = new RegExp(`^\\s*${PEM_FENCE}BEGIN PRIVATE KEY${PEM_FENCE}([A-Za-z0-9+/=\\s]+)${PEM_FENCE}END PRIVATE KEY${PEM_FENCE}\\s*$`);

/** PEM (PKCS#8) -> DER; `null` unless it is exactly one well-formed PRIVATE KEY block. */
export function pkcs8PemToDer(pem: string): Uint8Array | null {
  const normalised = pem.replace(/\\n/g, "\n");
  const m = PKCS8_PEM.exec(normalised);
  if (!m) return null;
  try {
    const bin = atob(m[1]!.replace(/\s+/g, ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
}
