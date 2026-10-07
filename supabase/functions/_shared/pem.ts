// supabase/functions/_shared/pem.ts
//
// THE one PKCS#8 PEM parser for every Apple/Google private key this server reads from the environment (the Sign in with Apple
// `.p8`, the DeviceCheck `.p8`, the Google service-account key). Before this file the Sign in with Apple parser accepted a one-line
// PEM with literal backslash-n (how a single-line environment variable carries a key) and the DeviceCheck / Play Integrity parser
// did not, so the same key pasted the same way worked for one and read as "not configured" for the other.
//
// Accepted: exactly one `PRIVATE KEY` block (PKCS#8, not `EC PRIVATE KEY` / `RSA PRIVATE KEY` / a public key) whose body is STRICT standard base64
// (padded, canonical: the decoded bytes must re-encode to exactly the text, so unpadded input and non-zero trailing bits are refused), with real
// line breaks (LF or CRLF) OR the two characters backslash + `n` standing in for each line break, and ASCII whitespace (space, tab, CR, LF) around
// the block and inside the body, and ONE leading byte-order mark (U+FEFF). Anything else (a non-string, empty, wrong label, non-base64 or Unicode whitespace, unpadded or non-canonical
// base64, trailing junk, a second block) is `null`; this function never throws.
//
// The block markers are assembled at run time so no source line carries a literal PEM header (a secret scanner reads one as a
// leaked private key, correctly in general and wrongly here).

const PEM_FENCE = "-".repeat(5);
const PKCS8_PEM = new RegExp(`^[ \\t\\r\\n]*${PEM_FENCE}BEGIN PRIVATE KEY${PEM_FENCE}([A-Za-z0-9+/= \\t\\r\\n]+)${PEM_FENCE}END PRIVATE KEY${PEM_FENCE}[ \\t\\r\\n]*$`);

/** PEM (PKCS#8) -> DER; `null` unless it is exactly one well-formed PRIVATE KEY block. */
export function pkcs8PemToDer(pem: string): Uint8Array | null {
  if (typeof pem !== "string") return null;
  // One leading byte-order mark (U+FEFF) is dropped: Windows editors and PowerShell's `Out-File` prepend one to a saved key file or env file.
  // Nothing else beyond ASCII whitespace is tolerated: a no-break space (U+00A0), any other Unicode space, or a second BOM is refused on purpose
  // (a pasted key that picked up one has been through a word processor and should be re-exported, not silently repaired).
  const normalised = (pem.charCodeAt(0) === 0xfeff ? pem.slice(1) : pem).replace(/\\n/g, "\n");
  const m = PKCS8_PEM.exec(normalised);
  if (!m) return null;
  const text = m[1]!.replace(/[ \t\r\n]+/g, "");
  try {
    // atob is lenient (it accepts unpadded input and non-zero trailing bits), so the strictness is the round trip: the decoded bytes must
    // re-encode to exactly the text. That alone refuses unpadded, mis-padded, non-alphabet and non-canonical input, and an empty body.
    const bin = atob(text);
    if (bin.length === 0 || btoa(bin) !== text) return null;
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
