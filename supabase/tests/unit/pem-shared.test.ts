// supabase/tests/unit/pem-shared.test.ts
//
// ONE PKCS#8 PEM parser (`_shared/pem.ts`) for the Sign in with Apple key, the DeviceCheck key and the Google service-account key. Before it, the
// Sign in with Apple parser accepted a one-line PEM with literal backslash-n and the DeviceCheck / Play Integrity one did not.

import { beforeAll, describe, expect, it } from "vitest";
import { pkcs8PemToDer as shared } from "../../functions/_shared/pem.js";
import { pkcs8PemToDer as viaSignin } from "../../functions/_shared/signin/apple-client-secret.js";
import { pemToDer as viaRewards } from "../../functions/_shared/rewards/vendor-http.js";
import { toB64 } from "./rewards-test-crypto.js";

// The fences are assembled at run time so no source line carries a literal PEM header (gitleaks' private-key rule reads one, correctly in
// general and wrongly here: nothing in this file is a key).
const FENCE = "-".repeat(5);
const block = (label: string, body: string) => `${FENCE}BEGIN ${label}${FENCE}\n${body}\n${FENCE}END ${label}${FENCE}`;

let pem: string;
let der: Uint8Array;
beforeAll(async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  pem = block("PRIVATE KEY", toB64(der).replace(/(.{64})/g, "$1\n"));
}, 30_000);

describe("the shared PKCS#8 PEM parser", () => {
  it("is ONE implementation: the sign-in and rewards entry points are the shared function", () => {
    expect(viaSignin).toBe(shared);
    expect(viaRewards(pem)).toEqual(shared(pem));
  });

  it("accepts real LF newlines, CRLF, a one-line literal backslash-n form, and surrounding whitespace, all to the same DER", () => {
    const forms = [pem, pem.replace(/\n/g, "\r\n"), pem.replace(/\n/g, "\\n"), `\n\t ${pem} \n\n`, `  ${pem.replace(/\n/g, "\\n")}  `];
    for (const f of forms) {
      for (const parse of [shared, viaSignin, viaRewards]) expect(Array.from(parse(f)!), f.slice(0, 30)).toEqual(Array.from(der));
    }
  });

  it("rejects everything else with null and never throws: empty, wrong label, bad base64, truncated, two blocks, trailing junk, a bare escaped newline", () => {
    const bad = [
      "",
      "   ",
      "nope",
      block("PUBLIC KEY", "AAAA"),
      block("EC PRIVATE KEY", "AAAA"),
      block("PRIVATE KEY", "!!!"),
      block("PRIVATE KEY", ""),
      `${FENCE}BEGIN PRIVATE KEY${FENCE}\nAAAA`,
      `${FENCE}BEGIN PRIVATE KEY${FENCE}\\nAAAA`,
      `${pem}\n${pem}`,
      `${pem}\ntrailing`,
      `prefix\n${pem}`,
      "\\n",
      "\\n\\n\\n",
    ];
    for (const b of bad) {
      for (const parse of [shared, viaSignin, viaRewards]) expect(parse(b), JSON.stringify(b).slice(0, 40)).toBeNull();
    }
  });

  it("is STRICT base64: unpadded, non-canonical trailing bits, a body that passes the character class but not atob, and Unicode whitespace are all null", () => {
    // Synthetic bodies (the parser does not look inside the DER): 4 bytes = "AQIDBA==" (two pad), 5 bytes = "AQIDBAU=" (one pad).
    expect(Array.from(shared(block("PRIVATE KEY", "AQIDBA==")) ?? [])).toEqual([1, 2, 3, 4]);
    expect(Array.from(shared(block("PRIVATE KEY", "AQIDBAU=")) ?? [])).toEqual([1, 2, 3, 4, 5]);
    for (const [name, body] of [
      ["unpadded (two missing)", "AQIDBA"],
      ["unpadded (one missing)", "AQIDBAU"],
      ["non-zero trailing bits, two pad", "AQIDBB=="],
      ["non-zero trailing bits, one pad", "AQIDBAV="],
    ] as const) {
      expect(shared(block("PRIVATE KEY", body)), name).toBeNull();
    }
    const body = toB64(der);
    // passes `[A-Za-z0-9+/=]+` but is not decodable: length 1 mod 4, an `=` in the middle, only padding
    for (const notBase64 of ["AAAAA", "A=AA", "====", "AA==AA==", "AAA"]) expect(shared(block("PRIVATE KEY", notBase64)), notBase64).toBeNull();
    // Unicode whitespace (NBSP, line separator, ideographic space) is not whitespace here: inside the body or around the block
    for (const ws of ["\u00a0", "\u2028", "\u3000", "\u000b", "\u000c"]) {
      expect(shared(block("PRIVATE KEY", `${body.slice(0, 8)}${ws}${body.slice(8)}`)), `inside ${JSON.stringify(ws)}`).toBeNull();
      expect(shared(`${ws}${pem}`), `leading ${JSON.stringify(ws)}`).toBeNull();
      expect(shared(`${pem}${ws}`), `trailing ${JSON.stringify(ws)}`).toBeNull();
    }
  });

  it("returns null (never throws) for a non-string", () => {
    for (const v of [undefined, null, 0, 42, {}, [], true, Symbol.iterator, new Uint8Array([1, 2, 3])]) {
      for (const parse of [shared, viaSignin, viaRewards]) expect(() => parse(v as unknown as string), String(typeof v)).not.toThrow();
      expect(shared(v as unknown as string)).toBeNull();
    }
  });
});
