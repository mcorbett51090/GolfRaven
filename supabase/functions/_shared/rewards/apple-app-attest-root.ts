// supabase/functions/_shared/rewards/apple-app-attest-root.ts
//
// Apple's App Attestation Root CA, PINNED IN CODE as public data (it is a public certificate, not a
// secret). This is the only trust anchor App Attest key registration accepts; there is no
// environment variable, request field or database row that can supply another. The one seam that
// takes an anchor is `createAttestationVerifier` (app-attest-registration.ts), whose `trustAnchorDer`
// parameter is set ONLY by privileged.ts's production wiring (to the constant below) and by tests
// (to a throw-away test root); nothing a request carries reaches it.
//
// PROVENANCE `[unverified against a second source]`: fetched on 2026-10-02 from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem by an agent whose
// outbound TLS goes through a TLS-terminating egress proxy, so the bytes are "what the proxy served
// for Apple's URL", not an independently authenticated copy. Before this ships, a human must
// compare the fingerprint below with the one Apple publishes (or `curl` the URL from a clean
// machine) and confirm they are equal. A unit test pins the SHA-256 of these bytes to the
// constant, so an accidental edit fails CI; it cannot tell you the constant was right to begin with.
//
//   Subject / issuer : CN=Apple App Attestation Root CA, O=Apple Inc., ST=California (self-signed)
//   Key              : EC P-384, signature ecdsa-with-SHA384
//   Valid            : 2020-03-18T18:32:53Z .. 2045-03-15T00:00:00Z
//   Serial           : 0B:F3:BE:0E:F1:CD:D2:E0:FB:8C:6E:72:1F:62:17:98
//   SHA-256 (DER)    : 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32
//
// When this certificate nears 2045, or Apple publishes a new root, replace it here and in the pinned
// fingerprint; there is deliberately no way to do so at run time.

export const APPLE_APP_ATTEST_ROOT_SHA256_HEX = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";

const APPLE_APP_ATTEST_ROOT_B64 =
  "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw" +
  "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK" +
  "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa" +
  "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv" +
  "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y" +
  "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh" +
  "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au" +
  "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/" +
  "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw" +
  "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn" +
  "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV" +
  "oyFraWVIyd/dganmrduC1bmTBGwD";

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The pinned root, DER-encoded. */
export const APPLE_APP_ATTEST_ROOT_DER: Uint8Array = decodeBase64(APPLE_APP_ATTEST_ROOT_B64);
