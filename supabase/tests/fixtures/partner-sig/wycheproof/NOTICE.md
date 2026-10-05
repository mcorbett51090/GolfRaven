# Vendored: Project Wycheproof test vectors

These two files are **unmodified copies** of test vectors from [Project Wycheproof](https://github.com/C2SP/wycheproof)
(`C2SP/wycheproof`), copyright the Wycheproof authors, licensed under the **Apache License, Version 2.0**. The full licence text is `LICENSE` in this directory
(a copy of the upstream repository's `LICENSE`).

| File | Upstream path | Tests | sha256 of the vendored file |
|---|---|---|---|
| `ecdsa_secp256r1_sha256_test.json` | `testvectors_v1/ecdsa_secp256r1_sha256_test.json` (ECDSA over P-256 with SHA-256, DER signatures, `ecdsa_verify_schema_v1`) | 484 | `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332` |
| `rsa_signature_2048_sha256_test.json` | `testvectors_v1/rsa_signature_2048_sha256_test.json` (RSASSA-PKCS1-v1_5, SHA-256, `rsassa_pkcs1_verify_schema_v1`) | 259 | `94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393` |

Retrieved 2026-10-04 from `https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/<file>` (the upstream `main` branch at that time; the files' own header
reports test-vector source `google-wycheproof` version `0.9rc5`). The upstream commit hash was **not** recorded: the GitHub API lookup for it was denied in the authoring
session ("GitHub access to this repository is not enabled for this session"), so the sha256 values above are what pins the content.

What they are used for: `supabase/tests/matrix/26_partner_sig_verifiers.sql` runs **every** test of both files through the SQL signature verifiers of migration
`0048_partner_signin_mint.sql` (`private.partner_sig_es256_verify`, `private.partner_sig_rs256_verify`), under the verdict policy stated in that file: the strict verifier
must accept every `valid` ES256 vector and refuse every `invalid` one; for RSA, `valid` vectors with a public exponent other than 65537 and the one `acceptable` vector
(a missing NULL in the DigestInfo) are *expected to be refused* by policy (e = 65537 only; the DigestInfo is built fresh and compared whole), and every other verdict is
taken as written. The vendored files are never edited; if a corpus is refreshed, replace the file, update the sha256 above and re-run the suite.
