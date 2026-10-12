#!/usr/bin/env node
// tools/db/provision-course-qr-key.mjs
//
// OPERATOR TOOL (docs/security/partner-auth-design.md, "As built: S2b"): generates ONE Ed25519 course-QR signing key and prints the SQL that provisions it. Nothing is written to a file, a database or a log by this
// script: the SQL goes to STDOUT and is meant to be PIPED straight into psql, which an operator runs as the project's owner role (the role that may call vault.create_secret and insert into app.course_qr_key):
//
//   node tools/db/provision-course-qr-key.mjs rotating_token kid-2030-01 | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
//   node tools/db/provision-course-qr-key.mjs printed_qr     kid-2030-01 | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
//
// What the SQL does, in ONE transaction:
//   * the PRIVATE half goes to Vault only: secret `course_qr_signing_key_<purpose>` = `<kid>:<32-byte Ed25519 seed, base64url>`. It is read by exactly one function (private.course_qr_signing_key_read), which only the
//     A1 mint and the A3 qr-print definers call, and it is released to the Edge only inside those authorized calls. It is never in a table, a migration, an audit row or a log.
//   * the PUBLIC half goes to app.course_qr_key (purpose, kid, public key): what the player lane verifies against (`kid`-addressed, revocable at once).
// `--rotate` replaces an EXISTING Vault secret of that purpose (vault.update_secret) under a NEW kid and registers the new public key; the OLD kid's public row is NOT revoked here (tokens already minted verify for
// their 120 s, and a printed QR under the old kid stays valid until qr-print re-registers the facility under the new one: then the old kid is `qr_revoked` in the player lane). Revoking a kid is a separate,
// deliberate act: `update app.course_qr_key set revoked_at = now() where purpose = ... and kid = ...` (a COMPROMISE revocation takes effect at once, and every printed QR of that kid is then reprinted).
//
// The seed is printed ONCE, inside the SQL. Do not redirect the output to a file, do not run this with shell tracing on, and do not paste it anywhere: pipe it. A kid is `[A-Za-z0-9_-]{1,64}`.

import { generateKeyPairSync } from "node:crypto";

const PURPOSES = new Set(["rotating_token", "printed_qr"]);
const KID_RE = /^[A-Za-z0-9_-]{1,64}$/;

const args = process.argv.slice(2);
const rotate = args.includes("--rotate");
const [purpose, kid, ...rest] = args.filter((a) => a !== "--rotate");
if (rest.length > 0 || !PURPOSES.has(purpose) || !KID_RE.test(kid ?? "")) {
  process.stderr.write("usage: node tools/db/provision-course-qr-key.mjs [--rotate] <rotating_token|printed_qr> <kid: [A-Za-z0-9_-]{1,64}>  | psql ...\n");
  process.exit(2);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "jwk" }).d; // the 32-byte seed, unpadded base64url (RFC 8037)
const pub = publicKey.export({ format: "jwk" }).x; // the 32-byte public key, unpadded base64url
if (typeof seed !== "string" || seed.length !== 43 || typeof pub !== "string" || pub.length !== 43) {
  process.stderr.write("provision-course-qr-key: the runtime did not produce a 32-byte Ed25519 key\n");
  process.exit(1);
}

const name = `course_qr_signing_key_${purpose}`;
const secret = `${kid}:${seed}`;
const create = rotate
  ? `SELECT vault.update_secret((SELECT s.id FROM vault.secrets s WHERE s.name = '${name}'), '${secret}');`
  : `SELECT vault.create_secret('${secret}', '${name}', 'Ed25519 signing key of the course QR (${purpose}); value is <kid>:<seed>');`;
process.stdout.write(
  [
    "BEGIN;",
    create,
    `INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('${purpose}', '${kid}', '${pub}');`,
    "COMMIT;",
    "",
  ].join("\n"),
);
