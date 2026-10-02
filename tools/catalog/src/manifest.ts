/**
 * Manifest and `versions.json` shape, canonical-JSON, strict parsing, and
 * append-only helpers for the catalog artifact (build plan §3.3 "A
 * signed, append-only `catalog/v1/versions.json`", §3.5 "App lifecycle
 * fields in the signed manifest", §10 P1 AT(2)).
 *
 * **Node-side wrapper over `./manifest-core.js`.** The algorithm and the
 * schemas live in `manifest-core.ts`, which has no `node:*` import and no
 * `Buffer` reference so the mobile app (Metro/Hermes) can reuse them
 * unchanged (build plan §3.5: "the app and the import function consume the
 * same signed artifact"). This file re-exports all of it and adds the
 * three members that need Node: `sha256Hex`, the two `*StatementBytes`
 * Buffer wrappers and the Buffer-taking `strictParseAndValidate`.
 * Behaviour and signatures are identical to before the split.
 *
 * See `manifest-core.ts` for the Opus-security-gate history (commit
 * 7692919) of the canonical-bytes design.
 */
import { createHash } from "node:crypto";
import type { z } from "zod";
import {
  manifestStatementText,
  strictParseAndValidateText,
  versionsStatementText,
  type ManifestStatement,
  type StrictParseResult,
  type VersionsStatement,
} from "./manifest-core.js";

export * from "./manifest-core.js";

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function manifestStatementBytes(statement: ManifestStatement): Buffer {
  return Buffer.from(manifestStatementText(statement), "utf8");
}

export function versionsStatementBytes(statement: VersionsStatement): Buffer {
  return Buffer.from(versionsStatementText(statement), "utf8");
}

export function strictParseAndValidate<T>(
  raw: Buffer,
  schema: z.ZodType<T>,
  label: string,
): StrictParseResult<T> {
  return strictParseAndValidateText(raw.toString("utf8"), schema, label);
}
