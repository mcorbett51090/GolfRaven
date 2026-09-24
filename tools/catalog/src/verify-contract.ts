/**
 * `verify-contract` — generates `contract/catalog.schema.json` from the
 * §4.1 Zod schema (via Zod v4's native `z.toJSONSchema`, no third-party
 * `zod-to-json-schema` dependency needed) and checks the committed file
 * against it (§3.5: "CI regenerates `contract/catalog.schema.json` and
 * fails on any diff").
 *
 * This one CLI is both "the generator" and "the check" the task asks for,
 * the same way `prettier --write` / `prettier --check` are one tool with
 * two flags — `--write` regenerates the committed file; with no flag, it
 * diffs the generated schema against what's committed and fails (exit 1)
 * on any difference, including the file not existing yet.
 *
 * **What's in the generated document.** A Zod v4 "registry" export
 * (`{ schemas: { <Name>: <JSON Schema>, ... } }`), one entry per top-level
 * §4.1 entity this P1a implements: `Region`, `Source`, `Designer`, `Hole`,
 * `Tee`, `Facility`, `Course`, `Trail`, `RosterVersion`, `OfferTerms` (S6,
 * gate review post-e9b3ab0 — `OfferTerms` needs no `RuleExpr`, see
 * `schema.ts`'s module doc, so it's in scope and in this registry). A
 * shared nested schema (e.g. `Course` inside `Facility.courses`) becomes a
 * `$ref` between entries rather than being inlined twice — Zod's own
 * registry behaviour, not a choice made here. `AchievementDef` is the one
 * entity still not in this registry (it needs `RuleExpr`, part B).
 */
import { readFile, writeFile, realpath as fsRealpath } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  DesignerSchema,
  FacilitySchema,
  CourseSchema,
  HoleSchema,
  OfferTermsSchema,
  RegionSchema,
  RosterVersionSchema,
  SourceSchema,
  TeeSchema,
  TrailSchema,
} from "@golfraven/catalog";

export function generateContractSchema(): unknown {
  const registry = z.registry<{ id: string }>();
  registry.add(RegionSchema, { id: "Region" });
  registry.add(SourceSchema, { id: "Source" });
  registry.add(DesignerSchema, { id: "Designer" });
  registry.add(HoleSchema, { id: "Hole" });
  registry.add(TeeSchema, { id: "Tee" });
  registry.add(CourseSchema, { id: "Course" });
  registry.add(FacilitySchema, { id: "Facility" });
  registry.add(RosterVersionSchema, { id: "RosterVersion" });
  registry.add(TrailSchema, { id: "Trail" });
  registry.add(OfferTermsSchema, { id: "OfferTerms" });
  return z.toJSONSchema(registry);
}

/** Canonical (sorted-key) JSON serialisation, so key order in the
 * committed file never causes a false "stale" result. */
export function canonicalJsonString(value: unknown): string {
  return `${JSON.stringify(sortKeys(value), null, 2)}\n`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return Object.fromEntries(entries.map(([k, v]) => [k, sortKeys(v)]));
  }
  return value;
}

export interface ContractCheckResult {
  stale: boolean;
  reason?: "missing" | "diff";
  generated: string;
  committed?: string;
}

export async function checkContract(contractPath: string): Promise<ContractCheckResult> {
  const generated = canonicalJsonString(generateContractSchema());
  let committed: string | undefined;
  try {
    committed = await readFile(contractPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { stale: true, reason: "missing", generated };
    }
    throw err;
  }
  if (committed !== generated) {
    return { stale: true, reason: "diff", generated, committed };
  }
  return { stale: false, generated, committed };
}

/* ------------------------------------------------------------------ */
/* Path resolution + CLI                                               */
/* ------------------------------------------------------------------ */

/** Repo-root-relative default path, resolved from this module's own file
 * location (works from any `cwd`, not just the repo root). */
function defaultContractPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/verify-contract.js -> tools/catalog/dist -> up 3 = repo root.
  return join(here, "..", "..", "..", "contract", "catalog.schema.json");
}

interface CliArgs {
  write: boolean;
  contractPath: string;
}

function parseArgs(argv: string[]): CliArgs {
  let write = false;
  let contractPath = defaultContractPath();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--write") {
      write = true;
    } else if (arg === "--contract-path") {
      const next = argv[i + 1];
      if (!next) throw new Error("--contract-path requires a value");
      contractPath = next;
      i += 1;
    }
  }
  return { write, contractPath };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.write) {
    const generated = canonicalJsonString(generateContractSchema());
    await writeFile(args.contractPath, generated, "utf8");
    process.stdout.write(`verify-contract: wrote ${args.contractPath}\n`);
    return;
  }

  const result = await checkContract(args.contractPath);
  if (!result.stale) {
    process.stdout.write("verify-contract: PASS (contract/catalog.schema.json is up to date)\n");
    return;
  }
  if (result.reason === "missing") {
    process.stderr.write(
      `verify-contract: FAIL — ${args.contractPath} does not exist. Run with --write to generate it.\n`,
    );
  } else {
    process.stderr.write(
      `verify-contract: FAIL — ${args.contractPath} is stale (the committed JSON Schema does not match the Zod schema in packages/catalog). Run with --write to regenerate it.\n`,
    );
  }
  process.exitCode = 1;
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const [herePath, argvPath] = await Promise.all([
      fsRealpath(fileURLToPath(import.meta.url)),
      fsRealpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`verify-contract: ${message}\n`);
    process.exitCode = 1;
  });
}
