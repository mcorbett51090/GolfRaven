/**
 * `verify-catalog`'s input format: a "catalog bundle" — one self-contained
 * JSON file holding every facility, trail, designer and the ID ledger a
 * single check run needs.
 *
 * **Design choice, not a literal reading of the plan.** §10 P1 names the
 * eventual on-disk layout as a multi-file `data/` tree (`data/facilities/*`,
 * a `data/id-ledger.json`, …, §4.1/§4.2). This bundle format is a thin,
 * separately-testable adapter in front of the same validated types, chosen
 * for two reasons specific to P1a: (1) the task asks for "one committed
 * fixture per must-fail case" — a single JSON file per fixture is the most
 * direct way to satisfy that; scanning a multi-file directory would need
 * either one directory per fixture (far more file-tree noise for the same
 * coverage) or a shared fixture directory (which would make fixtures
 * interact with each other, the opposite of "each must-fail fixture must
 * fail for its own reason"). (2) P1a carries no real `data/` content (only
 * the ledger format and synthetic fixtures), so there is nothing yet to
 * scan a real multi-file tree against. `loadBundleFromDataDir` below is a
 * placeholder seam for that future adapter; swapping it in does not change
 * any gate-rule code, because every rule below operates on `CatalogBundle`,
 * not on file paths.
 */
import { z } from "zod";
import {
  CONTRACT_VERSION,
  DesignerSchema,
  FacilitySchema,
  IdLedgerSchema,
  TrailSchema,
} from "@golfraven/catalog";

/**
 * **Gate review correction (post-e9b3ab0): a bundle may not assert its own
 * review state.** Earlier this schema carried `bookingHostAllowList` and
 * `labels` fields, so a bundle could ship its own allow-list or claim its
 * own `geometry-reviewed`/`contact-reviewed` labels — a self-approval hole
 * (a malicious or careless PR could add its own booking host to its own
 * allow-list, or assert the review label that lets it skip review). Both
 * now come only from trusted, out-of-band inputs the bundle cannot touch:
 * the booking-host allow-list from the committed `config/booking-hosts.json`
 * (`src/config.ts`), and labels only from the CLI's `--labels` flag (real
 * PR labels, passed in by CI). `mf-bundle-cannot-self-label` and
 * `mf-bundle-cannot-self-allow-booking-host` (test/fixtures) prove a
 * bundle carrying either field is now rejected outright (`strictObject`
 * -> `SCHEMA_INVALID: Unrecognized key`).
 */
export const CatalogBundleSchema = z.strictObject({
  contractVersion: z.literal(CONTRACT_VERSION),
  facilities: z.array(FacilitySchema),
  trails: z.array(TrailSchema),
  designers: z.array(DesignerSchema).optional(),
  idLedger: IdLedgerSchema,
});
export type CatalogBundle = z.infer<typeof CatalogBundleSchema>;

export interface BundleParseFailure {
  ok: false;
  schemaIssues: { path: string; message: string }[];
}

export interface BundleParseSuccess {
  ok: true;
  bundle: CatalogBundle;
}

/** Parses raw JSON into a `CatalogBundle`, or returns every Zod issue with
 * a dotted path (`facilities[2].tz`) rather than throwing — `verify-catalog`
 * reports these as `SCHEMA_INVALID` issues alongside its own semantic gate
 * rules, in the same run. */
export function parseCatalogBundle(
  raw: unknown,
): BundleParseSuccess | BundleParseFailure {
  const result = CatalogBundleSchema.safeParse(raw);
  if (result.success) {
    return { ok: true, bundle: result.data };
  }
  return {
    ok: false,
    schemaIssues: result.error.issues.map((issue) => ({
      path: formatPath(issue.path),
      message: issue.message,
    })),
  };
}

function formatPath(path: readonly PropertyKey[]): string {
  if (path.length === 0) return "<root>";
  let out = "";
  for (const segment of path) {
    if (typeof segment === "number") {
      out += `[${segment}]`;
    } else {
      out += out.length > 0 ? `.${String(segment)}` : String(segment);
    }
  }
  return out;
}
