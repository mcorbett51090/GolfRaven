# P3 money path — requirements for the API / Edge Function layer

Source: the money-path security review of `packages/rules`, 2026-09-24.

`scorePlay` is a pure function, and it is only as trustworthy as its input. The package now fixes what a pure
function can fix: allow-list checks, a strict input parser, a course anchor, and caps. Everything below can only
be enforced where the input is built. Each item must be satisfied, and tested, before the P3 Edge Functions ship.
The DB-side items are tracked in the P3a queue.

## 1. Build every `Evidence` / `AppFix` on the server — never pass client JSON through

| Field | Must come from |
|---|---|
| `token.grade`, `hardwareSupportsAttestation` | Server verification of App Attest / Play Integrity, and the verified device model |
| `challenge` | The `checkin_challenge` row: single-use, `used_at` set atomically |
| `facilityId`, `verificationTier`, `geometryKind`, `insideBuffer`, `accuracyMeters` | Re-running the matcher (`packages/matching`) on the raw coordinates against the signed catalog |
| `capturedAt` | For live challenges, clamped to `[challenge.issued_at, issued_at + TTL]`. Otherwise a skew check against server `now`, with a `fraud_signal` above 24 h |
| `localDate` | Derived from the server-trusted `capturedAt` and the facility `tz` |
| `fixId` | The challenge id, or a hash of the attestation assertion. **Item 3 of the ninth gate: PINNED to unpadded base64url (RFC 4648 §5) — `[A-Za-z0-9_-]`, no `+`/`/`/`=`.** |

**Why base64url, not hex, for `fixId` (item 3, ninth gate).** `packages/rules` already uses hex
elsewhere (`inputDigest`, a SHA-256 digest) but `fixId` is not always a digest — the trust table above
allows it to be either a raw challenge-nonce id OR a hash of the attestation assertion, and the mobile
attestation ecosystems this system integrates with (App Attest, Play Integrity) already emit base64
tokens natively. Re-encoding that output as UNPADDED base64url — swap `+`/`/` for `-`/`_`, drop `=`
padding — is the standard "make an opaque server token URL- and JSON-safe" step, and it covers a raw
random nonce and a hash digest equally well; hex would be an awkward re-encoding of a base64 SDK
output for no benefit. **This is a hard requirement on whichever Edge Function issues/derives `fixId`:
never emit standard, padded base64 (`+`, `/`, or `=` will be rejected and the row quarantined — see
`packages/rules`' `FixIdSchema`), and never emit a raw hex string with unnecessary padding either —
base64url, unpadded, is the one accepted encoding.**

## 2. Each row type comes only from its own server path

| Row / field | Only from |
|---|---|
| `staff_presence` (`scanAt` = server time) | `/v1/partner/attest`, with an `attestation` row carrying a unique `token_jti` |
| `booking`, `paymentRef` | The P7 provider webhook |
| `arccos` / `garmin` (`vendorCourseMapped`, `sensorProvenance`) | The P8 connector |
| Receipt `status` | The review queue |
| `courseDisambiguatedBy` | The matcher or the portal |

`POST /v1/evidence` rejects every field in these two tables.

**A SQL `NULL` maps to an OMITTED JSON field, never to a literal `null` (item 2, ninth gate).**
`packages/rules`' parser treats an omitted `courseId` and a present `courseId: null` as two
COMPLETELY DIFFERENT things on purpose: omitted means "no course anchor at all — facility-level
evidence, always allowed" (the seventh gate's H3 residual rule); a present `null` is a MALFORMED
value (not a string), which the parser can only treat as ambiguous and quarantine. Any endpoint or
ORM layer that serializes a DB row to JSON MUST drop a `NULL` column from the payload entirely rather
than emitting it as `null` — this applies to `courseId` specifically (the anchor field this gate's
own finding concerns) and, as a general rule, to every OPTIONAL field `packages/rules`' schema
declares with `.optional()` (never `.nullable()`) for exactly this reason. A framework/ORM default
that emits `null` for every absent column (a common Postgres-client default) will silently turn every
facility-level evidence row into an unnecessary quarantine candidate — this is a real, addressable
integration bug class, not merely a theoretical one, and must be checked explicitly wherever
`app.evidence` rows are serialized for `scorePlay`'s input.

## 3. Per-play limits and fraud signals

- Cap evidence rows matching a play at 1,000 (`packages/rules`' `EVIDENCE_ROW_CAP`, raised from 200 in the
  seventh gate, item 9 — the cap now counts only rows the parser's loose facility/date/course filter kept, not
  every row a raw, unfiltered query happened to return). Keep a much larger raw-query DoS cap (10,000,
  `ABSOLUTE_ROW_CAP`) on the unfiltered result set itself. `scorePlay` scores one play per call — the caller
  does not need to pre-filter before calling it.
- Catch scorer exceptions per play, so one bad row cannot block a re-score batch. **This is now largely
  superseded by `packages/rules`' own quarantine (seventh gate, item/finding F3): a single malformed
  on-play row no longer fails `scorePlay` at all — it is excluded (`excludedRows`, `kind: "quarantined"`) and
  the play still scores on its remaining evidence.** The DB/Edge-Function layer must still catch exceptions
  defensively (a bug in the caller's own row assembly is not itself a `packages/rules` concern), but should not
  rely on a single bad row as the reason a re-score batch would stall.
- **Every ON-PLAY quarantine (item 2, seventh gate) must raise a `fraud_signal` or create a `review_item`.**
  `packages/rules` already forces `heldReview: true` (and populates `heldReviewReasons: ["quarantined"]`)
  whenever `money` is true and `excludedRows` contains a `kind: "quarantined"` entry — but `heldReview` alone
  only stops AUTO-issuance; it does not itself create a durable, actionable record. The DB-side consumer of a
  `scorePlay` result MUST, on every on-play quarantine (regardless of whether `money` ended up true — a
  malformed on-play row is worth recording even on a play that doesn't qualify for money, since the SAME
  malformed-row shape recurring across many plays is itself a fraud signal), raise a `fraud_signal` row or
  create a `review_item` naming the play, the quarantined row's original index, and its (already
  truncated/escaped — see the note below) reasons.
- Event-time velocity check: a play is disputed above 200 km/h between consecutive fixes.
- Clock skew over 24 h → `fraud_signal`. `packages/rules` now also rejects `capturedAt`/`scanAt` outside
  `[2020-01-01, 2100-01-01)` outright at the parser (seventh gate, item 6) — a plausibility floor/ceiling, not a
  substitute for this DB-side skew-against-`now()` check, which is tighter and time-varying.
- **A fix that grades `failed` MUST raise `fraud_signal(attestation_failed)` AT INTAKE** (item 2, seventh
  gate) — i.e. at `POST /v1/evidence` / whatever server path first receives the row, not merely observed
  later by a batch re-score. `packages/rules`' own scorer only ZEROES a `failed`-grade fix's contribution
  (§4.5 G3-08: "nothing can be earned on it") — it is a pure function with no DB access, so it cannot itself
  raise the signal; this has always been a DB-side obligation, restated here because the seventh gate's
  quarantine work made it easy to lose sight of which layer owns it.
- **`excludedRows` and `reasons` (both `packages/rules`' own types) are SERVER-SIDE DIAGNOSTIC DATA
  ONLY** (item 5, seventh gate). Every value they embed is already truncated (128 chars) and
  `JSON.stringify`-escaped before it reaches these arrays, but they still exist to help an operator or an
  internal dashboard understand why a row didn't score — never echo them into a player-facing UI, even
  escaped; a quarantine reason restates exactly which shape check rejected the input, which is more detail
  than an end user needs and more than an adversary probing the validator should get back.

## 4. Persisting and issuing

- Store the scorer's own `money`, `heldReview`, `hardSignal`, `policyVersion` and `inputDigest`.
- Never recompute money from the rounded `numeric(3,2)` score.
- Reserve offer budget atomically (row lock). Validate eligibility at save, approval and issuance with
  `validateOfferEligibility`. That validator rejects rules that are true on an empty play set. Treat a thrown
  validator error as invalid.

## 5. Receipts and fingerprints

Item 1 of the eighth gate: `packages/rules`' own fingerprint-dedup logic (`voidDuplicateFingerprints`,
`score-play.ts`) now trusts `voidReason` (`"duplicate" | "reviewer" | "fraud"`) to tell an honest intake-side
dedup apart from a real fraud/reviewer flag — a `"duplicate"`-void row is simply ignored (never poisons its
fingerprint group); a `"reviewer"`/`"fraud"`-void row (or a `status: "void"` row with NO `voidReason` at all —
defaults to `"reviewer"`, fails safe) poisons the whole group. This is a pure function; it can only act
correctly on what the DB/intake layer hands it. That layer MUST:

- **Never attach a dedup-voided duplicate to `play_evidence` in the first place.** `voidDuplicateFingerprints`
  ignoring a `"duplicate"`-void row is a *second* layer of defence, not a substitute for intake not creating
  the row as scoreable evidence at all — a receipt intake already recognizes as a re-upload of an existing one
  should either not be inserted into `app.evidence` as a distinct row, or should be inserted already `void` /
  `voidReason: 'duplicate'` and never linked into `play_evidence` for a DIFFERENT play than the original.
- **`voidReason` MUST be set at intake or at review — never left implicit.** A void row with no `voidReason`
  is treated as `"reviewer"` by `packages/rules` (the safe default), but that is a *fallback*, not a licence to
  skip setting it: an intake dedup step that voids a row without recording WHY loses the distinction this
  whole mechanism exists to preserve, and every such row will poison its group even when the intake step
  itself knew it was a harmless duplicate.
- **A fingerprint match against ANOTHER user's receipt goes to human review and is NEVER auto-voided.**
  This is the grief-vector this section exists to name: a shared or public receipt (a group green-fee slip, a
  clubhouse photo op) can be fingerprinted and uploaded by more than one legitimate player. If intake
  auto-voids "the second submission of a fingerprint," WHOEVER UPLOADS FIRST can silently void the
  RIGHTFUL owner's receipt just by getting there first with the same photo — the fingerprint match alone
  says two receipts look identical, not which uploader (if either) actually owns the underlying green fee. A
  cross-user fingerprint match must route to a human reviewer (who can ask for the original file, check
  payment records, etc.) — it is exactly the `"reviewer"` (or, if the review substantiates it, `"fraud"`)
  `voidReason` case, never `"duplicate"`, which is reserved for a SAME-USER re-upload intake can safely
  recognize on its own.

## Status

| Item | Where | Status |
|---|---|---|
| 1, 2, 3, 4 | P3 Edge Functions | Not started (P3 Edge Functions are not built yet) |
| `play_evidence UNIQUE(evidence_id)`, grade column, budget CHECKs, decision columns, receipt dedupe, global nonces | P3a migrations | Done — `supabase/migrations/0017_money_path_hardening.sql` |
| Allow-lists, parser, trust table, course anchor, caps, tautology rejection | `packages/rules` | In progress |

## Addendum (post-P3a gate): `evidence.attestation_grade` — "never graded" vs "unattestable"

`app.evidence.attestation_grade app.attestation_grade NOT NULL DEFAULT 'unattestable'`
(0017) reuses the existing three-value enum from 0003 (`'attested'`, `'unattestable'`,
`'failed'`). That enum has no fourth, "not yet graded" value, so every row defaults to
`'unattestable'` at INSERT time whether it was genuinely graded unattestable by server
verification (§1 above — the matcher/scorer ran and found no attestable signal) or has
simply never been graded at all (the P3 Edge Functions that would grade it don't exist
yet, per the Status table above).

**Decision (documented here per the gate's own instruction — "if adding it is
disruptive, document it" — rather than widening the enum now):** adding a fourth enum
value (`'pending'` or similar) is deferred to when the scoring Edge Function is actually
built, for two reasons:

1. `ALTER TYPE ... ADD VALUE` cannot run inside the same transaction as other DDL that
   uses the new value (a hard Postgres restriction, not a style choice), so it would
   force `0017_money_path_hardening.sql` to split into two migrations for one column —
   disproportionate for a value nothing yet reads or writes.
2. Nothing in this stage (P3a: schema + RLS only, no Edge Functions) actually
   DISTINGUISHES "never graded" from "graded unattestable" — the distinction only
   matters once a grading process exists to eventually revisit "never graded" rows and
   promote them, which is exactly the P3 Edge Function work the Status table already
   marks "Not started".

**Requirement carried forward, not dropped:** `attestation_grade` MUST be written from
server-side verification only (never client-supplied) — this is now stated on the
column itself (`COMMENT ON COLUMN`, 0017) so it survives independently of this doc. When
the P3 scoring Edge Function is built, add the enum's fourth value in its own migration,
backfill existing `'unattestable'` rows only where they are KNOWN never-graded (not
by assumption), and update `packages/rules`' consumers of this column accordingly.

## `[unverified]` — H2 approximation mode's vault grants (post-P3a re-gate)

`tools/db/test-migrations-no-migration-owner.sh`'s `H2_MODE=approximation` run grants
its freshly-created, NOSUPERUSER-but-database-owning role (`h2_approx_postgres`)
`GRANT ALL ON SCHEMA vault ... WITH GRANT OPTION`, `GRANT ALL ON vault.secrets ... WITH
GRANT OPTION`, and `GRANT ALL ON vault.decrypted_secrets ... WITH GRANT OPTION`, done as
the cluster bootstrap superuser (mirroring what `supabase/tests/shim.sql` already grants
`migration_owner`, both by fiat, in a local Postgres cluster this harness controls
completely).

**`[unverified]`:** this local grant shape is an assumption about what a real Supabase
project's own non-superuser `postgres` role actually holds on `vault.secrets`/`vault.
decrypted_secrets` — it has NOT been confirmed against a real Supabase project or
branch. If the real role's grants on Vault are narrower (e.g. SELECT only, no `WITH
GRANT OPTION`, or scoped differently), then `0018_pseudonym_vault.sql`'s own `GRANT
USAGE ON SCHEMA vault TO private_definer` / `GRANT SELECT (...) ON vault.
decrypted_secrets TO private_definer` step — which needs the connecting migration role
to itself hold grantable privilege on those objects — could fail on a real deploy even
though it passes in both harness modes locally. **Must be verified on a real Supabase
branch (or an equivalent hosted staging project) before this migration set is deployed
for real** — check what `GRANT`s the project's own `postgres` role actually holds on
`vault.secrets`/`vault.decrypted_secrets` (e.g. `\dp vault.secrets` connected as that
role, or `information_schema.role_table_grants`), and narrow both `shim.sql` and
`test-migrations-no-migration-owner.sh` to match reality once confirmed, rather than
leaving the WITH-GRANT-OPTION-by-fiat assumption as the only evidence this path works.

## service-role lint: what it is and isn't (post-P3a re-gate M2)

`tools/service-role-lint` (`supabase/functions/**`, §4.7.1a) is a **guardrail against
accidental misuse and against unreviewed code entering through the import graph** — it
is not, and cannot be, a boundary against a deliberate insider who obfuscates within a
single file.

What it enforces, after the M2 rewrite (post-P3a re-gate): a service-role Supabase
client, and every privileged call on one, is confined to
`supabase/functions/_shared/privileged.ts`'s `withOwnership()` callback; `Deno.env`/
`process.env` are unreachable outside one sanctioned, allow-listed
`Deno.env.get("<literal>")` shape; and — the M2 rewrite — **every import is either a
relative import that resolves inside `supabase/functions`, or a bare specifier that is
an EXACT key in a reviewed import map (`supabase/functions/deno.json` or
`import_map.json`) whose target is on the committed
`tools/service-role-lint/pinned-import-targets.json` allow-list.** Every direct
`http(s):`/`npm:`/`jsr:`/`file:` import, every absolute path, and every import-map
PREFIX mapping (a key or target ending in `/`) is banned outright — host trust is gone
entirely; only a specific, pinned, reviewed target string is ever legitimate. Adding a
new dependency is therefore a reviewed diff against that one file, not a judgment call
the lint makes about a host or a package name at import time.

**Round 2 (post-P3a re-gate):** the model above still let five real bypasses through —
an import-map **key** that is itself a relative path (remapping a specific in-tree
import to an arbitrary target), a `deno.lock` `"redirects"` table swapping a pinned
target's resolved URL, and a config file living ANYWHERE above `supabase/functions`
(the repo root, or any directory between it and `supabase/functions`) whose own remap
applies to everything inside. Closed by: every import-map key must be a bare specifier
(no `./`, `../`, `/`, or `:`); every import-map target must be an exact pinned string —
relative targets are banned outright, not merely escape-checked; every `deno.json`/
`deno.jsonc`/`import_map.json`/`deno.lock` found anywhere between `supabase/functions`
and the repo root (the nearest ancestor containing `.git`) is itself a finding,
regardless of content; and every `deno.lock` under `supabase/functions` is validated —
a non-empty `redirects` table is banned outright, and every `remote` key must itself be
an exact pinned target. See `tools/service-role-lint/src/config.ts`'s own header
comment for the full R1–R5 + lockfile model.

**What it is not:** a static AST check over ONE file's syntax cannot see across a
process boundary, cannot see what a legitimately-imported, pinned dependency's OWN code
does once invoked, and cannot stop a sufficiently determined author from smuggling
privileged behaviour into logic this lint has no rule for at all (an infinite space of
possible JS/TS shapes — the whole reason M1/M3 moved from a deny-list of syntactic
bypasses to allow-lists in the first place still applies structurally: an allow-list
narrows the *legitimate* surface, it does not enumerate and block every possible
*illegitimate* one). It also only ever runs over `supabase/functions/**` — it says
nothing about privileged code anywhere else in the repo, and nothing about what an
Edge Function's *runtime* dependencies (an already-pinned, already-imported package)
do once actually executing.

**The backstop is the DB side, not this lint.** Row-Level Security (`FORCE ROW LEVEL
SECURITY`, never removed, on every table), the `private_definer` ownership/allow-list
model (`private.function_inventory`, `private.definer_policy_allowlist`), and Supabase's
own service-role/anon/authenticated grant boundaries are what actually stop a privileged
action from succeeding, regardless of what code path — reviewed or not, inside
`supabase/functions` or entirely outside it — attempted it. This lint's job is narrower
and earlier: catch an accidental or unreviewed privileged-access shape in Edge Function
code *before* it ships, as a second, in-loop signal alongside code review — not to be
the boundary review substitutes for.

### `private_definer` GUC-read policies: exact-form requirement, and its known limit (post-P3a re-gate round 3/4)

Every `private_definer`-scoped RLS policy that reads a `delete_my_data`-family GUC
(`current_setting('app.delete_my_data.target_*', true)`, `0016_private_definer.sql`)
must wrap that read in exactly `nullif(current_setting('<name>', true), '')`. Why:
`set_config(name, value, true)` ("is_local") only reverts at the end of the ENCLOSING
transaction, not at `RESET`/the calling function's own return — once that transaction
commits, the GUC keeps reading `''` (Postgres's own placeholder for a custom GUC that
has ever been `SET LOCAL` in the session, never `NULL`) for the rest of the session, and
PostgREST/Supavisor reuse connections across unrelated requests. A bare
`current_setting(...)::uuid` then raises on the very next unrelated query that touches a
table carrying that policy, on the same connection — and because Postgres OR's together
every candidate policy for a role without short-circuiting past one that errors, ONE
unwrapped policy anywhere on a table breaks every later query against it (round 3's
concrete repro: `private.offer_code_play_guard`'s own re-read broke because of an
unrelated, older policy's unwrapped cast). `nullif(x, '')` turns the leftover `''` into a
genuine SQL `NULL` before any cast runs — `NULL::uuid` is simply `NULL`, never an error,
and fail-closed behaviour (no rows visible with no real target set) is unchanged.

**Enforced by `tools/db/verify-function-inventory.mjs` check #7**, which requires the
EXACT deparsed form `NULLIF(current_setting('<name>'::text, true), ''::text)` —
tightened (round 4) after the original, looser "is there a `NULLIF(` immediately before
this `current_setting(`" check was confirmed (probe policies on a scratch cluster) to
pass a wrong sentinel (`nullif(current_setting('x', true), 'zz')`) and a missing
`missing_ok` argument (`nullif(current_setting('x'), '')`, which raises outright if the
GUC was never set in this session at all) — both are distinct, also-live failure shapes
the loose check would have silently accepted.

**Known, accepted limit — one level of indirection only (round 4 follow-up).** Check #7
also follows a policy to any function it depends on (via `pg_depend` on the policy
object, not a name-matching heuristic) and applies the same exact-form rule to that
function's body — this catches a policy that reads the GUC through a wrapper function
(e.g. `USING (user_id = private.guc_uid())`) rather than inline. It follows **exactly one
hop**: if that wrapper function's own body calls a SECOND function which is the one that
actually reads the GUC, the second function is never inspected. There is no
wrapper-of-a-wrapper in this project's migrations today (confirmed by grep) — this is a
documented residual for a future one, not a live bug, and the same class of "no bound on
how many hops a static check can chase" limitation named for the dynamic-code-key check
just below.

**A named, accepted residual (should-fix 3, post-P3a re-gate): the dynamic-code-key
checks stop at one hop.** The lint flags a computed member access whose key is built
directly from a string-building expression (`obj["constr" + "uctor"]`), and — should-fix
3 — a computed access whose key is a `const` in the SAME flat pass over the file,
initialised from such an expression (`const k = "constr" + "uctor"; obj[k]`), via a
same-scope-only name lookup, not real lexical scope analysis. This is explicitly a
one-hop heuristic, not a data-flow analysis: moving the string-build a second hop away
(through a function return, an object property, a `let`/reassignment, a destructure, or
simply a same-named `const` shadowed in a nested scope this flat lookup cannot
distinguish from the outer one) defeats it. **This residual is accepted, not treated as
a bug to keep chasing** — the reviewer's own M2 finding is instructive here: every round
of closing one more single-file obfuscation shape has been met with a next one, because
there is no bound on how many hops JS/TS syntax offers before a static check without a
real data-flow/points-to analysis runs out of syntactic shapes to enumerate. A
sufficiently motivated single-file rewrite can still hide a built key from this (or
almost any static AST) check; the DB-side controls in the paragraph above are what
actually stop the resulting privileged action from succeeding regardless.

### Edge-layer requirement: pin `--config` at deploy time `[unverified]` (BLOCKING round 2, post-P3a re-gate)

The lint's config model (round 2) closes every confirmed live bypass by validating
every `deno.json`/`deno.jsonc`/`import_map.json`/`deno.lock` under `supabase/functions`
**and** by refusing to allow any config or lockfile to exist anywhere between
`supabase/functions` and the repo root at all — see `tools/service-role-lint/src/
config.ts`'s own header comment for the full model (R1–R5 plus the lockfile
requirements). That closes what the lint can see.

**`[unverified]`:** this lint reproduces `deno run`'s own directory-walk config
resolution (confirmed against real Deno 2.5.2 by the reviewer) — it has **not** been
confirmed that the Supabase CLI's `deploy` command, or the hosted Edge Runtime that
actually executes a deployed function, resolves `deno.json`/`import_map.json` the
identical way. If either resolves configs differently (a different search order, a
different default config path, or an `--import-map`/`--config` flag defaulting to
something this lint never inspects), a config file this lint never validates at all
could still govern the real deployed function's imports.

**Requirement, until that is verified:** the deploy command for every Edge Function in
this project MUST explicitly pin `--config supabase/functions/deno.json` (the one
config file this lint always treats as authoritative for the whole functions tree,
absent a validated per-function override). Do not rely on Supabase CLI's own default
config discovery. This is a deploy-tooling requirement, out of this stage's scope to
implement (no deploy pipeline exists yet) — recorded here so it is not lost, and to be
verified against the real Supabase CLI/Edge Runtime before this project's first real
deploy.

## Ops note: a Vault key referenced by the pseudonym key registry must never be deleted (should-fix 2, post-P3a re-gate)

`private.pseudonym_key_registry` (`supabase/migrations/0018_pseudonym_vault.sql`) is
**append-only by construction**, not merely by policy: `app.attestation`/
`app.attestation_shift_log`'s `*_hmac_id` columns carry a `NOT DEFERRABLE` foreign key
into it, so once a key id is registered, no role — not `service_role`, not
`private_definer`, not even a superuser bypassing RLS entirely — can remove that row
from the registry while any live row still references it (M1 BLOCKING, post-P3a
re-gate). This is deliberate: the earlier design let `service_role` delete a registry
row directly, which is exactly what let a single `DELETE` silently drop a key from
`private.delete_my_data`'s discovery loop and leave that key's rows undeleted after a
"successful" account deletion.

**The operational consequence:** deleting the *underlying Vault secret itself*
(`vault.secrets`) for a key id that is still referenced by the registry is **not**
blocked by this FK (there is deliberately no FK from the registry into Vault's own
schema — see `0018`'s own note on Vault-upgrade fragility) — but doing so makes
**every** account deletion fail closed, not just the one row that used that key.
`private.delete_my_data`'s discovery loop iterates the *whole* registry unscoped by
user (it has to — it doesn't know which rows belong to the target user until it tries
each key), so a single Vault key that no longer resolves (`vault.decrypted_secrets`
returns no row, or a secret shorter than 32 bytes) raises for **every** subsequent
`private.delete_my_data(uuid)` call, for **every** user, until the key is restored or
its secret value is put back.

**Before retiring or rotating out a `pseudonym_hmac_*` key in Vault:** confirm no
`app.attestation`/`app.attestation_shift_log` row still carries that key's id in
`player_pseudonym_hmac_id`/`staff_pseudonym_hmac_id` (or accept that deletion becomes
fail-closed system-wide until the key is restored). There is currently no supported
"deregister a key" operation — the registry has no legitimate delete path at all, by
design (see M1's own migration comment). A real key-retirement workflow, if one is ever
needed, is a live follow-up, not something to route around this constraint for.

## Accepted follow-ups at the P3a gate PASS (2026-09-25, round 12, `fb0ac15`)

The P3a combined correctness and security gate passed with no blocking findings. The gate accepted
these open items as follow-ups. None of them is exploitable against the current schema.

1. **Check 7b coverage.** 7b checks only functions a policy directly depends on. It does not
   follow chains two or more levels deep, it does not look at views referenced from policy
   subqueries (`pg_get_viewdef`), and it does not look at settings read through dynamic SQL,
   through `pg_settings`, or through `coalesce(nullif(...,''), '')`. The gate confirmed none of
   these shapes exists today. To close it: walk `pg_depend` recursively and include view
   definitions. As a backstop, every new GUC-scoped policy gets a session-reuse pgTAP test in the
   style of `supabase/tests/matrix/12_guc_session_reuse.sql`.
2. **Service-role lint residual.** Deliberately obfuscated code inside a single file is out of
   scope for the lint. The database-side controls are the backstop (see "service-role lint: what
   it is and isn't").
3. **Vault key ops rule.** Never delete a Vault key that `private.pseudonym_key_registry` still
   references. If one is deleted, every `delete_my_data` call fails closed.
4. **Unverified deploy requirement.** The "pin `--config` at deploy time" requirement is still
   `[unverified]`. Check it against the real Supabase CLI and edge runtime before the P3 Edge
   Functions ship.
5. **`attestation_grade`.** It still defaults to `'unattestable'`. Adding a "never graded" enum
   value is deferred until the scoring Edge Function exists.

## P3c status (2026-09-25): the Edge Functions now exist

`POST /v1/evidence`, `POST /v1/evidence/batch`, `POST /v1/checkin/challenge` (incl. prefetch) and
`checkin-token` are built (`supabase/functions/{evidence,evidence-batch,checkin-challenge,checkin-token}/`).
Status against this doc's own items:

- **§1 (server-derived fields) — enforced.** `fixId`/`facilityId`/`verificationTier`/`geometryKind`/
  `insideBuffer`/`challenge`/`token` grade are all derived server-side
  (`supabase/functions/_shared/evidence/derive-fix.ts`), never taken from the client beyond raw
  lat/lng/accuracy/timestamps. `insideBuffer` is REAL PostGIS `ST_DWithin` against
  `app.catalog_course.boundary`/`radius_center` (`Repo#matchFix`, `privileged.ts`) — not a stub.
  `fixId` is pinned to unpadded base64url at the request-shape layer
  (`supabase/functions/_shared/evidence/request-shape.ts`).
- **§2 (each row type from its own path) — enforced.** `staff_presence`/`booking`/`receipt_green_fee`/
  `arccos`/`garmin`/`ghin` are rejected outright at `POST /v1/evidence` (`request-shape.ts`'s
  `REJECTED_SOURCES`) — none of their own server paths (partner-attest, the P7 webhook, the receipts
  endpoint, the P8 connectors) are built yet. `courseId: null` (vs. omitted) is rejected as a
  structural error, matching the OMITTED-not-null rule.
- **§3 (limits/fraud signals) — enforced for what's in scope.** Clock skew > 24h, a `failed`-grade
  fix, and an on-play quarantine (`scorePlay`'s own `excludedRows`) each raise a `fraud_signal` at
  intake (`evidence/handler.ts`). Rate limits (60/user/h evidence, 200/device/day, 2000/user/day
  batch, 30/user/h challenges, 10 unused prefetched/device) are wired via `private.hit_rate_limit`.
- **§4/§5 (persisting, receipts) — money-path columns persisted verbatim** (`money`, `heldReview`,
  `hardSignal`, `policyVersion`, `inputDigest` from the scorer's own result, never recomputed).
  Receipts/fingerprints are out of scope this round (no receipt-upload endpoint yet).
- **Catalog skew (AT 8/15, G3-10) — implemented, with one honest deferral.** *(The int
  `catalogVersion` form described in this bullet is superseded by P3e round 2, H1: the intake
  contract is now the site version STRING `yyyymmdd-gitsha7` — see the P3e section at the end.)* Version-window
  classification (current/within-5-releases-and-30-days / stale / forged) is real
  (`_shared/catalog/classify-version.ts`). Ed25519 manifest-signature verification is a REAL,
  unit-tested primitive (`_shared/catalog/signature.ts`, Web Crypto — confirmed working under both
  Deno 2.5.2 and this session's Node/vitest run) against a new, empty-by-default
  `app.catalog_signing_key` table (0019 migration) — so every "newer version" claim fails closed to
  `422 catalog_forged` in THIS environment (no keys are provisioned; the §4.8 key-rotation/
  registration workflow and the import pipeline are both still out of scope). The 202-queued outcome
  IS reachable in code (a registered key + a real signature would produce it — see
  `classify-version.test.ts`), just not exercised by a real signed manifest in this environment.
- **Deploy `--config` pin (item 4 above) — no longer merely `[unverified]` on the lint side.** This
  session confirmed directly (`deno check`) that resolution DOES depend on passing
  `--config supabase/functions/deno.json` explicitly — omitting it, even when invoked from the repo
  root with the config file present at a fixed relative location, fails import-map resolution. The
  hosted Edge Runtime's own deploy-time resolution is still unconfirmed; the requirement stands.
- **Attestation — out of scope, exactly as directed.** `checkin-token` grades every submission via
  the G3-08 "no token" rule (real App Attest/Play Integrity verification isn't built), so it can only
  ever produce `unattestable` or `failed` this round, never `attested`.
  **[UPDATE 2026-10-03: closed for clients that send an attestation. `checkin-token` now verifies App Attest / Play Integrity and can
  grade `attested`; see "checkin-token: real attestation verification" at the end of this document.]**
- **Dependency pin bump:** `supabase/functions/deno.json`'s `"zod"` entry moved from `3.23.8` to
  `4.6.5` (matching `packages/rules`' own zod dependency, now that the scoring vendor tree actually
  imports it for real) — `tools/service-role-lint/pinned-import-targets.json` updated to match, plus
  three new pins (`@noble/hashes@2.4.0`'s two entry points, `tz-lookup@6.1.25`, and
  `deno.land/std@0.224.0/http/server.ts` for `Deno.serve` — see `evidence/index.ts` et al.'s own
  comments on why a direct `Deno.serve` reference doesn't pass the lint outside `privileged.ts`).

## P3c gate round 2 (`dbe1aaa`) — 6 HIGH + 6 MEDIUM found only by running privileged.ts for real

The reviewer found every one of the 12 blockers below by running the REAL `privileged.ts` and the
handlers under Deno against a real Postgres cluster — CI never did that (pgTAP exercises raw SQL
directly; the vitest unit suite ran only against an in-memory FAKE `Repo`). Item 0 closed that blind
spot: `supabase/tests/integration/{repo,handlers}.deno.test.ts` now run the exact same modules against
the harness cluster `tools/db/test.sh` builds, wired into the `db-tests` CI job for BOTH harness modes
(`tools/db/test-deno-integration.sh`). Every item below has its own test in that suite (or in the pgTAP
matrix, for the schema-level ones) — see that suite's own file for the file:line detail; this section
records the DECISIONS, not the diff.

**HIGH, all fixed:**

1. **Day-2 evidence** (item 1). `Repo#evidence.listForPlay` now filters on a REAL `app.evidence.local_date`
   column (0019 migration), capped at `ABSOLUTE_ROW_CAP`; only evidence ids the scorer actually
   contributed get linked to a play, never every candidate row. A facility-level (no `courseId`) row is
   a `listForPlay` candidate for every course-anchored play at that facility+date, but `app.play_evidence`'s
   own `UNIQUE (evidence_id)` (0017) means it can still only ever back ONE of them — a second course's
   intake that also tries to link it now no-ops cleanly (`ON CONFLICT (evidence_id) DO NOTHING`) instead
   of raising a raw, unhandled constraint violation, which is what the FIRST version of this fix did
   until this suite's own "second course, same day" test caught it.
2. **Writes silently lost.** Every `withOwnership` callback runs inside one real `sql.begin()` transaction.
   `resolveLedgerId` callers assert the id kind and require a real `catalog_facility`/`catalog_course` row.
3. **Forged facility/course pairing.** `422 facility_course_mismatch` unless `courseFacilityId(course) === facility`.
4. **Challenge-window clamp and token reuse.** `Repo#checkinToken.consumeForFix` is one atomic UPDATE
   enforcing ownership + single-use + device match + `issued_at <= capturedAt <= expires_at`, all in one
   WHERE clause. Found and fixed along the way: `issued_at`'s column `DEFAULT now()` is the
   *transaction's* start time, not the moment the INSERT statement itself runs — under real advisory-lock
   contention (item 8) a queued transaction could compute `expires_at` (from real wall-clock time, read
   AFTER the wait) later than `issued_at + 24h` (frozen at transaction start, BEFORE the wait), tripping
   `checkin_challenge_expires_at_bounded` with a raw exception. Both `checkin_challenge.insert` and
   `checkin_token.insert` now write `issued_at` via `clock_timestamp()` explicitly instead of the column
   default, keeping the two values internally consistent regardless of lock-wait duration.
5. **`withOwnership` ignores the actor.** `buildRepo(trx, actor)` closes over `actor.uid` once; no `Repo`
   method takes a user-identity parameter. `tools/service-role-lint/test/with-ownership.test.ts` — which
   used to assert the OLD, bug-pinning shape (`buildRepo()`, zero args) — now asserts the real one.
   **Found by this same class of bug, NOT on the coordinator's list:** `Repo#rateLimit.hit`'s bucket key
   was never scoped by actor at all — every caller (`evidence/handler.ts`, `checkin/challenge-handler.ts`,
   `checkin/token-handler.ts`) passes a bare key like `"evidence:user"`, relying on the Repo to scope it
   per actor the same way every other method does; `privileged.ts` never prefixed it with `uid`, so every
   user on the platform shared the SAME `private.rate_limit_bucket` row for that bucket — a GLOBAL rate
   limit, not a per-user one. Fixed (`${uid}:${bucketKey}`) and covered by its own integration test.
   **Also found, a distinct bug in the same review pass:** `Repo#device.ensureOwn` never wrote the
   caller's own `deviceId` into the new row — it inserted with no `id` column, letting
   `DEFAULT gen_random_uuid()` mint an unrelated random id, and returned THAT. Since no endpoint response
   ever echoes the resolved device id back to the caller, the client's own `deviceId` was silently
   discarded on first registration: every later request with that same id would find nothing, mint
   ANOTHER stray row, forever — defeating both device-identity continuity and the item 7 device cap (a
   retry looks like a brand-new device every time), and separately breaking this suite's own
   concurrent-prefetch-request test (three "concurrent requests for the same device" turned out to be
   three unrelated devices). Fixed: `ensureOwn` now inserts WITH the caller's own id
   (`ON CONFLICT (id) DO NOTHING` + fallback SELECT, the same idempotent-insert idiom
   `evidence.insertIdempotent` already uses).
6. **Client claims mint badge credit.** `connect_iq`, `health_route`, `file_import` are rejected the
   same way `REJECTED_SOURCES` rejects `staff_presence`/`booking`/etc — recorded as a **deferral**:
   until a real server-side matcher (`@golfraven/matching`, wired against the raw route/points the same
   way `Repo#catalog.matchFix` already does for a single fix) or the P8 connector exists, these three
   sources have no honest server-derivable signal at all, and stay rejected outright rather than trusting
   the client's own `insidePolygon`/`k4bPassed`/`matchedRoute`/`sourceAllowListed` claims. `holes` for
   `foreground_dwell` is derived from `Repo#catalog.courseHoleCount`, never a client-submitted field —
   request-shape.ts rejects a submission that still sends one as an unrecognized key.

**MEDIUM, all fixed:**

7. **Device-limit bypass.** `deviceId` is validated as a UUID at the request-shape layer (a non-UUID used
   to reach the driver before failing, surfacing as an unhandled 500). Rate-limited before any write. 20
   devices/user cap, checked via `findOwn` (never creates a row) BEFORE `ensureOwn` (which does) — a
   rejected over-cap request never creates the device row it's about to reject.
8. **Count-then-insert races.** `pg_advisory_xact_lock`, inside the transaction, for both the prefetch-cap
   count (`Repo#challenge.countOpenPrefetched`) and the queued-catalog cap (`Repo#evidence.countOpenQueued`).
   Proven under REAL concurrency (`Promise.all` of overlapping `withOwnership` transactions racing the
   same counter) — both at the raw `Repo` level and through the real HTTP-shaped handler.
   **Also found along the way, a signed/unsigned bug:** `pg_advisory_xact_lock(int, int)` takes two
   SIGNED 32-bit integers; the lock-key hash used `h >>> 0` (always non-negative, up to 4294967295) —
   roughly half of all possible hash outputs exceeded `int4`'s max positive value and failed outright
   ("value ... is out of range for type integer") the instant a real query bound one. Fixed to `h | 0`
   (same 32 bits, reinterpreted as signed — the lock's own collision behaviour is unchanged).
9. **Replay with a changed payload.** If a replayed insert was not new, the fresh payload's derived
   content is compared (canonical JSON) against what is already persisted; a mismatch is `409
   evidence_conflict`, never silently re-scored from the unpersisted fresh content.
10. **Body cap.** `readJsonBody` streams with a running byte count, cancelling past `MAX_BODY_BYTES`
    (64 KB) rather than buffering an unbounded body before checking size. Invalid UTF-8 is a clean `400`.
11. **Tombstoned-id rewrite.** `reconstructEvidenceForScoring` uses the RESOLVED (survivor) facility/course
    ids for the fresh row, never the raw submitted (possibly tombstoned) ones.
12. Resolved by item 6 (`health_route` is now rejected outright, so its own quarantine fraud signal never
    fires — there is nothing left to quarantine).

**Conditions on the BYPASSRLS design (all satisfied):**

- Every `withOwnership` transaction runs `SET LOCAL ROLE service_role` first and asserts
  `current_user = 'service_role'` before building a `Repo` — proven this round from a connecting role
  that is genuinely NOT already `service_role` in either shape the harness models: a true superuser
  (`postgres`, HARNESS_MODE=superuser) and a NOSUPERUSER NOBYPASSRLS table owner (`migration_owner`,
  HARNESS_MODE=restricted) both pass every integration test.
- No per-request GUC is used anywhere in `privileged.ts` — every query parameterizes `actor.uid`/ids
  directly as bound values, so the `SET LOCAL` + `nullif(current_setting(...,true),'')` requirement has
  nothing to apply to in this file (noted because the gate asked for this to be stated explicitly).
- `0019:35` — `service_role` has `SELECT` only on `app.catalog_signing_key` (`INSERT`/`UPDATE`/`DELETE`
  revoked/never granted); `checkin_token` has no `DELETE` grant for `service_role` (only
  `private_definer`'s `delete_my_data` path, or the `ON DELETE CASCADE` from `checkin_challenge`, may
  remove a row). Both proven this round as real permission failures under `service_role`
  (`supabase/tests/integration/repo.deno.test.ts`'s own "BYPASSRLS grants" tests), not merely an absent
  row in a grants listing.

**Should-fix, done:**

- **Supply chain, partial.** `privileged.ts`'s `postgres` (postgresjs) import moved from a raw
  `https://` string literal to a bare specifier resolved through `supabase/functions/deno.json`'s
  reviewed import map (+ `tools/service-role-lint/pinned-import-targets.json`) — the same discipline
  every other third-party dependency in this codebase already has, closing the gap where bumping the pin
  used to be an inline edit invisible to that discipline. `@supabase/supabase-js` could **not** be moved
  the same way: `tools/service-role-lint/src/config.ts` unconditionally bans any import-map entry whose
  value contains `@supabase/` or `supabase-js`, regardless of pinning — a deliberate, pre-existing
  hardened rule closing exactly the evasion this move would otherwise open (routing a service-role-shaped
  client through the map from a file OTHER than `privileged.ts`, invisible to the AST's own
  specifier-text ban). It stays a direct pinned URL import, same as before this round. A real `deno.lock`
  is committed at `supabase/tests/deno.lock` (deliberately NOT under `supabase/functions/` or on the
  ancestor path up to the repo root — both are separately banned by the same lint, confirmed this round —
  `supabase/tests/` is a sibling directory, invisible to either check) and both `deno check` (CI's
  `verify` — actually `db-tests` — job) and `tools/db/test-deno-integration.sh` now run with
  `--lock=supabase/tests/deno.lock --frozen`.
- **Nonce.** `checkin-token` requires the raw nonce POST /v1/checkin/challenge returned and compares its
  hash (`Repo#challenge.consume(challengeId, nonceHash)`) — a challenge id alone is no longer sufficient.
- **Challenge kind.** A real `app.checkin_challenge.kind` column (0019), not inferred from TTL width.
- **Batch limits.** The 2,000/user/day cap is counted per item; each item explicitly skips the live 60/h
  bucket; `MAX_BATCH_ITEMS_PER_REQUEST` is 100 (chosen to fit a reasonable wall-clock budget given each
  item runs roughly a dozen sequential round trips inside one transaction).
- **Revoked kid.** A revoked `kid` on the declared version returns `422 catalog_stale` (AT 15) —
  checked independently of the normal skew-window arithmetic, proven against a real
  `app.catalog_signing_key` row.
- **Signed payload.** *(Superseded by P3e round 2, H1 — see the P3e section at the end of this
  document.)* The manifest signature is verified over the REAL P1 manifest statement — the
  `golfraven/catalog/v1/manifest\n` domain tag plus the canonical JSON of
  `{catalogVersion, contractVersion, kid, manifestSha}`, exactly the bytes
  `tools/catalog/src/manifest.ts#manifestStatementBytes` signs — never a payload this codebase
  invented. (This bullet used to pin `golfraven-catalog-manifest-v1:${version}:${manifestSha256}`,
  which the P1 signer never produces.)
- **Play status.** `provisional` below the 0.50 badge threshold, `confirmed` at or above it (except a
  `disputed` row, which a re-score never silently un-disputes).
  **Found along the way:** the INSERT's own `status` value was a bare `CASE WHEN ... THEN 'confirmed'
  ELSE 'provisional' END` expression with no cast — Postgres resolves a CASE expression's own result type
  to plain `text`, not `app.play_status` (unlike a bare string literal in a VALUES list, which gets the
  usual "unknown"-literal-to-column-type coercion) — so this INSERT would have failed on every real
  Postgres, always, the very first time a fresh play row was ever created. No unit/fake-repo test could
  catch it, since the fake Repo never runs real SQL. Fixed with an explicit `::app.play_status` cast.
- **Rate limit.** `checkin-token` has its own 60/user/h limit.
- **Scorer reasons.** Never returned to the client — logged server-side only on the one path that can
  reach them (a structural `scorePlay` failure, which only happens if THIS handler's own row assembly is
  malformed; a client can't reach it).
- **Quarantine fraud signal.** Includes `play_id`.
- **Concurrent re-score.** `Repo#play.upsertFromScore` holds an advisory lock on `(uid, courseId, playDate)`
  for the duration of its own transaction.
- **Nits.** `generate-bundle.sh` strips each vendored file's own `//# sourceMappingURL=...` comment (the
  referenced `.map` is deliberately not copied in, so the comment was a dangling reference). The vendor-
  freshness test (`rules-vendor-freshness.test.ts`) now regenerates into a scratch tmpdir and diffs
  against the committed tree, rather than regenerating IN PLACE and diffing against a pre-run snapshot —
  it can no longer leave the working tree modified on a failing or interrupted run.

**Updated Accepted follow-ups (append to the P3a gate's own list above):**

6. **BYPASSRLS role scope (P3c gate round 2, "Conditions on the BYPASSRLS design").** Every
   `withOwnership` transaction activates `service_role` explicitly and verifies it — safe regardless of
   what role the connection string authenticates as. Before the FIRST real deploy, move to a dedicated
   `NOBYPASSRLS` login role for the Edge Function connection, with `SET LOCAL`-scoped, actor-parameterized
   policies or `SECURITY DEFINER` functions replacing the current blanket `service_role` BYPASSRLS model,
   and route reads through the JWT-forwarded client + the `api.my_*` views (0010) per build plan §4.7.1a,
   rather than through `privileged.ts` for everything. **Owner: P3 backend lead.**
7. **Attestation is still client-hinted (G3-08), not verified.** `checkin-token`'s own
   `hardwareSupportsAttestation` boolean is the one part of "no token" grading a real client CAN honestly
   self-report even before real App Attest/Play Integrity verification exists (the platform capability
   check itself, not a signed assertion) — every submission this round can only ever grade `unattestable`
   or `failed`, never `attested`. This is a genuine, standing gap (not merely a placeholder default) until
   real attestation verification is wired in; `checkin/token-handler.ts`'s own header carries the same
   note. Restated here per the P3c gate round 2 instruction to record it in this document too.
   **[UPDATE 2026-10-03: the stub is gone. A request that carries an attestation is verified (iOS: registered key, signature, `rpIdHash`,
   strictly increasing counter advanced atomically; Android: Play Integrity `requestHash`, package, certificate digest,
   `deviceIntegrity`, freshness) and can grade `attested`; a request that carries none is `failed` when the claim says capable OR when the
   server's own evidence says the device can attest (a registered key / a prior `attested` token), otherwise `unattestable`. What stays open:
   a client that has never registered a key and claims `hardwareSupportsAttestation:false` is still believed.]**
8. **`connect_iq`/`health_route`/`file_import` have no honest server-derivable signal yet (P3c gate round
   2, item 6).** Rejected outright at `POST /v1/evidence` (`request-shape.ts`'s `REJECTED_SOURCES`),
   the same as `staff_presence`/`booking`/`receipt_green_fee`/`arccos`/`garmin`/`ghin` — none of their own
   server-side verification paths (a real route/points matcher via `@golfraven/matching`, or the P8
   connector) are built yet. Revisit once either exists.

## P3c gate round 2 status (this round): Deno integration suite counts

`supabase/tests/integration/{repo,handlers}.deno.test.ts` — 14 + 11 = 25 tests, run via
`tools/db/test-deno-integration.sh` (called by `tools/db/test.sh`, against the SAME live cluster the
pgTAP matrix and the two concurrency scripts already ran against, before teardown), both HARNESS_MODE=
superuser and HARNESS_MODE=restricted: **25 passed, 0 failed, in both modes.**

## P3c gate round 3 fixes (`b7c41cc` re-gate: 2 blocking HIGH + 3 blocking MEDIUM)

Everything from round 2 was confirmed fixed by the coordinator's own round-3 message. This round closed
the 5 blocking findings plus the should-fix list, file:line pointers below.

**Blocking HIGH 1 (changed-replay bypass) + HIGH 2 (AT 3 regression) — one fix.** The OLD replay check
only ran when the stored row showed up in that call's own `listForPlay` window (a changed `localDate`
skipped it entirely), and `consumeTokenForFix` ran BEFORE any replay check at all (so an identical retry
saw its own token already consumed). Fixed by moving the whole replay/conflict decision to the FRONT of
the pipeline, before any side effect:

- `app.evidence` gets a real `input_hash text NOT NULL` column — a canonical SHA-256 of the ENTIRE parsed
  submission (`evidence/handler.ts:207` `computeInputHash`), covering content a fix-bearing source's own
  natural `source_ref` (keyed on fixId alone) cannot distinguish. `supabase/migrations/0019_evidence_intake.sql`
  §7 (nullable → backfill-from-`source_ref`-digest → `NOT NULL`, since 0019 is still unmerged).
- `Repo#evidence.findExisting(source, sourceRef)` (`privileged.ts:428`, `types.ts`'s `Repo.evidence`
  interface) — the FIRST repo call `handleEvidenceIntake` makes (`evidence/handler.ts:393`), before rate
  -limiting, device resolution, token consumption or any fraud signal.
- A match with an identical `input_hash` is an idempotent replay: `buildReplayResult` (`evidence/handler.ts:311`)
  re-derives the response purely from already-persisted rows (a fresh `listForPlay` + re-score, itself
  idempotent) — zero new side effects. A mismatch is `Errors.conflict` (`http.ts:75`, new 409 helper) —
  `evidence/handler.ts:398`.
- The SAME post-insert race window (a concurrent request winning between `findExisting` and the actual
  insert) is closed by comparing `insertIdempotent`'s own returned `inputHash` on the `!wasNew` branch —
  `evidence/handler.ts:514` (queued-catalog branch) and `:671` (accepted branch).
- Integration tests (both single and batch mode; both harness modes): `supabase/tests/integration/handlers.deno.test.ts`
  ("blocking HIGH 1", "blocking HIGH 2"), `supabase/tests/integration/evidence-batch.deno.test.ts` ("blocking
  HIGH 1+2 (batch mode)"), plus the unit-level fake-repo equivalents in `supabase/tests/unit/evidence-handler.test.ts`.

**Blocking MEDIUM 3 (rate-limit hits roll back on 4xx).** `private.hit_rate_limit` raised on over-limit in
the SAME statement that did the increment — an uncaught `RAISE EXCEPTION` aborts the transaction that
statement ran in, discarding that SAME statement's own increment; wrapping the call in its own transaction
did not change this, since the abort was already scoped to one statement. Fixed in TWO parts:
`private.hit_rate_limit` no longer raises at all — it always returns the post-increment count
(`supabase/migrations/0020_rate_limit_no_raise.sql`, a NEW migration since 0007/0016 are merged; the
`SET ROLE private_definer` / `GRANT CREATE ON SCHEMA private` bracketing at `:75-76` is required because
0016 already narrowed `private_definer` to schema-USAGE-only, and `CREATE OR REPLACE FUNCTION` needs BOTH
ownership and schema CREATE, not ownership alone — found by actually running this against
`HARNESS_MODE=restricted`/the H2 check, never reachable from a superuser bootstrap connection alone).
`privileged.ts#rateLimit.hit` (`privileged.ts:224-286`) now opens its own separate `db.begin()` (not the
request's shared `trx`) and compares the returned count to its own max. Integration test: `supabase/tests/integration/repo.deno.test.ts`
proves N calls against a real Postgres cluster each increment by exactly 1, the (max+1)th correctly flips
`ok:false` without losing the count; `supabase/tests/matrix/07_rate_limit.sql` updated for the no-raise
contract (5 assertions, was 4).

**Blocking MEDIUM 4 (batch: one failing item aborts the whole transaction).** Fixed via a new
`privileged.ts#withOwnershipBatch` (`privileged.ts:854`) — one outer `db.begin()`, each item in its OWN
`trx.savepoint(...)`, so a failing item's writes roll back to just its own savepoint while every earlier
item's committed work is untouched. `evidence-batch/index.ts:75` calls it; rate-limiting (MEDIUM 3's own
fix) runs first per item, so a cap-crossing item is rejected as `rate_limited` without even attempting its
now-pointless savepoint-scoped work. Integration tests: `supabase/tests/integration/evidence-batch.deno.test.ts`
("one bad item among good ones", "items after the per-user daily cap... earlier items still commit").

**Blocking MEDIUM 5 (local_date comes from the client label, not the server).** For a fix-bearing source
(`foreground_checkin`/`foreground_dwell`), `localDate` is now derived server-side from the anchor fix's own
`capturedAt` resolved into the facility's real IANA tz (`evidence/handler.ts:221` `localDateInTz`, `:235`
`anchorCapturedAtMs`, `:276` `assertServerDerivableLocalDate`) — a mismatching client label is rejected
with 422 `local_date_mismatch` before any side effect, never silently overridden. For a date-only source
(`self_report`/`health_workout`, no client-controlled capturedAt to derive a date from at all), the
client's own label is accepted only inside a bounded window of facility-local "today"
(`evidence/handler.ts:252` `assertSelfReportDateWindow`; `SELF_REPORT_WINDOW_DAYS_BACK`/`_FORWARD` = 30/1
— no plan-stated number found in this checkout, same documented-default footnote as `MAX_DEVICES_PER_USER`).
`app.evidence.local_date`'s own column comment (0019 §5) rewritten to match. Integration tests: the
UTC-date-traveller case (`supabase/tests/integration/handlers.deno.test.ts`, anchored to the most recent
real occurrence of 02:00 UTC so it is correct on whatever real date the suite runs, never a hardcoded one)
gets the facility-local date accepted and the naive UTC date rejected; out-of-window `self_report` gets
422 `local_date_out_of_window`.

**Should-fix items, all done:**

- **Clamp live fixes to the challenge window, not the token's.** `Repo#checkinToken.consumeForFix`
  (`privileged.ts:753`) now joins `app.checkin_challenge` and clamps `capturedAt` against ITS
  `issued_at`/`expires_at` (120s live / 24h prefetched, whichever the challenge actually was) instead of
  the token's own separate 15-minute redemption TTL, which could let a capturedAt up to ~13 minutes stale
  pass as valid for a live challenge.
- **`ensureOwn` on another user's device id: 409, not 500.** `privileged.ts:650` — `Errors.conflict("device_owned_by_other_user", ...)`
  replaces the old bare `throw new Error(...)`.
- **CI pin-proof step.** `.github/workflows/ci.yml`'s new "deno cache --frozen (proves the pinned hashes,
  tamper-evident)" step. This session independently RE-TESTED the premise ("`deno check --frozen` doesn't
  verify JS module hashes") directly — a copy of `supabase/tests/deno.lock` with one remote entry's hash
  byte-flipped, run via both `deno check --frozen` and `deno cache --frozen`, against both a fresh empty
  `DENO_DIR` and an already-warm one — and in Deno 2.5.2, `deno check --frozen` ALSO failed with `error:
  Integrity check failed for remote specifier` (exit 10) in every combination tested, not merely `deno
  cache --frozen`. `[unverified — training-knowledge premise as originally stated, and NOT reproduced this
  session on Deno 2.5.2]`. The dedicated step is added regardless — see its own inline comment for the
  three reasons a `check`-only step doesn't fully cover on its own even so.
- **0019 `local_date`/`input_hash` nullable → backfill → NOT NULL.** Both already fixed as of round 2's
  own close-out edit to 0019 (see that migration's own comments); round 3 additionally needed the SAME
  `helpers.sql`/pgTAP-fixture/concurrency-script `input_hash` backfill across every raw
  `INSERT INTO app.evidence` this repo's own test fixtures make directly (`supabase/tests/helpers.sql`,
  `supabase/tests/matrix/11_money_path.sql`, `supabase/tests/matrix/13_evidence_intake.sql`,
  `tools/db/test-replay-concurrency.sh`) — none of these go through `Repo#evidence.insertIdempotent`, so
  the new NOT NULL column needed a value at every one of these call sites too.
- **`test-deno-integration.sh` portability.** No longer depends on a manually pre-warmed `DENO_DIR` tied to
  one sandbox's own paths: it now creates and owns a scoped, throwaway `DENO_DIR` via `mktemp` when the
  caller hasn't already supplied one (cleaned up on exit), and discovers a usable `DENO_CERT` from whichever
  of `DENO_CERT`/`NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`/`CURL_CA_BUNDLE` is BOTH set and actually readable by
  the invoking OS user (never a hardcoded path) — verified end to end in this session as the `postgres` OS
  user, with no manual pre-warming, against a genuinely fresh, throwaway `DENO_DIR` the script created
  itself, using a copy of this sandbox's own CA bundle made world-readable under `/tmp` (never touching
  `/root`'s own permissions) so the fallback-discovery loop had something real to find.

**Updated Deno integration suite counts:** `supabase/tests/integration/{repo,handlers,evidence-batch}.deno.test.ts`
— 14 + 16 + 4 = 34 tests (up from 25 at round 2 — new: HIGH 1/HIGH 2/MEDIUM 5's own integration tests, plus
the new `evidence-batch.deno.test.ts` file), both HARNESS_MODE=superuser and HARNESS_MODE=restricted:
**34 passed, 0 failed, in both modes.** pgTAP matrix: 387 assertions (up from 386 — `07_rate_limit.sql`'s
own no-raise rewrite added one).

**Updated Accepted follow-ups (tightening #7 from the P3c gate round 2 append above — append-only, that
entry is left as originally written; this is the CURRENT, more precise statement of the same gap):**

9. **Follow-up 7, tightened (P3c gate round 3).** `hardwareSupportsAttestation` is fully CLIENT
   -CONTROLLED (a platform-capability self-report, never a signed assertion), and a tokenless fix
   hard-codes it to `false` regardless of what the device could actually support (`derive-fix.ts:91`) — so
   a MISSING token never grades `failed` under G3-08's own rule, only `unattestable`. Restated precisely:
   **no offer issuance or reward activation may rest on a P3c-graded fix until real App Attest/Play
   Integrity attestation verification ships.** This is not a hypothetical future tightening — it is the
   condition under which P3c's own scoring output is safe to build on top of at all.
   **[UPDATE 2026-10-03: the verification now ships in code (not yet against a real device or Google: every vendor interaction is `[unverified]`
   until the week-1 spike runs on hardware). The condition above is therefore met for the verifier and still unmet for live evidence.]**
10. **`supabase/tests/deno.lock` does not govern `supabase functions deploy` (P3c gate round 3).** This
    lockfile is a TEST-time artifact only — `tools/db/test-deno-integration.sh` and the CI `deno check`/
    `deno cache` steps are the only things that read it. The real Supabase CLI's own deploy-time dependency
    resolution for the Edge Runtime is a SEPARATE mechanism this repo has not yet verified pins the same
    way (the pre-existing "pin `--config` at deploy time" `[unverified]` flag, follow-up 4 at the P3a gate
    and restated in `privileged.ts`'s own header, already covers the `--config` half of this; this note
    covers the LOCKFILE half specifically). Deploy-time pinning verification is a pre-deploy item, not
    something this round's test-time lockfile discipline substitutes for.

## P3c gate round 4 fixes (`a2e7e00` re-gate: 1 blocking HIGH + 1 blocking MEDIUM)

Round 2's five blockers were confirmed fixed and reproduced as fixed. This round's own two findings, both
in the round-3 rate-limit/replay refactor itself:

**Blocking HIGH ("5 concurrent requests deadlock the pool").** `privileged.ts`'s round-3 `Repo#rateLimit.hit`
opened its own `db.begin()` (a SECOND pooled connection) from INSIDE a `buildRepo` callback that already
held one (the request's own `withOwnership`/`withOwnershipBatch` transaction) — against a `max: 5` pool,
5+ concurrent requests each waiting on a 6th connection that would never free up is a real deadlock
(postgres.js has no acquire timeout at all). Fixed by moving EVERY rate-limit hit to a pre-transaction
phase:

- `Repo` no longer has a `rateLimit` member at all — a structural removal (`types.ts`), not a
  deprecation, so nothing can reintroduce the deadlock by calling it from inside a transaction again.
- `privileged.ts`'s new top-level `hitRateLimitForActor(actor, bucketKey, windowSeconds, max)` — the
  ONE place a rate-limit hit opens its own connection, designed to be called BEFORE
  `withOwnership`/`withOwnershipBatch` even opens.
- `evidence/handler.ts`'s new `planEvidenceRateLimitChecks(rawBody, options)` — parses the submission and
  returns the bucket checks to hit, pure, no DB access, computable entirely from `actor.uid` (the
  caller's own concern) and the client-supplied `deviceId` (always present, never a DB-resolved value).
- `evidence/index.ts`, `checkin-challenge/index.ts`, `checkin-token/index.ts` all call
  `hitRateLimitForActor` before their own `withOwnership` call.
- `evidence-batch/index.ts` rewritten as an explicit two-phase flow: phase 1 hits every item's rate
  limit(s) with no transaction open at all (preserving "one hit per item slot, even a structurally
  -invalid one"); phase 2 runs `withOwnershipBatch` (per-item savepoints, unchanged from round 3) only for
  items that passed phase 1.
- Defense in depth, not the fix itself: `privileged.ts`'s pool now sets `connect_timeout: 10` (seconds)
  and `connection.idle_in_transaction_session_timeout: 30_000` (ms); `http.ts#handleRequest` now races
  every request against a 15s timeout, returning 503 (`Errors.serviceUnavailable`) if exceeded.
- Integration test: `supabase/tests/integration/repo.deno.test.ts`, "P3c gate round 4, blocking HIGH: 2x
  pool max concurrent withOwnership calls, each ALSO hitting a rate limit, complete within a bound (no
  deadlock)" — 10 concurrent requests (2x the real pool's `max: 5`) against a 20s bound; completed in
  under 50ms in both harness modes.

**Blocking MEDIUM ("replays skip every rate limit").** The round-3 `findExisting` check ran BEFORE any
rate-limit hit, so a replay flood (150 replays in the reviewer's own repro) never touched its bucket at
all, and each replay still re-scored and re-upserted the play row. Both closed by the SAME HIGH fix above:
rate-limiting now happens in the pre-transaction phase, before `handleEvidenceIntake` — and therefore
`findExisting` — is ever reached, replay or not; and `buildReplayResult` no longer re-scores or re-upserts
at all — it reads the already-persisted `app.play` row back via a new, plain-SELECT `Repo#play.getForDate`.
Integration/unit tests: `supabase/tests/unit/evidence-handler.test.ts` ("a rate-limit check runs even for
a replay"; "a replay reads the play row back, it never re-upserts it" — proven by object-reference
identity, not merely equal values).

**Also done:**
- CI comment corrected: the round-3 pin-proof step's own comment claimed `deno check --frozen` "ALSO"
  catches a tampered hash, based on tampering one `deno.land` `.js` file that happens to be its own type
  source. The round-4 reviewer reproduced that this does NOT generalize to an esm.sh `.mjs` reached only
  through a separate `.d.ts` (`supabase-js.mjs`) — `deno check --frozen` left that untouched at exit 0,
  `deno cache --frozen` correctly failed at exit 10. This session independently reproduced the same result
  and corrected the comment (`.github/workflows/ci.yml`).
- A REAL tamper test added to CI (not merely a comment claim): a new "deno cache --frozen tamper test"
  step copies the lockfile, flips one byte of the `supabase-js.mjs` hash, and asserts `deno cache --frozen`
  exits non-zero against it — failing the build if it does NOT (`.github/workflows/ci.yml`).
- `Repo#challenge.insert`'s dead `staffUserId` parameter removed (`types.ts`, `privileged.ts`,
  `checkin/challenge-handler.ts`, `fake-repo.ts`) — staff/partner-attest issuance is out of this round's
  scope and no real call site ever passed anything but `null`.

**Accepted follow-ups (append-only):**

11. **Batch history import (AT 10) doesn't work this round.** `evidence-batch`'s own items go through the
    SAME `local_date` derivation as a live submission: a fix-bearing item's `localDate` must exactly match
    its own `capturedAt` resolved into the facility's tz, and a date-only item's `localDate` is bounded to
    facility-local-today ±30/+1 days (`evidence/handler.ts`'s `assertServerDerivableLocalDate`). Neither
    shape fits a REAL historic import (a fix-bearing item genuinely captured weeks or months ago; a
    date-only item legitimately outside a 30-day window) — and clock-skew (`> 24h from server "now"`)
    would raise a `clock_skew` fraud signal on every genuinely old, correctly-dated fix in a real historic
    batch, which is exactly wrong for backfilled data. Revisit the ±30-day window and the clock-skew check
    on historic/late-synced batch fixes once `file_import`/`health_route` (currently rejected outright,
    `request-shape.ts`'s `REJECTED_SOURCES`) return with a real server-side verification path — batch
    should move to event-time-only checks (build plan §4.7 item 8's own "items are scored with event-time
    velocity only," out of this round's scope) rather than the live-submission clock/date rules it
    currently reuses.
12. **A concurrent duplicate FIRST-submission can still write a duplicate `clock_skew` signal (low).** Two
    truly concurrent requests for the SAME genuinely-new (user, source, source_ref) — a real race, since
    `findExisting` returns null for BOTH before either has committed — both independently compute clock
    skew and, if skewed, both call `fraudSignal.insert("clock_skew", ...)` before either knows it lost the
    `insertIdempotent` race. The LOSER's own race-safety branch (`evidence/handler.ts`, the `!inserted.
    wasNew` path) deliberately does not undo side effects it already made in good faith (see that branch's
    own comment) — so a duplicate `clock_skew` row can land for the same real event. Low severity: `app.
    fraud_signal` is an audit/review trail, not a money-path enforcement point, so a duplicate entry is
    review-queue noise, not a security gap. Closing it would mean either moving the clock-skew check to
    run only after the transaction's winner is known (losing the "signal every attempt" property this
    round's other fixes deliberately established) or de-duplicating fraud_signal rows by content — a
    genuine design trade-off, not a one-line fix, and left open.

## Accepted follow-ups at the P3c gate PASS (2026-09-25, round 4, `57657e4`)

The P3c security gate passed with no blocking findings. The reviewer drove the real entrypoints over
HTTP against Postgres. The earlier follow-ups (6–12) still stand. These were added at the pass:

13. **503 after a successful commit (should-fix before real clients use prefetch).**
    - The 15 s HTTP request race can return 503 while the transaction later commits.
    - This is safe for evidence: a retry returns `replay:true`.
    - For `checkin-challenge` and `checkin-token`, secrets are issued but never delivered. A 503'd
      prefetch can fill the device's 10-challenge cap for 24 hours, and a 503'd token leaves its
      challenge consumed.
    - Fix either way:
      - make the database give up before the HTTP timeout (`SET LOCAL statement_timeout` and
        `lock_timeout` below 15 s inside `withOwnership`);
      - or make challenge and token issuance idempotent by a client request id.
14. **Nits.**
    - `buildRepo` still takes a `db` parameter it no longer uses.
    - The CI lockfile tamper step treats any non-zero exit as a pass. It should assert exit 10 or
      the "Integrity check failed" message, so a lockfile path or parse error can't pass.

## P3d status (2026-09-25): `DELETE /v1/me`, `GET /v1/me/export`, `POST /v1/me/push-token`, and the
## two P3c gate PASS follow-ups (13, 14)

Three new Edge Functions (`supabase/functions/{me-delete,me-export,me-push-token}/index.ts`, thin
entrypoints over `_shared/me/{delete,export,push-token}-handler.ts`, the same DI'd-pure-handler
pattern every other endpoint this round uses) plus one new migration
(`supabase/migrations/0021_export_my_data.sql`).

- **`DELETE /v1/me` (build plan AT 6).** Calls the existing, gate-passed `private.delete_my_data`
  (0015) through `Repo#me.deleteMyData()` — never reimplemented. Confirmed, before writing any code,
  that `delete_my_data` already deletes `app.push_token` rows (`push_token.user_id` is a `delete_row`
  policy row, 0014) and already voids unredeemed/`vouchered` special-marker entitlements (its own
  bespoke `UPDATE ... SET state = 'void' WHERE state IN ('earned','held_review','redeemable',
  'vouchered')` block) — neither needed new code. What P3d adds: the provider-revocation SEAM
  (`_shared/me/provider-revocation.ts`) for AT 6's "revokes connectors" — reads
  `signin_provider_token`/`connector_account` provider names BEFORE `deleteMyData()` removes the
  rows, and returns one explicitly-`deferred: true` outcome per provider, naming exactly why: Apple/
  Google sign-in revocation is build plan O12/AT 19, P4, not this round; golf-app connector (GHIN/
  Arccos/Garmin) revocation is P8, conditional and not yet built at all. The LOCAL grant row is
  deleted either way. Supabase Auth user deletion (`deleteAuthUser`, `privileged.ts`) uses the Auth
  Admin API — `@supabase/supabase-js`'s `auth.admin.deleteUser`, the SAME allow-listed privileged
  module every other service-role-shaped client construction already goes through — called AFTER the
  DB transaction commits (it is an HTTP call, not a Postgres statement, so it cannot join that
  transaction), and treats an already-deleted/missing user as success, not a failure, for retry
  idempotency. `[unverified — no live Supabase Auth instance in this environment; the Admin API's
  exact error shape for a missing user is read broadly (404, or a message naming "not found") rather
  than pinned to one exact shape]`. Idempotent end to end: `private.delete_my_data`'s own generic
  pass is a no-op against an empty match set (proven this round,
  `supabase/tests/integration/me-handlers.deno.test.ts`, "a retry ... is idempotent").
- **`GET /v1/me/export`.** New `private.export_my_data(uuid) RETURNS jsonb` (0021) — the READ-ONLY
  twin of `private.delete_my_data`, walking the SAME `private.pii_retention_policy` registry
  (0014_hardening.sql) the delete function itself is driven from, so the two "which tables are
  personal" answers cannot drift apart (one registry, read by both). `SECURITY DEFINER`, owned by
  `private_definer` — the SAME defense-in-depth pattern `delete_my_data` already established (S1
  close-out), reusing the EXISTING `..._r`-suffixed SELECT policies 0016 already created as every
  DELETE/UPDATE policy's mandatory read-visibility companion, under the SAME
  `app.delete_my_data.target_user_id`/`target_email` GUCs — zero new RLS policies added by 0021.
  `app.attestation_shift_log` is deliberately excluded (documented in 0021's own header): it carries
  no FK to `auth.users` at all and has no row in the registry — `delete_my_data` reaches it through a
  wholly separate pseudonym-matching mechanism, out of scope for "discovered from the registry."
  Actor-scoped only (every row is looked up `WHERE <column> = p_user_id`, and the only id ever passed
  in is the caller's own verified `actor.uid`). Documented size bound: `EXPORT_SIZE_BOUND_BYTES` = 8
  MiB (`export-handler.ts`), `[inference]` — no plan-stated number exists for this endpoint; a breach
  is logged, never truncated or refused.
- **`POST /v1/me/push-token`.** `app.push_token` already existed (0003_player_core.sql) — no new
  migration needed for it. Registers/updates via `ON CONFLICT (user_id, device_id) DO UPDATE`
  (line 832: "replaced on reinstall"). "Cap the number of tokens per user" is enforced as the SAME
  `MAX_DEVICES_PER_USER` (20) cap `evidence/handler.ts`/`checkin/challenge-handler.ts` already use,
  checked BEFORE creating a new device row — since `push_token`'s own PK is `(user_id, device_id)`, a
  token is capped at one per device by construction, so the device cap IS the token cap.
- **Follow-up 13 ("503 after a successful commit"), CLOSED — corrected/extended, P3d gate round 2.**
  The ORIGINAL wording below described only the `statement_timeout`/`lock_timeout` half; the gate
  round 2 pass found a SECOND, distinct hole the per-statement timeouts alone cannot close (a
  transaction of MANY SHORT statements, none individually near either timeout, whose CUMULATIVE
  wall-clock time still exceeds the HTTP race) and a live O(n²) batch-scoring bug — both fixed and
  documented in the new "P3d gate round 2" section below. Kept here verbatim for what it still
  correctly describes: `withOwnership`/`withOwnershipBatch` (`privileged.ts`) run
  `SET LOCAL statement_timeout = '10s'` and `SET LOCAL lock_timeout = '5s'` as their first two
  statements after activating `service_role` — both comfortably under `http.ts`'s 15 s request race,
  `lock_timeout` firing first on purpose (a lock wait is the specific failure shape this follow-up
  names). A new `mapPgTimeoutError` maps Postgres SQLSTATEs `57014` (`query_canceled`,
  statement_timeout) and `55P03` (`lock_not_available`, lock_timeout) to `Errors.serviceUnavailable()`
  (503), in both functions (including per-item, inside `withOwnershipBatch`'s savepoint loop). Proven
  end to end against a REAL held lock from a SECOND session, exactly as specified:
  `supabase/tests/integration/me-handlers.deno.test.ts` holds an `ACCESS EXCLUSIVE` lock on `app.play`
  for 20 s from a second connection while a concurrent `withOwnership` call is made — the call fails
  with a real 503 in ~5 s (not the full 20 s), 0 rows are written afterward, and (the full
  evidence-intake-pipeline variant of the same test) the checkin token's `consumed_at` is still `NULL`
  — its own `consumeForFix` UPDATE rolled back with everything else in the same transaction. Passed in
  BOTH harness modes.
- **Follow-up 14 ("nits"), CLOSED.** `buildRepo`'s unused `db` parameter removed
  (`buildRepo(trx, actor)`/`buildRepo(sp, actor)`, not `buildRepo(db, trx, actor)`); confirmed with
  `deno check` and the service-role lint that nothing else referenced it. The CI lockfile tamper step
  now asserts `deno cache --frozen`'s exit code is exactly `10` OR its output contains "Integrity
  check failed" — re-verified empirically THIS round (Deno 2.5.2, the same tamper fixture the round-3
  pin-proof step already builds): exit 10, "Integrity check failed" present. A non-zero exit from an
  unrelated cause (a network error, a config typo) no longer masquerades as a pass.
- **Test counts (superseded — see "P3d gate round 2" below for the FINAL counts).** This bullet
  originally reported 398 pgTAP assertions and 42 Deno tests, from before the gate round 2 fixes
  (the export blocking-HIGH rewrite, should-fixes 1–3) added more of both. Left here only so the delta
  in the new section below is legible; do not cite this bullet's numbers as current.
- **Deferrals, restated plainly.** Real Apple/Google sign-in-provider revocation (O12/AT 19) and real
  golf-app connector revocation (P8) are NOT built this round — see `provider-revocation.ts`'s own
  header. `deleteAuthUser`'s exact behaviour against a REAL Supabase Auth instance (not merely its
  own reading of the `@supabase/supabase-js` Admin API's TypeScript surface) is unverified in this
  environment, same class of gap as this doc's other `[unverified — training knowledge]` flags.
  Follow-ups 6–12 (the P3c gate round 2/3 "Accepted follow-ups" list, above) are UNCHANGED by this
  round — P3d did not touch the BYPASSRLS role-scope design, the attestation-still-client-hinted gap,
  or the batch-history-import/duplicate-clock-skew items; only 13 and 14 were in this round's scope.
  Gate round 2 adds its OWN, separately documented deferrals — see below.

## P3d gate round 2 (2026-09-25): export blocking HIGH, should-fixes 1–3

The gate on commit `269b1bf` failed on one blocking HIGH (export leak) and asked for three
should-fixes "now." All four are closed this round; nothing here was deferred without saying so.

- **BLOCKING HIGH: `GET /v1/me/export` leaked other users' data and secret token material — CLOSED.**
  `0021_export_my_data.sql` rewritten from scratch. Root cause: the original version exported every
  row the registry matched through EITHER a `delete_row` OR a `set_null` column via `to_jsonb(t)` —
  for a `set_null` column the matched column names the ACTOR (e.g. `redeemed_by_staff`,
  `invited_by`, `cleared_by`), not the subject, so a staff member's own export pulled in whole rows
  belonging to whichever PLAYERS that staff member had redeemed offer codes for or reviewed; two
  connector/token tables (`connector_account`, `signin_provider_token`) were exported via bare
  `to_jsonb(t)` with no column allow-list, including `refresh_token_ciphertext`/`dek_wrapped`/
  `kek_id`; and `fraud_signal`/`review_item` exported their full `detail` jsonb, including another
  user's uuid and fraud-review internals.

  Fix: a new `private.pii_export_policy` registry (`export` / `exclude` per table, mirroring
  `private.pii_retention_policy`'s own shape) with a fail-closed coverage check — `export_my_data`
  raises if any `pii_retention_policy` table has no matching row — and `export_my_data` itself
  rewritten to 20 EXPLICIT, hand-written `SELECT <named columns> ... WHERE <subject column> =
  p_user_id` statements, never `SELECT *`/`to_jsonb(t)` blind. Every subject-column choice is a
  genuine subject specific column (`attestation.player_user_id`, `entitlement.user_id`,
  `receipt_fingerprint.user_id`, `audit_log.actor_user_id`), never a `set_null` actor column — no
  table is EVER reached through `redeemed_by_staff`/`invited_by`/`cleared_by`/`resolved_by`.
  `connector_account` is exported with only `api.my_connector_account`'s own column set (no token
  columns at all, §4.4). `signin_provider_token` is excluded entirely (reason recorded in the
  registry). `fraud_signal`/`review_item` are restricted to `id, kind, created_at` — no `detail`, no
  `cleared_by`/`resolved_by` — the "actions you took" shape the fix instructions allowed. Every
  other table's SELECT lists every real column BY NAME, excluding every secret/hash/pepper/key
  column that exists on it (`devicecheck_token_hash`, `code_hmac`, `pepper_kid`, `nonce_hash`, etc).

  New tests (`supabase/tests/matrix/14_me_export.sql`, rewritten, 24 assertions, up from 11):
  registry-sync (every `pii_retention_policy` table has a `pii_export_policy` row, no empty reasons);
  a whole-export regex scan (both a staff export and an admin export) for
  `ciphertext|dek_wrapped|kek_id|token_hash|code_hmac|pepper_kid|nonce_hash` — absent; a whole-export
  scan of the serialized JSON text for the OTHER seeded player's uuid — absent, for both the staff
  export and the admin export; `signin_provider_token` key entirely absent from the JSON;
  `connector_account`'s exported object never includes `refresh_token_ciphertext`; no `"detail"` key
  appears anywhere under `fraud_signal`/`review_item` in any export; staff's own export has ZERO
  `offer_code`/`entitlement` rows belonging to the player they redeemed for (proving the `set_null`
  leak is closed); the player still gets their own full export. File:line:
  `supabase/migrations/0021_export_my_data.sql:1` (header explaining the fix),
  `supabase/tests/matrix/14_me_export.sql:1`.

- **Should-fix 1: timeouts — CLOSED.**
  - `SET LOCAL transaction_timeout = '12s'` added to `withOwnership`/`withOwnershipBatch`
    (`supabase/functions/_shared/privileged.ts`, gated behind a cached `server_version_num >= 170000`
    check — PG16 has no such GUC). Verified empirically (scratch PG17 cluster, this round) that
    `transaction_timeout` is WALL-CLOCK across the whole transaction, including idle-between-statement
    gaps, and that exceeding it is a FATAL, connection-TERMINATING event (not a catchable SQLSTATE) —
    `mapPgTimeoutError` extended to also map a postgres.js `CONNECTION_CLOSED` driver code to 503.
    New test: `supabase/tests/integration/me-handlers.deno.test.ts` — 13 real repo calls separated by
    real 1 s waits (no single statement or gap near `statement_timeout`/`lock_timeout`) still 503s at
    ~12 s, 0 rows committed; self-skips with a printed reason on PG16 (confirmed: skip message
    printed, 46/46 still pass).
  - Batch rescoring changed from once-per-item to once-per-DISTINCT-play
    (`supabase/functions/_shared/evidence/batch-handler.ts`, `_shared/evidence/handler.ts`'s new
    `finalizeScoringForKey`): every batch item now always defers its own scoring
    (`deferScoring: true`), grouped by `(facilityId, courseId, localDate)`, with ONE dedicated
    finalize savepoint per group. A same-batch replay of an unscored sibling also defers
    (`handler.ts`'s `buildReplayResult`, new `batchMode` parameter) instead of hitting the
    now-unreachable-in-batch-context "no play yet" raise. New tests confirm: 3 items for the same
    play share one play id and one scoring pass; a group of size 1 behaves exactly like an un-batched
    submission; 2 different plays in one batch score independently.
  - File:line: `supabase/functions/_shared/privileged.ts` (`mapPgTimeoutError`,
    `supportsTransactionTimeout`, the three `set local` statements inside `withOwnership`/
    `withOwnershipBatch`); `supabase/functions/_shared/evidence/handler.ts` (`EvidenceIntakeDeferred`,
    `HandleEvidenceIntakeOptions`, `finalizeScoringForKey`); `supabase/functions/_shared/evidence/
    batch-handler.ts:1` (full header explains the two-phase design and why the FIRST attempt — "the
    group's last item scores for real" — was wrong).

- **Should-fix 2: `delete_my_data` post-condition + the "`_r` companion" gate — CLOSED.**
  New migration `supabase/migrations/0022_delete_my_data_post_condition.sql` redefines
  `private.delete_my_data` (0015 is merged; same signature, so `CREATE OR REPLACE FUNCTION`
  preserves its OID/grants — nothing to re-grant) using 0020's own ownership-bracketing convention
  (`GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ... RESET ROLE;
  REVOKE CREATE ...`). Adds a fail-closed POST-CONDITION at the end of the function body: iterates
  `private.pii_retention_policy` (the SAME registry the deletion itself is driven from) and RAISES if
  any subject row still remains for any table/column, with ONE documented exclusion
  (`entitlement.user_id` — redeemed/terminal rows are INTENTIONALLY retained, per O9/O10, not a bug).

  New static check (`tools/db/verify-function-inventory.mjs` check 8, `supabase/tests/matrix/
  10_function_inventory.sql` check 11, pgTAP `plan()` bumped 9→10): every table with a DELETE/
  UPDATE(/ALL) RLS policy applying to `private_definer` also has a SELECT(/ALL) "`_r` companion"
  policy applying to `private_definer` on the SAME table (table-level existence, not exact
  expression matching — a legitimate companion is not always byte-identical to its sibling). A
  from-scratch parse of every `private_definer`-scoped policy across every migration (this round)
  found ZERO current violations among 98 such policies — this check is protective/regression-
  preventing, not a fix for a live bug; it is what makes the runtime post-condition TRUSTWORTHY in
  the first place (without a guaranteed SELECT companion, a missing/misscoped DELETE/UPDATE policy
  could let a delete silently no-op while the SAME missing companion also blinds the post-condition's
  own read-back — reporting success while the row survives, exactly the gap named).

  "Export must fail when a registry table has no SELECT visibility" is addressed the SAME way, not by
  a separate runtime check inside `export_my_data`: from inside plpgsql a SELECT narrowed to zero rows
  by a missing policy is byte-for-byte indistinguishable from a SELECT that correctly found no data
  (RLS filters silently, never raises) — there is no runtime signal to build a "blocked vs. empty"
  check on. The `_r`-companion check above is what guarantees every table `export_my_data` reads from
  has REAL SELECT visibility in the first place, which is the only place this class of bug is
  actually observable — reasoning recorded in `0022_delete_my_data_post_condition.sql`'s own header.

  File:line: `supabase/migrations/0022_delete_my_data_post_condition.sql:1` (full reasoning in the
  header, the post-condition loop is the block right after the storage.objects/public_profile_
  projection cleanup and before the final `v_result` build); `tools/db/verify-function-inventory.mjs`
  (check 8, appended before the final `if (failures.length > 0)`); `supabase/tests/matrix/
  10_function_inventory.sql` (check 11, appended before `SELECT * FROM finish();`).

- **Should-fix 3: rate-limit keys — CLOSED. Chosen: purge inside `delete_my_data`, not `me-delete`'s
  own handler.** Folded into the SAME 0022 redefinition (same transaction as the deletion itself, so
  it is atomic with — and rolls back together with — everything else, and fires for every caller of
  `delete_my_data`, not only the `me-delete` Edge Function specifically). `DELETE FROM
  private.rate_limit_bucket WHERE bucket_key LIKE p_user_id::text || ':%' AND bucket_key <>
  p_user_id::text || ':me-delete:user'` — every bucket `hitRateLimitForActor` ever writes for this
  user is prefixed `<uid>:...` (`privileged.ts`'s own `scopedBucketKey`), so the LIKE-prefix match
  covers every endpoint's bucket with no separate registry. The in-flight `me-delete:user` bucket
  itself is DELIBERATELY KEPT (per the fix instructions' own allowance) so a RETRY of this same
  deletion call — the one legitimate reason to call this endpoint again in a short window — stays
  rate-limited exactly as a first attempt already is, rather than becoming unbounded the moment one
  successful run has purged its own counter. No new RLS policy needed — `private_definer` already
  holds an unscoped DELETE policy on this table (`pd_rate_limit_purge`, 0016), the same one the
  nightly `purge_rate_limit_buckets` sweep already uses, with its own `_r` companion
  (`pd_rate_limit_purge_r`) already present (confirmed by this round's own check 8/11).

  New test (`supabase/tests/matrix/09_delete_my_data.sql`, `plan()` bumped 31→33): seeds one ordinary
  rate-limit bucket and the `me-delete:user` bucket for player A before her deletion, then asserts the
  ordinary bucket is gone and the `me-delete:user` bucket survives. File:line:
  `supabase/migrations/0022_delete_my_data_post_condition.sql` (the DELETE block, right before the
  post-condition loop, with its own header comment); `supabase/tests/matrix/09_delete_my_data.sql`
  (the two new assertions, right after the first `private.delete_my_data(...)` call).

- **Local-harness-only fix (not a code/security change): `tools/db/test-deno-integration.sh`.** The
  Deno integration suite failed in THIS session's sandbox with "Failed to load platform certificates:
  Permission denied" — root cause: `SSL_CERT_FILE` (and sibling vars) remained set to this sandbox's
  proxy CA bundle (`/root/.ccr/ca-bundle.crt`, root-only-readable) even after the script's existing
  DENO_CERT-selection logic correctly left `DENO_CERT` itself unset; Deno's underlying
  rustls-native-certs loader reads `SSL_CERT_FILE` directly, independent of `DENO_CERT`. Fixed by
  unsetting any of `SSL_CERT_FILE`/`NIX_SSL_CERT_FILE`/`CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`/
  `HTTPLIB2_CA_CERTS`/`NODE_EXTRA_CA_CERTS`/`CURL_CA_BUNDLE` that is set but NOT readable by the
  invoking user, leaving any genuinely-usable one alone. Confirmed empirically before landing (a raw
  `deno eval` fetch, su'd to `postgres`, failed before this fix and succeeded after, with no other
  change). File:line: `tools/db/test-deno-integration.sh` (the new loop right after the existing
  DENO_CERT-candidate block).

- **Final test counts, BOTH harness modes (superuser and restricted), plus PG16:**
  - pgTAP matrix: **414 assertions, 14 files, all passed** (up from 398 — `09_delete_my_data.sql`
    31→33, `10_function_inventory.sql` 9→10, `14_me_export.sql` 11→24).
  - Deno integration suite (`supabase/tests/integration/{repo,handlers,evidence-batch,
    me-handlers}.deno.test.ts`): 15 + 16 + 7 + 8 = **46 tests, 46 passed, 0 failed**, in BOTH
    `HARNESS_MODE=superuser` and `HARNESS_MODE=restricted` (up from 42 — evidence-batch 4→7 for the
    batch-rescoring should-fix-1 tests, me-handlers 7→8 for the transaction_timeout test).
  - Re-confirmed on PG16 (`PG_BIN_DIR=/usr/lib/postgresql/16/bin`, `HARNESS_MODE=superuser`): same
    414/414 pgTAP and 46/46 Deno, with the transaction_timeout test self-skipping (printed
    `SKIPPING (server_version_num=160013, < 170000)`) rather than failing.
  - `tools/db/test.sh` exit code 0 in both `HARNESS_MODE=restricted` and `HARNESS_MODE=superuser`
    (and again under PG16), including `verify-function-inventory` OK and `service-role-lint: clean`
    as the harness's own final steps.
  - Unit (vitest, `pnpm --filter @golfraven/rules exec vitest run --config
    ../../supabase/tests/vitest.config.ts`): 114 tests, 12 files, all passed — unchanged by this
    round (no unit-level surface touched).
  - `pnpm -r typecheck`: exit 0 across all 13 TypeScript-bearing workspace projects, 0 errors.
  - `node tools/service-role-lint/dist/cli.js supabase/functions`: clean, no lint changes (checked
    after every edit this round, not only at the end) — no stray `deno.lock` under
    `supabase/functions/` at any point.
  - `gitleaks git . --config .gitleaks.toml --redact --exit-code 1` (checksum-pinned 8.30.1): no
    leaks found (26 commits scanned).
  - `gitleaks dir . --config .gitleaks.toml --redact --exit-code 1`: no leaks found (~11.5 MB
    scanned).

- **Accepted as follow-ups (gate round 2's own list — recorded here, NOT built this round):**
  1. Provider rows (`connector_account`/`signin_provider_token`) are deleted BEFORE P4/P8's real
     Apple/Google/golf-app revocation exists — AT 6's "revokes connectors" stays open (see
     `provider-revocation.ts`'s own seam, P3d status section above). Before shipping P4/P8, either
     refuse deletion while provider rows exist, or queue the revocation material first, so a
     revocation token isn't lost the moment the local row is gone.
  2. A durable pending-deletion marker, plus a background retry of the Supabase Auth user delete, for
     a user who abandons the client after a 500 from `deleteAuthUser` (the DB-side deletion has
     already committed by that point — see the AT 6 bullet above — but the Auth-side user record
     could be left behind indefinitely with no automatic retry).
  3. `storage.objects` receipt deletion on a REAL hosted Supabase project is `[unverified]`, and the
     `LIKE 'receipts/<uid>/%'` fallback pattern possibly never matching a real object's stored name —
     both carried over from P3a, unresolved without a real Supabase Storage instance to test against
     (this environment has none). Verify on a real Supabase branch before relying on it.
  4. Asynchronous or paginated export for an account whose personal data exceeds
     `EXPORT_SIZE_BOUND_BYTES` (8 MiB) — the current behaviour logs the breach and returns the full
     payload anyway, never truncating or refusing.
  5. Push-token hardening not built this round: Expo push-token FORMAT validation (currently any
     non-empty string is accepted), and the fact that the SAME token string can currently be
     registered to several different accounts (no uniqueness constraint on the token value itself,
     only on `(user_id, device_id)`).

## P3d gate round 3 (2026-09-25): B1 (blocking, merged-migration immutability), S1–S4

The re-gate on `5d3f4bc` failed on one blocking item (B1) plus four should-fixes. All five are
closed this round.

- **B1 (blocking): a merged migration (0021) was edited in place — CLOSED.**
  `supabase/migrations/0021_export_my_data.sql` is restored byte-for-byte to its `34d00dc` (origin/main)
  content — confirmed via `tools/db/check-migrations-immutable.sh --base origin/main`, which now also
  runs in CI (`.github/workflows/ci.yml`, `db-tests` job, as its own first step, before the expensive
  Postgres install). Everything gate round 2 changed inside 0021 (the `private.pii_export_policy`
  registry and the leak-fixed `export_my_data` body) moved into the renamed, still-unmerged
  `supabase/migrations/0022_export_and_delete_hardening.sql` — `pii_export_policy` is a brand-new
  table (plain `CREATE TABLE`), and `export_my_data` is redefined via `CREATE OR REPLACE FUNCTION`
  under 0020's own ownership bracket, the SAME one `delete_my_data`'s own redefinition (round 2, also
  relocated into this renamed file) already uses — both functions share ONE `GRANT CREATE ON SCHEMA
  private TO private_definer; SET ROLE private_definer; ... RESET ROLE; REVOKE CREATE ...` bracket.
  The effective, final database state is unchanged from round 2 — only which migration file states it
  changed.

  New CI gate: `tools/db/check-migrations-immutable.sh` — any file under `supabase/migrations/` that
  already exists on the base ref (default `origin/main`) must be byte-identical on the branch being
  checked; a file present on base but missing here (renamed/deleted) is also a failure. Must-fail
  self-test (`--self-test`, run unconditionally as its own CI step before the real check, not a manual
  side step): plants one line into a **`/tmp`-only scratch copy** of a real base-ref migration file
  (the real working tree is never touched) and proves the comparator flags it, then proves the SAME
  file's byte-identical content passes clean. File:line: `tools/db/check-migrations-immutable.sh:1`
  (full header); `.github/workflows/ci.yml` `db-tests` job, the `fetch-depth: 0` addition to its
  Checkout step (needed so `origin/main` actually resolves — a `pull_request` event's default shallow
  checkout has no ref for it) plus the new "Migrations are immutable once merged" step immediately
  after.

- **S1 (do now): export narrowing + a key-set coverage test — CLOSED.**
  - `audit_log.subject_id` is no longer exported at all (was: `id, action, subject_table, subject_id,
    created_at`) — the SAFER of the two offered options, chosen over a per-row conditional: `subject_id`
    is a polymorphic reference that can itself BE another account's own id (e.g. a staff member's audit
    row for an action taken on another user's data), and omitting the column outright cannot leak
    regardless of which row it is, where a conditional is one more place a future edit could get wrong.
  - `purchase_evidence.ref_id` is no longer exported — for a `qr_variant = 'course'` row it is the
    consumed `course_qr_token`'s own nonce hash (an internal matching key, the same reasoning
    `course_qr_token` itself is excluded from export entirely for), not the caller's own data.
  - New pgTAP assertion (`supabase/tests/matrix/14_me_export.sql`, `plan()` 24→27): the export's
    top-level `jsonb_object_keys` exactly equal the set of `action = 'export'` rows in
    `private.pii_export_policy` — an export-classified table with no real `SELECT` block in
    `export_my_data`'s body (or a typo'd `jsonb_build_object` key) would previously pass every OTHER
    assertion in the file silently, since none of them enumerated the FULL key set. Plus two direct
    exclusion assertions for the two narrowed columns above (`purchase_evidence`'s fixture row is given
    a real, non-null `ref_id` value first, so the exclusion assertion proves something, not vacuously
    true against an already-empty column). File:line: `supabase/migrations/0022_export_and_delete_hardening.sql`
    (the `export_my_data` body's two narrowed `SELECT` lists, each with an inline comment), `supabase/tests/matrix/14_me_export.sql`
    (the new key-set + two exclusion assertions, placed right before the "Access control" section).

- **S2 (MEDIUM): batch phase-A-only state leaves evidence with no play, and a live retry 500'd — CLOSED.**
  `evidence/handler.ts`'s `buildReplayResult`: when a course-anchored replay finds no `app.play` row
  and `batchMode` is `false` (the live, non-batch `POST /v1/evidence` path), it now calls the SAME
  idempotent `finalizeScoringForKey` a batch's own phase 2b would have called — reading every
  already-persisted evidence row for that `(facilityId, courseId, localDate)` key and scoring/upserting
  the play NOW, synchronously — instead of throwing `Errors.internal()` (a 500). This is exactly the
  state an interrupted batch (phase A/`withOwnershipBatch` #1 committed, phase B/`withOwnershipBatch`
  #2 failed or never ran) legitimately leaves behind, and a live retry of the same evidence is the
  normal way a client recovers from it.

  Made safe against a SECOND idempotency gap this fix would otherwise reopen:
  `Repo#fraudSignal.insert` (`privileged.ts`) is now deduped on `(kind, detail.playId)` via a single
  atomic `INSERT ... SELECT ... WHERE NOT EXISTS` (not a separate SELECT-then-INSERT, which would leave
  a race window) whenever the caller's `detail` carries a `playId` string — both current
  `quarantined_evidence_row` call sites do. A `detail` with no `playId` (the `clock_skew` kind, keyed
  on `fixIds` instead) has no dedupe key and is left exactly as before, always inserting. This means a
  `finalizeScoringForKey` retry — either a batch's own phase-2b retry, or this fix's new live-retry
  path — never raises a second `quarantined_evidence_row` signal for a play that already has one.

  New tests: `supabase/tests/integration/evidence-batch.deno.test.ts` — inserts an item with
  `{deferScoring: true, batchMode: true}` and stops (simulating phase-A-only), asserts 0 `app.play`
  rows, then replays the SAME item through the plain (non-batch) `handleEvidenceIntake` path and
  asserts `status: "accepted"`, `replay: true`, a real play id, and exactly 1 `app.play` row created.
  `supabase/tests/integration/repo.deno.test.ts` — calls `repo.fraudSignal.insert("quarantined_evidence_row",
  ...)` twice with the SAME `playId` and asserts exactly 1 row; a DIFFERENT `playId` still gets its own
  row; a `clock_skew` call with no `playId` is never deduped. File:line:
  `supabase/functions/_shared/evidence/handler.ts` (`buildReplayResult`'s `!play`/`!batchMode` branch);
  `supabase/functions/_shared/privileged.ts` (`fraudSignal.insert`); `supabase/functions/_shared/types.ts`
  (both methods' doc comments, corrected to describe the new, real shapes instead of "should be
  unreachable in practice").

- **S3: the `CONNECTION_CLOSED` → 503 message no longer claims "timeout" — CLOSED.** `mapPgTimeoutError`
  (`privileged.ts`) used to say `"the database could not complete this request in time (transaction
  timeout) — safe to retry"` for a `CONNECTION_CLOSED` driver error — a specific CAUSAL claim this
  handler cannot actually verify (the connection dropping is also consistent with a network blip, a
  pooler recycling the connection, or the database process restarting; `transaction_timeout` is ONE
  cause among several, not the only one). The message is now `"outcome unknown; retrying is
  idempotent"` — what IS actually true and verifiable: because `withOwnership`/`withOwnershipBatch`
  always run inside a single transaction, the connection dropping means either everything committed or
  nothing did, never a partial write, and every write path this maps onto is idempotent by
  construction. No test pinned the old message text (both existing tests assert only `caught.status
  === 503`), so nothing else needed updating. File:line: `supabase/functions/_shared/privileged.ts`
  (`mapPgTimeoutError`'s `CONNECTION_CLOSED` branch).

- **S4 (MEDIUM): the "`_r` companion" check was table-level, and the post-condition's own comment
  overclaimed what that guaranteed — CLOSED.** Round 2's check (table 8/matrix check 11) asked only
  "does SOME `private_definer` SELECT(/ALL) policy exist on this table at all" — a table with TWO
  classified columns, one with a real companion and one with none, PASSED it, while
  `delete_my_data`'s own post-condition and `export_my_data` both re-read PER COLUMN, under RLS gated
  on that SAME column. Both check 8 (`tools/db/verify-function-inventory.mjs`) and matrix check 11
  (`supabase/tests/matrix/10_function_inventory.sql`) are now COLUMN-level: for every
  `private.pii_retention_policy` (table, column) pair classified `delete_row`/`set_null`, a
  `private_definer` SELECT(/ALL) policy on that SAME table must guard THAT SPECIFIC column with the
  EXACT `nullif(current_setting(...))` form — reusing check 7's own "exact form, not a loose substring"
  parsing discipline (a shared regex built from `pg_get_expr`'s canonical deparsed shape, confirmed
  against this project's own real policies).

  New must-fail fixture (matrix check 12, `plan()` 10→21 across checks 11+12 combined, see the
  file's own per-check comments for the exact breakdown): plants a real, temporary table
  `app.zz_two` with two `delete_row`-classified columns (`user_a`, `user_b`), a `private_definer`
  DELETE policy on BOTH, but a SELECT "`_r` companion" on ONLY `user_a` — the reviewer's own repro
  shape — and asserts the column-level query flags EXACTLY `zz_two.user_b` and not `zz_two.user_a`,
  proving the check is genuinely column-level (a table-level check would have reported BOTH columns
  fine, since the table has *a* SELECT policy). Fixture setup/teardown needed two things not obvious
  up front, both now documented inline where they occur: (a) the file authenticates as `service_role`
  at its own top and never resets, so the fixture first calls `tests.clear_actor()` (a plain `RESET
  ROLE`) to get back to the connecting/owning role, which actually owns schema `app`; (b) inserting
  into `private.pii_retention_policy` at TEST time (not migration time) needs the SAME
  `GRANT INSERT/DELETE ... TO CURRENT_USER` + self-granting temporary policy dance
  `0019_evidence_intake.sql` already needed for this exact table — table ownership alone does not carry
  an implicit DML grant here (FORCE ROW LEVEL SECURITY applies to the owner too, and the owner's
  default DML privileges were explicitly revoked as part of this project's own hardening).

  `delete_my_data`'s post-condition comment (0022) is corrected to describe what the OLD table-level
  check actually guaranteed (less than the prior wording implied) and what the NEW column-level check
  guarantees instead — see that migration's own inline comment, right above the post-condition loop,
  for the full corrected account. File:line: `tools/db/verify-function-inventory.mjs` (check 8, the
  `NULLIF_COLUMN_RE` regex and the per-column existence check that replaced the table-level version);
  `supabase/tests/matrix/10_function_inventory.sql` (check 11, rewritten as a `DO` block; check 12, the
  new `zz_two` must-fail fixture); `supabase/migrations/0022_export_and_delete_hardening.sql` (the
  corrected post-condition comment, and the post-condition loop itself, unchanged in logic).

- **Verify, exact commands and results (all re-run after every fix above, not just once at the end):**
  - `HARNESS_MODE=restricted tools/db/test.sh` → exit 0. pgTAP: **428/428 assertions, 14 files, all
    pass** (up from 414 — matrix checks 10/11/12 and 14's own new assertions). Deno integration:
    **48/48 tests, 0 failed** (up from 46 — the two new S2 tests). `verify-function-inventory: OK`.
    `service-role-lint: clean`.
  - `HARNESS_MODE=superuser tools/db/test.sh` → exit 0, same 428/428 pgTAP, 48/48 Deno.
  - `PG_BIN_DIR=/usr/lib/postgresql/16/bin HARNESS_MODE=superuser tools/db/test.sh` → exit 0, same
    428/428 pgTAP, 48/48 Deno; the transaction_timeout test still self-skips on PG16
    (`SKIPPING (server_version_num=160013, < 170000)`).
  - `tools/db/check-migrations-immutable.sh --self-test` → OK (must-fail and must-pass fixtures both
    behave as expected). `tools/db/check-migrations-immutable.sh --base origin/main` → OK, 0021 is
    byte-identical to `origin/main`.
  - `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` →
    **114/114 tests, 12 files, all pass** (unchanged — no unit-level surface touched this round).
  - `pnpm -r typecheck` → exit 0, 0 errors, all 13 TypeScript-bearing workspace projects.
  - `deno check --config supabase/functions/deno.json --lock=supabase/tests/deno.lock --frozen
    supabase/tests/integration/` → clean, no lockfile drift.
  - `node tools/service-role-lint/dist/cli.js supabase/functions` → `clean`. Its own test suite,
    `pnpm --filter @golfraven/service-role-lint test` (after `pnpm --filter @golfraven/service-role-lint
    run build`) → **112/112 tests, 4 files, all pass**, unchanged (`tools/service-role-lint/test/
    with-ownership.test.ts` was not touched this round — no nits from round 1 recurred).
  - `gitleaks git . --config .gitleaks.toml --redact --exit-code 1` (checksum-pinned 8.30.1): no leaks
    found (27 commits scanned).
  - `gitleaks dir . --config .gitleaks.toml --redact --exit-code 1`: no leaks found (~11.55 MB
    scanned).

- **Touch-scope compliance.** Only files under `supabase/migrations/` (0021 restored, 0022 renamed —
  0023/0024 left untouched, reserved for another builder), `supabase/functions/_shared/`,
  `supabase/tests/`, `tools/db/` (including the new `check-migrations-immutable.sh`), and
  `.github/workflows/ci.yml` were touched this round, plus this append-only doc section. No FORCE RLS
  was removed anywhere; no RLS policy was broadened — the fixtures added this round (`app.zz_two`, the
  temporary `private.pii_retention_policy` self-granting policy) are both created and dropped within
  their own test file's transaction (`BEGIN; ... ROLLBACK;`), never a permanent schema change, and both
  mirror an EXISTING, already-reviewed pattern in this same file/migration set rather than inventing a
  new one. No mutation proof was left in the tree — `check-migrations-immutable.sh --self-test`'s own
  planted-edit fixture is built and compared entirely inside a `mktemp`-created `/tmp` scratch
  directory, cleaned up via its own `trap ... EXIT`, and the negative-path proof used to validate the
  script during THIS session (copying the repo to a separate `/tmp` directory and tampering with the
  copy) was likewise deleted immediately afterward — `git status --short` was re-checked clean of any
  such artifact before this report was written.

## P3d gate round 4 (2026-09-25): F1 (blocking), S-a1, S-a2

The re-review on round 3's own commit (`d7c7127`) confirmed B1 and S1–S4 all fixed, and found one new
blocking MEDIUM (F1) plus two advisory items (S-a1, S-a2) in the round-3 work itself. All three closed
this round; 0021 and earlier remain untouched (verified again below), and 0022 (still unmerged) is
where every schema change in this round went.

- **F1 (BLOCKING): the fraud-signal dedupe dropped a genuinely DIFFERENT quarantine signal on the
  SAME play — CLOSED.** Round 3's `Repo#fraudSignal.insert` (`privileged.ts`) deduped on `(kind,
  detail->>'playId')` alone. Reviewer's repro: a malformed row q1 on play P, finalized, raises 1
  signal; a DIFFERENT malformed row q2 on the SAME play P, finalized again, raised **nothing** — q1's
  earlier signal was read as "already signaled for this play" and q2 was silently dropped, violating
  security doc §3's own "every on-play quarantine... naming the row and its reasons" requirement.
  Independently, the round-3 mechanism (`INSERT ... SELECT ... WHERE NOT EXISTS`) was never safe under
  real concurrency without a backing unique constraint.

  Fix: `evidence/handler.ts`'s new `computeQuarantineDigest` computes a canonical digest over the FULL
  SET of rows a single scoring pass actually quarantined — each row's own `id` (resolved via
  `evidenceForScoring[excludedRow.index].id`, never a separate lookup) plus its `reasons`, doubly
  sorted (each row's own `reasons` array, then the row list itself by id) so the SAME logical
  quarantine set always canonicalizes to the SAME SHA-256 hex digest, stored as `detail.quarantineDigest`
  and computed at BOTH call sites (the single-item scoring tail and `finalizeScoringForKey`).
  `supabase/migrations/0022_export_and_delete_hardening.sql` (still unmerged, appended to — never
  0021 or earlier) adds a partial unique index,
  `fraud_signal_quarantine_dedupe_idx ON app.fraud_signal ((detail->>'playId'), (detail->>'quarantineDigest'))
  WHERE kind = 'quarantined_evidence_row'` — scoped to that ONE kind only, every other fraud_signal
  kind (e.g. `clock_skew`) is completely unaffected. `Repo#fraudSignal.insert` now does
  `INSERT ... ON CONFLICT ((detail->>'playId'), (detail->>'quarantineDigest')) WHERE kind =
  'quarantined_evidence_row' DO NOTHING` against that exact index — atomic, so a REPLAY of the exact
  same quarantine set is still idempotent (round 3's own original ask), a DIFFERENT set on the same
  play raises its own signal, and the whole thing is now genuinely concurrency-safe. A
  `quarantined_evidence_row` call with no `playId`/`quarantineDigest` (should never happen — every
  real call site always computes both) throws loudly rather than silently falling back to an undeduped
  insert.

  Existing-data check before adding the unique index (a live duplicate would make `CREATE UNIQUE
  INDEX` itself fail): grepped every frozen migration (0001–0021) and `supabase/tests/helpers.sql` for
  `quarantined_evidence_row` — the only fraud_signal fixture row anywhere (helpers.sql's own M5 seed)
  has a different kind (`manual_review_seed`), entirely outside this index's partial predicate.

  Tests: `supabase/tests/integration/evidence-batch.deno.test.ts` — the real q1-then-q2 repro through
  the actual scorer/handler path (two already-stored evidence rows, each corrupted in place via a
  direct SQL `summary` override — an unpadded `localDate` and a trailing-space `facilityId`, both
  proven-quarantined shapes from `packages/rules/test/parse-evidence.test.ts`): finalize after q1 →
  1 signal; finalize after q2 joins → 2 signals, the second one's `excludedRows` naming q2 (its
  `facilityId` reason text present only in the second, not the first); a third finalize with no new
  corruption (replaying q1+q2) stays at 2. `supabase/tests/integration/repo.deno.test.ts` — the
  mechanism-level proof directly against `Repo#fraudSignal.insert`: same digest twice → 1 row;
  different digest, same play → 2 rows; different play → its own row; a no-playId kind never deduped;
  and a NEW test, **4 concurrent inserts for the identical `(playId, quarantineDigest)` → exactly 1
  row** (proving the atomic `ON CONFLICT` closes the concurrency gap the old `WHERE NOT EXISTS` had).
  pgTAP (`supabase/tests/matrix/13_evidence_intake.sql`, `plan()` 24→28): the partial unique index
  exists with the right shape (`pg_indexes` introspection), and a live duplicate
  `INSERT ... ON CONFLICT ... DO NOTHING` against it is a genuine no-op (row count stays 1, not
  asserted in prose). File:line: `supabase/functions/_shared/evidence/handler.ts`
  (`computeQuarantineDigest`, right after `toHex`; both call sites' `fraudSignal.insert(...)` calls);
  `supabase/functions/_shared/privileged.ts` (`fraudSignal.insert`, rewritten);
  `supabase/migrations/0022_export_and_delete_hardening.sql` (the new index, appended after
  `delete_my_data`'s `REVOKE CREATE ON SCHEMA private`).

- **S-a1: the immutability gate could pass vacuously on a bad base — CLOSED.**
  `tools/db/check-migrations-immutable.sh`: `--base` is now validated with
  `git rev-parse --verify --quiet "$BASE_REF^{commit}"` (not a bare `rev-parse --verify`, so a ref
  that resolves to something OTHER than a commit is also rejected) and exits 2 if it fails — closes
  the "a typo'd/unfetched ref silently compares against nothing and reports OK" gap. The `|| true` on
  the `git ls-tree` call (was line ~146) is gone — a real `ls-tree` failure now propagates (the script
  already runs under `set -euo pipefail`). The script also now counts how many migration files the
  base actually lists and fails loudly (exit 2) if that count is zero — a base that resolves cleanly
  but genuinely has no `supabase/migrations/` files is the same "vacuous pass" shape reached a
  different way. `--self-test` gained two new must-fail cases, both invoking the real script as a real
  subprocess (not just asserting the failure mode in prose): a nonexistent `--base`
  (`refs/heads/this-ref-does-not-exist-...`) and a `--base` built from git's own well-known empty-tree
  object via `git commit-tree` (a real, valid, but deliberately empty commit — never referenced by any
  branch/tag/ref, so it neither touches the working tree nor becomes reachable history). File:line:
  `tools/db/check-migrations-immutable.sh` (the `^{commit}` validation right after `resolve_base_ref`
  is applied; the `MIGRATION_COUNT` check right after the comparison loop; the two new must-fail cases
  inside `self_test()`).

- **S-a2: on `push: main` the job compared main against itself — CLOSED.** `.github/workflows/ci.yml`'s
  `db-tests` job: on a `push` event (this workflow's `on.push.branches: [main]`), `origin/main` at
  checkout time already equals the just-pushed HEAD — the round-3 step's `--base origin/main` compared
  the new commit's migrations against themselves and could never fail regardless of what the push
  actually changed. Fixed: on `push`, the base is now `github.event.before` (main's tip immediately
  BEFORE this push), passed via `env:` (never interpolated directly into the shell body, per GitHub's
  own event-context hardening guidance) — skipped ONLY when `before` is the all-zero SHA (a brand-new
  branch reaching `main` for the first time, or a history rewrite with no real prior tip; nothing to
  compare against in that one shape). `pull_request` keeps `--base origin/main` unchanged (a PR's base
  is main's current tip, which the PR's own commits have not landed on yet — the round-3 bug never
  applied there). Checkout depth: `fetch-depth: 0` (already set round 3) unshallows the WHOLE history,
  not merely `origin/main`'s tip, so `event.before`'s own commit is always resolvable. Verified locally
  by simulating both branches of the new shell logic with `GH_EVENT_NAME`/`GH_EVENT_BEFORE` env vars
  set by hand — the real-base case ran the real check against `origin/main`'s own prior tip
  successfully, and the all-zero-SHA case printed the skip message without invoking the script at all.
  File:line: `.github/workflows/ci.yml`, `db-tests` job, the "Migrations are immutable once merged"
  step (now carries an `env:` block and the `push`/`pull_request` branch).

- **Verify, exact commands and results (re-run after every fix above):**
  - `HARNESS_MODE=restricted tools/db/test.sh` → exit 0. pgTAP: **432/432 assertions, 14 files, all
    pass** (up from 428 — `13_evidence_intake.sql`'s 4 new F1 assertions). Deno integration: **50/50
    tests, 0 failed** (up from 48 — the new q1-then-q2 repro test and the 4-concurrent-finalizes
    test).
  - `HARNESS_MODE=superuser tools/db/test.sh` → exit 0, same 432/432 pgTAP, 50/50 Deno.
    `verify-function-inventory: OK`. `service-role-lint: clean`.
  - `PG_BIN_DIR=/usr/lib/postgresql/16/bin HARNESS_MODE=superuser tools/db/test.sh` → exit 0, same
    432/432 pgTAP, 50/50 Deno; transaction_timeout test still self-skips on PG16.
  - `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` →
    **114/114 tests, 12 files** (unchanged — no unit-level surface touched this round).
  - `pnpm -r typecheck` → exit 0, 0 errors.
  - `deno check --config supabase/functions/deno.json --lock=supabase/tests/deno.lock --frozen
    supabase/tests/integration/` → clean, no lockfile drift.
  - `node tools/service-role-lint/dist/cli.js supabase/functions` → `clean`. Its own suite
    (`pnpm --filter @golfraven/service-role-lint test`, after `run build`) → **112/112 tests, 4 files**
    (unchanged).
  - `tools/db/check-migrations-immutable.sh --self-test` → OK, including the two NEW must-fail cases
    (nonexistent base; zero-migration base).
  - `tools/db/check-migrations-immutable.sh --base origin/main` → OK — 21/21 migration files
    (0001–0021) byte-identical; confirms 0021 and earlier are STILL untouched this round too.
  - `gitleaks git . --config .gitleaks.toml --redact --exit-code 1` (checksum-pinned 8.30.1): no leaks
    found (28 commits scanned).
  - `gitleaks dir . --config .gitleaks.toml --redact --exit-code 1`: no leaks found (~11.59 MB
    scanned).

- **Touch-scope / constraint compliance.** Only `supabase/functions/_shared/evidence/handler.ts`,
  `supabase/functions/_shared/privileged.ts`, `supabase/migrations/0022_export_and_delete_hardening.sql`
  (still unmerged — schema changes went here, never 0021 or earlier), `supabase/tests/integration/
  {evidence-batch,repo}.deno.test.ts`, `supabase/tests/matrix/13_evidence_intake.sql`,
  `tools/db/check-migrations-immutable.sh`, `.github/workflows/ci.yml`, and this append-only doc
  section were touched. 0023 and later were never referenced or created. `/home/user/golfraven-p3e`
  and `/tmp/gr-gate*` were never touched (all work stayed under `/home/user/golfraven`, using
  `/tmp/gitleaks-bin` and `/tmp/check-migrations-immutable-selftest.*` only — the latter cleaned up by
  the self-test's own `trap ... EXIT`). No FORCE RLS removed, no RLS policy broadened. No mutation-proof marker
  string or other planted marker left anywhere in the tree — confirmed via
  a whole-tree grep for the mutation marker (no matches) and a final `git status --short` re-check before writing this
  report. Nothing committed — HEAD stays at `d7c7127` in the working tree for review.

## P3e — `import-catalog`, catalog skew over site versions, `queued_catalog` draining (round 2)

**Breaking change to the evidence request shape (H1) — no client exists yet.**

- `catalogVersion` is the site version STRING (`yyyymmdd-gitsha7`, `tools/catalog/src/manifest.ts`
  `CatalogVersionSchema`), no longer an internal int. The server resolves it through
  `app.catalog_version.site_version`; the int `version` is a server-side publish-order counter.
- `manifestSig` uses the field names of P1's signature file (`manifest.sig.json` =
  `{catalogVersion, contractVersion, kid, manifestSha, sig}`), so a client lifts the object straight
  out of the file: `{kid, contractVersion, manifestSha, sig}`, plus an OPTIONAL `catalogVersion` that
  duplicates the submission's own top-level `catalogVersion` and, when present, MUST equal it
  (round 2 gate, LOW: the wire field was `signature`, intake's own name, which differed from P1's
  `sig`). Any other key is rejected, and the parsed value is rebuilt from exactly those four known
  fields (never the raw client object). `sig` is STANDARD (padded) base64 — what
  `tools/catalog/src/sign.ts#signBytes` emits (B1). `fixId` stays pinned to unpadded base64url (§1 above): that pin is about a value this
  codebase mints; the artifact signature encoding is a third party's output format. The statement
  verified is the real domain-tagged canonical JSON (above). An interop test signs with the REAL
  `tools/catalog` `signManifest`/`signVersions` and imports the result.
- Skew semantics are unchanged but re-expressed: "5 releases" is the gap between the two versions'
  RELEASE ranks (`Repo#catalog.releaseRank`: how many imported versions have a `site_version` at or
  before it) — NOT the internal `version` int, which is import order and diverges after a rollback
  republish (round 2 gate, LOW); "30 days" is `published_at`; "far future" is the build plan's own
  §3.3(i) rule read off the declared version's date prefix (> now + 1 day, no signature can rescue
  it); a revoked kid is `422 catalog_stale`; an unregistered kid is `catalog_forged`.
- "Current" is the greatest `site_version` (rows with a NULL `site_version` — pre-import fixtures —
  sort last), so importing an older, previously-unseen version never moves the current version.

**Queued rows (B3) and draining (B2, M1).** Migration `0024`: a `queued_catalog` row carries
`claimed_facility_id`/`claimed_course_id`/`claimed_catalog_version` plus the raw validated submission
in `queued_input` (never exposed through an `api.*` view; it IS the caller's own submitted data, so it
IS in the owner's own `export_my_data` — decided in 0024 section 4, and it goes with the row on
`delete_my_data`; the column comment in 0024 says the same); `facility_id`/`course_id`/
`catalog_version` stay NULL (CHECK `evidence_queued_claim_shape`), so the deferred evidence FKs can no
longer turn a 202 into a COMMIT-time 500. Draining NEVER flips a status: each row is re-run through
the live derivation (tombstone rewrite, course/facility pairing, local date, matcher, `scorePlay`,
play upsert) in its own actor-scoped transaction (`redrainQueuedEvidenceRow`); the self-report date
window and clock-skew check are judged as of the row's queue time, not drain time. Outcomes: resolved
(scored), still queued, `needs_attention` (> 7 days, no `review_item`), or terminal `unknown_id` (the
import covering the claimed version already ran and the id is still absent, or a structural failure).
Two rules keep a drain from ever killing a row it has not actually judged (round 2 gate):

- **NEW-1 (BLOCKER) — judge ids only against the claimed version's own import.** A newer, validly
  signed, not-yet-imported claim classifies `ok`; a ledger lookup against the OLDER current import
  then missed every id and ended every queued row `unknown_id` on the first drain (which runs after
  EVERY import, failed ones included). Now, if the claimed `site_version` is newer than the current
  one and has no `catalog_version` row, the redrain returns `still_unresolved` BEFORE any id lookup and
  the orchestrator does not treat the (older) current import as coverage: the row stays queued and
  only the 7-day timer can end it, as `needs_attention`. (A claim OLDER than the current import with
  no row is a stale claim: classified `stale`, judged by M1 as before.)
- **NEW-2 (HIGH) — a throw is never evidence about a row.** A lock/statement timeout,
  `CONNECTION_CLOSED`/503 or deadlock inside a row's transaction (or while writing its terminal
  state) leaves the row queued for the next pass; the only things that may end a row are an explicit
  `terminal_unknown_id` from the redrain itself or the row's own 7-day age (-> `needs_attention`,
  never `unknown_id`). The pass reports `errored`.

A terminal row (`needs_attention` / `unknown_id`) keeps no queued submission: `queued_input` (raw
coordinates and all) and the `claimed_*` columns are cleared with the status change, matching the 0024
column comments. **NEW-3 (HIGH) — replaying a terminal row never 5xx.** `buildReplayResult` decides from
`status` BEFORE its null-facility guard: `unknown_id` replays as the `422 unknown_id` the live
submission would have returned, `needs_attention` as a stored-state `200 {status: "needs_attention"}`
(a 5xx would make the client outbox retry forever).

**Import (H2/H3/M3/M4).** The importer pulls and verifies EVERY artifact (manifest, versions, ledger,
`facilities/<region>.json`, `trails.json`, `designers.json`) before any write transaction opens
(`AbortSignal.timeout`, `redirect: "error"`, byte caps), then applies them set-based (`unnest`
upserts, verified against real Postgres) in one atomic transaction, exiting early when the current
version is already imported. A signed ledger that conflicts with stored state (different
`merged_into`, tombstone reversal) rejects the whole import; `revokedKids[]` is a hard reject for the
signing kids and is recorded append-only in `app.catalog_kid_revocation` (migration `0025`, INSERT/
SELECT-only — `catalog_signing_key`'s SELECT-only grant is untouched). The endpoint is HMAC-only
(secret >= 32 bytes), opaque 401 when unconfigured, and ALWAYS drains, in its own transactions, even
when the import fails.

**AT 18 — stub -> verified promotion and splits (round 3, R2; migration `0026`).** The importer only
QUEUES the work: a course whose stored ledger status was `stub` and whose incoming entry is `verified`
(same id) gets one `app.catalog_rescore_backlog` row (`reason='promotion'`), and a kept course that
gains a NEW split sibling (`split_from` set on the sibling) gets one (`reason='split'`) — set-based,
idempotent per (course, reason, catalog version), and a replay of the import is an early exit that
queues nothing. The drain pass (`import-catalog/index.ts`, after the `queued_catalog` drain, and also
when the import itself failed) works the backlog a BOUNDED batch at a time (<= 50 plays and <= 5
courses per pass, further bounded by the time budget below; a failing play stops its course and is
retried, never skipped), one short `withOwnership` transaction per play. The cursor is a STABLE
keyset over `(play created_at, play id)` stored on the backlog row (a deleted play cannot move it):
the original bare-uuid ordering missed a play inserted mid-drain whose random id sorted before the
cursor (round 2 gate, LOW). `app.play.created_at` is `now()` — the START of the inserting transaction —
so a long live-intake transaction (<= `transaction_timeout`, 12 s) can still COMMIT after the cursor
has passed its timestamp (round 3 gate, LOW). A course is therefore NOT closed the first time a page
comes back short: the row records `finished_at`, waits `RESCORE_SWEEP_DELAY_SECONDS` (15 s, > 12 s, so
every such transaction has committed or died), rewinds the cursor by `RESCORE_SWEEP_OVERLAP_SECONDS`
(15 s) and scans to the end once more (`swept`) before closing; re-scoring is idempotent. Promotion:
the stored derived fixes carry a
`verificationTier` frozen at ingest from the then-stub course, so it is rewritten to the course's
current `verification_status` and the play is re-scored through the live `finalizeScoringForKey`
(advisory-locked per user/course/date, idempotent). Split: the existing play at the kept course becomes
a `user` pick of that course (A2-01: at most one per facility + date), so it counts once, and is
RE-SCORED straight away. **NEW-4 (HIGH) — the A2-01 cap applies on every path.** The scorer caps a user
pick (contributes 0 to `score_monetary`, never `money`) only when each scored evidence row carries
`courseDisambiguatedBy === "user"`; every scoring path (live intake, `finalizeScoringForKey`, promotion
re-score, split re-score, re-pick) now reads the play's `course_disambiguated_by`
(`Repo#play.disambiguation`) and stamps it on every course-anchored scored row — a play labelled
`user` but scored without the stamp kept `score_monetary` 0.50 (and a money-true fixture stayed
money-true). **A blocked label never leaves a split play uncapped (round 3 gate, MEDIUM; A2-01 /
§4.2).** The one-user-pick-per-facility-date index can refuse the label for a SECOND split play at the
same facility and date (two courses K and K2 of one facility both split); that play used to stay
unlabelled, so it scored uncapped (`score_monetary` 0.93, money true) and counted as a second course.
`Repo#play.disambiguation` now returns `{stored, effective}`: `stored` is the recorded label (the only
thing ever written), `effective` is what the scorer is told — a play with no geometry/staff label at a
course in a split family (the kept course or any sibling) is a `user` pick — "a split play is always a
user pick and never money" — whether or not the label could be written. `uniqueCourseCount` counts the
user picks of a (facility, date) at most ONCE (the labelled play wins, then the lowest course id);
geometry/staff-resolved plays are unaffected. (A play whose label was blocked cannot itself be
re-picked: only a labelled `user` pick can.) A re-pick (`repickUserPlay`) is limited to a `user` pick, to exactly ONE re-pick per
play (the audit row is the record), and to the split family; it MOVES the same play row and its
evidence (never a second play) and FULLY RE-DERIVES the stored evidence against the target course:
each embedded fix is re-matched (`matchFix`: `geometryKind`, `insideBuffer`, `verificationTier`) from
the raw coordinates stored at intake (`app.evidence.integrity.fixCoords`, kept OUT of `summary` because
the scorer's fix schema is strict) and a dwell's `holes` is recomputed from the target's hole count
(a 9-hole dwell moved to an 18-hole sibling gets the 18-hole bar). Evidence without stored
coordinates fails closed (`cannot_rederive`, nothing moves). The move writes an `app.audit_log` row
(`play.repick`).

**Raw fix coordinates — retention (round 3 gate, HIGH; build plan §8.6 "No raw routes on the server by
default. The play location is the course id", §3.3 "Raw routes stay on the device").** A re-pick needs
the coordinates, so they are kept in `app.evidence.integrity.fixCoords` — but ONLY while a re-pick can
actually happen:
- STORED only when the course is a ledger `stub` at intake (G3-01: only stubs split), or is already in a
  split family (it has a `split_from`, is the kept course of one), or has an open rescore backlog row
  (`Repo#catalog.repickEligible`). A verified, never-split course stores NO coordinates; a row with no
  course (facility-level) never does.
- CLEARED (set-based, every import/drain pass, `rescoreBacklog.purgeFixCoords`, ≤ 5,000 rows per pass,
  backed by the partial index `evidence_fixcoords_idx` on the rows that still carry them): (a) when the
  single re-pick is used (`repickApply`, same transaction); (b) once the course can no longer be
  re-picked — promoted with its backlog row DONE, not in a split family; (c) after
  `FIX_COORDS_RETENTION_DAYS` = 30 days from the evidence's `created_at`. Why 30: it is a minimisation choice, not a derived bound. Splits come from verification work that
  can land months after a play, so 30 days does NOT cover every split; the accepted cost is that a split
  announced later cannot be re-picked for that play and fails closed (`cannot_rederive`, nothing moves). It is one named constant
  (`evidence/handler.ts`).
- A row without coordinates keeps failing closed at re-pick (`cannot_rederive`, nothing moves).
- They belong to the owner's own row: they ride along in `export_my_data` (the `integrity` column — so
  the export shows exactly what is retained: coordinates for a stub/split-family row inside its window,
  none otherwise) and go with the row on `delete_my_data`.

*Note for the §8.6 / privacy-label owner (wording corrected at the P3e gate PASS):* the server now
holds raw coordinates of a play for up to 30 days whenever the play's course is a catalog stub, is in a
split family, or has an open rescore backlog row, where it previously held none. Stubs are the whole
unverified base layer, so at launch this covers most plays away from the branded trails, not a narrow
case. Plays at verified, never-split courses and facility-level rows are unchanged (course id only).
The privacy label must state this exception, or the re-pick feature must be dropped. **Launch-blocking:**
the purge runs only inside `import-catalog`; until the hourly backstop (or a dedicated purge job) is
scheduled, the 30-day limit is not enforced. See the P3e gate PASS follow-ups below.

Known limit: if the
user ALREADY has a `user`-picked play at another course of the same facility + date, the split label
cannot be applied (A2-01's one-per-facility-date index); it is still scored as a user pick (above), only the stored label is missing. `Repo#play.uniqueCourseCount()` is the server-side
`uniqueCourses` (mirrors `playQualifies`: `score_badge >= 0.50 OR money`, ledger status `verified`,
not void/disputed, merge closure resolved, distinct). Proven against real Postgres: a play at a stub is
accepted and counts for nothing; after promotion + drain `uniqueCourses` is exactly 1 for each of
three players (bounded across two passes), a replayed import/drain does not double it, the split case,
and a re-score racing a live submission converges to the same score as a clean re-run. The live
re-pick is exposed as a handler capability (`repickUserPlay`) — no HTTP endpoint wraps it yet (client
UI wiring).

**R3 — what the emitter publishes vs. what has a target table** (checked against
`packages/catalog/src/schema.ts` and `tools/catalog/src/emit-catalog.ts`; documented field by field in
`directory-artifact.ts`'s header). Imported: facilities, courses (incl. `holes`), `holesDetail` ->
`catalog_hole`, trails, `rosterVersions` -> `catalog_roster_version`/`catalog_roster_member` (with
`removed_on` derived by physical identity, §4.3), designers. Published but with NO target column/table
(not imported): facility `nameFr`/`town`/`lat`/`lng`/`blurb`/`url`/`access`/`amenities`/`booking`/
provenance; course `slug`/`par`/`opened`/`tees`/`composite`/provenance and every designer after the
first; trail `nameFr`/`countries`/`regions`/`kind`/`status`/`operator`/`officialUrl`/`rosterStatus`/
`blurb`/`lastReviewed`/`sources`; designer `aliases`/`sources`; `offer-terms.json`; `osm/**`. NOT
published at all: geometry — `Course.geometry` is a pointer, never inline coordinates, so
`catalog_course.boundary`/`radius_*`/`geometry_kind` stay NULL for every imported course (an imported
course can never match a polygon or yield a presence co-signal until the geometry pipeline exists).
Hole count: `courseHoleCount` is the `catalog_hole` count, else the declared `Course.holes`, else 0
(unknown); a dwell takes the 9-hole bar ONLY for a known count of exactly 9 — unknown or any other
value (12, 27, ...) takes the stricter 18-hole bar, so an unknown count can never grant a round more
credit (the old `>= 18 ? 18 : 9` put a 12-hole count in the 9-hole bucket).

**Time budget (round 2 gate, MEDIUM).** `import-catalog` used to inherit http.ts's single 15 s race
over sequential 15 s fetches, a 12 s transaction, the drain and the re-score, so a full-directory run
answered 503 while work continued unobserved. Each PHASE now has its own explicit deadline
(`catalog/time-budget.ts`): the fetch phase has 30 s TOTAL across all artifact fetches (each fetch also
capped at 15 s and never allowed past the phase deadline); the import write is one transaction bounded
by `transaction_timeout` (12 s); what remains of the 100 s whole-request budget is split between the
queued drain (first half) and the re-score, and each only STARTS a per-user unit while 26 s remain.
A unit is normally ONE per-user transaction (<= 12 s): the queued drain writes a terminal state
(`needs_attention` / `unknown_id`) in the SAME transaction as the redrain (round 3 gate, LOW — it used to
be a second transaction, so a unit could overrun a 14 s reserve). The one remaining two-transaction unit
is a row whose redrain THREW and which is past its 7-day age (the age-out is a second transaction), so
the reserve is 2 × 12 s + margin = 26 s; the fetch phase is 30 s (was 40) so that a worst-case fetch + a
12 s import write still leave the drain half of the budget one full unit — whatever is left stays queued / stays in the backlog
(cursor persisted) for the next run. The response is therefore truthful: it reports each phase's result
and `truncated: true` when the budget, not an error, cut a drain short; the 100 s http.ts race is only
the backstop for a phase that blows through its own bound. `[unverified — training knowledge]`: the
hosting platform's wall-clock ceiling for an Edge Function request — 100 s was chosen to sit under it;
confirm against the deployed project before relying on the margin (each number is one constant).

**Remaining gaps (named, not built):**

1. Geometry import (see above — nothing to import).
2. The metadata fields listed above as having no target table.
3. A HTTP endpoint for `repickUserPlay`.
3a. Live intake never DERIVES a `user` pick: two plays at one facility on one date via different
   `courseId`s outside any split family are both full-weight (A2-01's cap and one-per-facility-date
   rule only bite for split-ambiguous plays today). The radius cap (0.50) masks it while no geometry is
   imported; revisit with the geometry pipeline.
4. Queued rows never earn a co-signal (a co-signal is a live-session guarantee; the drain consumes the
   token for its own side effects but never fabricates one days later) — this fails closed.
5. The AT 8 retired-MAJOR rule ("a retired major version -> 422") is enforced nowhere (pre-existing, not
   introduced by P3e).
6. `tools/db/check-migrations-immutable.sh --self-test` ignores `--base` (it always self-tests against
   its own fixture).

**Measured (H3):** 40,000 ledger ids + 1,000 facilities + 1,000 courses + trails/designers applied in
one atomic transaction against real Postgres in ~1.8 s (Deno integration suite, superuser harness),
well inside the 12 s `transaction_timeout`. A 16 MiB per-shard fetch cap (`maxShardBytes`) is the
default; a ~40k-id ledger is below it only for compact entries — raise it deliberately if the real
ledger outgrows it.

**Accepted as follow-ups (recorded, NOT built):**

1. Signature replay within the +-5 minute window: a captured valid webhook signature can be replayed
   inside its tolerance window and burn the global `import-catalog:system` rate-limit bucket. Fix with
   a nonce table.
2. Wiring the deploy webhook and the hourly backstop schedule (deploy-gated).
3. The service-role lint CLI treats a nonexistent root as clean (exit 0) instead of failing.

## P3e gate PASS (round 5, `c0d24e8`, 2026-10-02): accepted follow-ups

The P3e security gate passed with no BLOCKER or HIGH. These remain, recorded rather than built:

1. **MEDIUM (fail-closed, latent): split-family over-cap.** Every unlabelled play at a split sibling is
   scored as a `user` pick, including a post-split play matched to that sibling's own polygon, so no play
   at a facility that has ever split can earn money. The user-pick treatment belongs only to plays from
   before the split (created before the split import, or dated on or before the split transition), or to
   fixes matched to the site-covering geometry. Fix before the geometry import ships. Latent today:
   imported courses carry no geometry (the radius cap zeroes money), and the money programme is
   pilot-only on verified courses.
2. **LOW, launch-blocking: schedule the fix-coordinate purge independently** (the hourly `import-catalog`
   backstop, or its own job). Until then the 30-day retention is not enforced.
3. **LOW: replace the backlog grace-sweep** with a page bound `created_at <= clock_timestamp() - interval
   '15 s'` in `nextPlays`. The current sweep rewinds only from the final cursor, so a play straddling an
   early page of a multi-page drain can be missed (needs a ≤ 12 s race on a course with > 50 plays).
4. **NIT: guard the NEW-1 date-shift test against parallel runs** (a session advisory lock, or a
   "must stay sequential" note in `tools/db/test-deno-integration.sh`). Today files run sequentially.

Carried from the P3d round-4 gate (recommended, not blocking):

5. Replace esm.sh routing stubs in `supabase/functions/deno.json` (and `pinned-import-targets.json`) with
   final module URLs or exact `npm:` specifiers. esm.sh re-routed the `@noble/hashes` `utils.js` stub on
   2026-10-02 despite immutable cache headers, which broke `deno cache --frozen` until re-pinned.
   **DONE (2026-10-02, supply-chain hardening follow-up; supply-chain gate FAIL then fixed).** `zod`,
   `@noble/hashes` (`utils.js`, `sha2.js`) and `tz-lookup` now import as exact `npm:` specifiers
   (`npm:zod@4.6.5`, `npm:@noble/hashes@2.4.0/utils.js`, ...). The four direct versions are unchanged and no
   dependency was added, but regenerating the lock moved two floating transitives under the still-esm.sh
   `supabase-js` import: `ws` 8.21.3 to 8.22.0 and `@types/ws` 8.18.1 to 8.18.2 (the gate diffed the registry
   tarballs and found them benign). `supabase/tests/deno.lock` was regenerated by Deno itself over every CI
   entrypoint plus `supabase/tests/integration/`. **Scope of the guarantee:** in CI and in the test harness,
   the `npm:` packages are pinned by sha512 registry tarball integrity, so a CDN re-route can no longer change
   what they resolve to. At deploy time `supabase functions deploy` ignores this lock (item 10 above), so there
   the guarantee rests on npm's version immutability, not on the lock `[unverified — training knowledge: the
   deploy-time resolver was not exercised]`.
   **Lint backstop.** Deno `--frozen` 2.5.2 accepts an `npm` lock entry with its `integrity` removed, a
   `tarball` override serving another version's tarball under the pinned name, a specifier downgrade
   (`"npm:zod@4.6.5": "4.6.4"` plus a 4.6.4 entry), and the older `"version": "3"` layout with the tables under
   `"packages"` (where it honours `tarball`). So the COMMITTED `supabase/tests/deno.lock` is checked by
   `committedLockProblems` (`tools/service-role-lint/src/config.ts`): `version` must be `"5"` and the top-level
   keys limited to `version`/`specifiers`/`npm`/`redirects`/`remote`/`workspace`; every `npm` entry has a sha512
   integrity and no `tarball`; every `npm:` specifier maps to an existing entry and, when it names an exact
   version, resolves to exactly that version; no `npm` entry is an orphan (unreachable from a specifier or a
   reachable entry's dependencies). The check runs as a test in `tools/service-role-lint/test/index.test.ts`
   against the real lock (CI runs it through `pnpm -r test`), because that lock lives outside the linted
   `supabase/functions` tree; each probe above is also a must-fail mutation of the real lock.
   The same check covers the lock's `redirects` and `remote` tables, which frozen Deno also lets swap a module
   (a `redirects` entry from `deno.land/x/postgresjs@v3.4.5/mod.js` to another driver, with a matching `remote`
   hash, exits 0): every redirect key must be an `https://esm.sh/` URL whose version carries a range operator
   (`^ ~ > < * %3E %3C`, the legitimate floating resolutions under the supabase-js stub), no key may start under
   `deno.land` or equal a pinned target / import-map value, and the target must be the same origin, same package,
   same sub-path, with an exact version. `remote` keys must be on `deno.land` (canonical versioned `/std@` or
   `/x/<name>@v` paths only) or `esm.sh` (no range). **Limit:** there is no full import-graph reachability walk
   for `remote`, and the redirect target's version is not checked to satisfy the key's range.
   Import-map targets (`importMapTargetProblem`) are a POSITIVE allow-list, not a CDN deny-list: only an exact
   `npm:`/`jsr:` pin, or `https://deno.land/std@x.y.z/...` / `https://deno.land/x/<name>@vX.Y.Z/...` matched
   against the raw string (so ASCII lowercase host, no port, userinfo or trailing dot), with no backslash anywhere (WHATWG reads `\` as `/`) and `new URL(target).href === target` for `https:`. Whitespace/control
   characters and non-lowercase schemes are rejected first (Deno normalises `NPM:zod@^4`, ` npm:zod@^4` and
   `n\tpm:zod@^4` to a range). Everything else is rejected: `esm.sh` (including `esm.sh.`), `esm.run`, jsdelivr,
   unpkg, skypack, `ga.jspm.io`, IDN lookalikes, `data:`, `blob:`, `file:`, `node:`, `http:`. There is no
   exemption for the legacy `supabase-js` esm.sh URL: it is a direct import in `privileged.ts`, which the lint
   exempts by path, and `@supabase/` targets are banned separately. CI also gained an npm tamper test (flip a
   tarball integrity, fresh `DENO_DIR`, require "Tarball checksum did not match") beside the esm.sh one.
   **Still esm.sh:** the direct `@supabase/supabase-js@2.45.4` URL in `_shared/privileged.ts` and its floating
   transitives; its own follow-up. `deno.land/std` and `deno.land/x/postgresjs` are immutable versioned URLs and
   stay. `[unverified — training knowledge]`: that the hosted Supabase Edge Runtime resolves `npm:` specifiers
   in a function's `deno.json` import map (local Deno 2.5.2 does; no deploy was run). Revert path: restore the
   four `https://esm.sh/...` values in `deno.json` and `pinned-import-targets.json` (the positive allow-list will then
   reject them, so it needs a reviewed change too) and regenerate the lock.
   **Range check added (2026-10-02, supply-chain gate on PR #20, MEDIUM; closes the redirect-version limit above).** A redirect
   target's version must now SATISFY its esm.sh key's range, via `semverRangeProblem` in `config.ts`: `ws@^8.14.2` redirected to
   `ws@8.0.0` (a downgrade below a security fix, with `remote` hashes from a plain `deno cache`) passed every earlier rule and
   Deno loaded it; it now fails, while an in-range target such as `8.14.2` passes. The range forms in the committed lock are
   `^x.y.z`, `~x.y.z` and `%3E=x.y.z`. The checker understands exactly one comparator (`^ ~ >= > <= <`, the `%3E`/`%3C` encodings
   decoded) followed by a full `x.y.z`, with npm caret/tilde semantics (`^0.x` stops at the next minor, `^0.0.x` at the next
   patch). **Fails closed:** any other range syntax (`*`, `x`/partial versions such as `^8`, `~8.14`, exact or bare, `||`
   unions, space/hyphen ranges, a pre-release or build tag in the range), and any target carrying a pre-release or build tag.
   Must-fail mutations of the real lock and unit tests for each live in `tools/service-role-lint/test/`.
6. `check-migrations-immutable.sh` on `push`: try `git fetch --no-tags origin "$GH_EVENT_BEFORE"` before
   failing closed after a force-push, and print `commit-tree` stderr in the self-test failure branch.

## P3f (2026-10-02): `POST /v1/rewards/{id}/activate`, the §7.5 decision table, and the `held_review` semantics

New Edge Function `supabase/functions/rewards-activate/` (thin entrypoint) over `supabase/functions/_shared/rewards/`, and
two new migrations, `supabase/migrations/0027_rewards_activation.sql` and `0028_export_reward_ledger.sql` (0023-0026
belong to P3e; no existing migration was edited; `delete_my_data` is **not** redefined and `export_my_data` is rebuilt
from 0024's final body with one added block — see "Registry" below). This section was revised after the P3f gate
(round 1: 3 HIGH, 4 MEDIUM, LOWs); "Gate round 1" below maps every finding to its fix and its tests.

> ⚠ **LIVE VENDOR VERIFICATION IS NOT EXERCISED.** There is no Apple or Google credential and no network route to either
> vendor in the build environment. DeviceCheck, App Attest and Play Integrity are built behind narrow injected interfaces
> and tested against scripted `fetch` and against assertions this repo's own tests construct. Every statement about
> Apple's or Google's wire formats below is `[unverified — training knowledge]`. A real-device conformance run is a
> pre-ship item (follow-ups F1-F3).

### What was built

| Piece | File | Notes |
|---|---|---|
| §7.5 decision table (pure) | `_shared/rewards/decision-table.ts` | rows 1-6 in plan order; **first match decides the outcome, every matching row raises its signals** (M2); imports only types |
| Request binding | `_shared/rewards/binding.ts` | `SHA-256(canonical_body ‖ server_challenge)` for both `clientDataHash` (iOS) and `requestHash` (Android); canonical body = `{challengeId, deviceId, platform, rewardId}` plus, **iOS**, `deviceCheckTokenSha256` (hex SHA-256 of the DeviceCheck token the request carries) and, **Android**, `installLinkId` when sent; an absent field is absent from the bytes, never `null` |
| App Attest assertion verifier | `_shared/rewards/app-attest.ts` | local crypto (strict CBOR, DER→raw, ECDSA P-256 via Web Crypto): signature, `rpIdHash`, monotonic counter, key id |
| Play Integrity verdict check (pure) | `_shared/rewards/play-integrity.ts` | `requestHash`, package, certificate digest, `deviceIntegrity`, freshness |
| Vendor adapters (production) | `devicecheck-client.ts`, `play-integrity-client.ts`, `production-ports.ts`, `vendor-http.ts` | ES256 / RS256 JWTs via Web Crypto; **no new dependency**, `deno.lock` unchanged |
| Handler (pure, DI'd) | `_shared/rewards/activate-handler.ts` | runs inside `withOwnership`; rate limits are hit before the transaction |
| Request shape | `_shared/rewards/request-shape.ts` | strict; the reward id comes **only** from the URL |
| Repo seam | `privileged.ts` | one `rewards: buildRewardsRepo(trx, uid)` line in `buildRepo`, one delimited `P3f additions` section appended at the end, and one `release_account_reservations` call in `me.deleteMyData()` |
| Schema + functions | `0027_rewards_activation.sql`, `0028_export_reward_ledger.sql` | see below |

### Decision table and the DI vendor boundary

`decideActivation(facts)` takes five facts and returns `{row, matchedRows, outcome, signals, setBit0}`; it never does I/O.
Every row's condition is evaluated independently: `row`/`outcome` come from the first match (the plan's "first match
wins"), `matchedRows` lists all of them, and `signals` is the **union** of the matched rows' signals — a reward that
rests on an unattestable co-signal (row 3) on a bit0 device with no prior reward (row 4) is held by row 3 *and* raises
`multi_account_device`, so the reviewer is not handed a hold with the evidence stripped. The handler
builds the facts: bits from the vendor, `accountHasOpenAttestationFailed` / `accountHasPriorReward` from the database,
`rewardRestsOnUnattestable` from the reward's own flag (unless a reviewer cleared it) OR its backing play's `held_review`,
and the activating device's own attestation grade. Three inputs the plan's table does not name each make the outcome **more** restrictive, never
less: a `failed` grade joins row 2, an `unattestable` grade joins row 3 (§7.5 "Role"), and "no persistent signal"
(an Android install with no link key at all, so the server-side substitute has nothing to say) is held. There is **no
outcome called refused**. The app-review demo account is
answered **403** before any reward is read (§4.7.7), so it cannot probe for ids either.

The handler sees only three small interfaces (`IosPort`: `verifyAssertion`, `readBits`, `setBit0`; `AndroidPort`:
`verifyIntegrity` **only**; plus `Repo#rewards`). `null` for a platform means "not configured". Android has **no vendor
persistent-bit port**: whether Play Integrity device recall exists is spike A20 `[unverified]`, and a port that reported
bits it cannot also write would be half a mechanism, so the production Android port neither reads nor writes any. (The
earlier wording of this section said both "reports no bits" and "refuses to write any" of a port that still *returned*
bits when a payload carried them; it no longer exists in either form — `extractRecallBits` and `AndroidPort#setBit0` are
gone.) Android's two bits are the plan's server-side substitute, below.

**The Android substitute (§7.5, A20 / A2-08).** The handler records the request's `installLinkId` (an opaque,
client-chosen id, **bound into the Android request hash** so it cannot be altered in transit; stored only as its SHA-256 in
`device.install_link_hash`, first writer wins) **and as a pseudonymous tombstone row that survives account deletion** (N4,
below), then reads `app.device_link_signals(device)`: the tombstone rows for this install link, plus the live device rows
linked by an equal `install_link_hash` or `attest_key_id` (the larger of the two counts; the sources identify accounts
differently, so they cannot be merged exactly and the larger is the safe side). "Seen on > 2 accounts" (≥ 3 distinct
accounts, this one included) stands in for bit0; "an account voided for fraud used this install" (`fraud_voided_at` on a
device row **or on a tombstone row**, set by `app.mark_account_devices_fraud_voided`, an admin decision, audited) stands in for bit1. The
table is unchanged. A device row with **no** link key (no install id ever sent, no attest key) can be linked to nothing,
so the substitute has no answer and the activation is held (the "no persistent signal" row), never activated and never
refused. Honest limits (the plan accepts them because the table routes to review rather than refusing): the install id is
an **unauthenticated hint** (a factory reset or a fresh id starts a new install; an attacker who knew a victim's id could
push the victim's install over the threshold and cause a *review*, not a refusal); and the substitute counts accounts, not
rewards, so it is weaker than "an account that **received** a monetary reward has used this device".

**Fail-closed behaviour** (each is a test):

- An unconfigured platform (`ports.ios === null` / `ports.android === null`) → any request carrying that platform's
  attestation material gets **503 `attestation_not_configured`** before any write.
- An incomplete configuration (one variable missing or empty) is "not configured", never a default. The loader is
  `loadRewardsAttestationConfig()` in `privileged.ts` (the only file allowed to read the environment).
- A vendor outage / 429 / 5xx / network error / timeout → **503 `attestation_unavailable`**; DeviceCheck's 401/403 (our
  credentials rejected) → `attestation_not_configured`. In both, the whole transaction rolls back (reward stays
  `earned`, challenge unconsumed, counter unchanged) so the same request can be retried.
- A DeviceCheck 200 whose body is not the documented JSON or the one documented "never set" phrase is
  `VendorUnavailableError`, **not** "bits clear".
- A DeviceCheck **400 is split by its body**: one that names the *device token* is a bad token → graded `failed`; **any
  other 400** (a payload / transaction / timestamp complaint, an empty or unrecognised body) is a request or environment
  fault → `VendorNotConfiguredError` → **503**, no signal. Why: `failed` opens an account-wide `attestation_failed` signal
  that holds *all* of that account's activations, and a 400 this adapter cannot read is more likely **our** fault (a
  request we built wrongly, a development-environment token sent to the production host or the reverse) than the
  player's. The cost of the cautious default is a retryable 503, never a wrongly-held account. `[unverified]`: Apple's
  exact 400 bodies, and whether an environment mismatch is distinguishable from a bad token at all — if not, a mismatch
  still reads as a token complaint (follow-up F16: a deploy-time canary).
- Unreadable bits on an `attested` grade never become clean (503). On a non-attested grade the read is best-effort,
  because the reward is held whatever the bits say; it only decides whether row 1's signal is raised.
- A DeviceCheck token Apple rejects, an integrity token Google cannot decode, a wrong `requestHash`, a signature over a
  different request, a replayed or non-monotonic counter, an unknown key id → graded `failed` → `fraud_signal(
  attestation_failed)` **at intake** and the reward goes to `held_review`. No registered App Attest key → `unattestable`.
- bit0 is set at the vendor **last**, after the database transition, inside the same transaction: a failure to set it
  rolls everything back (proved against real Postgres), so bit0 is never claimed set when it was not. `update_two_bits`
  writes both bits, so bit1 is written back **as the table read it** — an admin's bit1 is never cleared by this call.
- The App Attest assertion is bound to the request: an assertion for another reward, device, platform, challenge **or
  DeviceCheck token** does not verify (AT 5, H1). The challenge is live-only, single-use, device-bound and 120 s.
- `derSignatureToRaw` accepts only strict DER: a non-minimal INTEGER (a redundant leading zero) or a negative one is
  rejected, so one signature has one accepted encoding.

### Schema (0027) and the budget model

`device`: `attest_public_key` (65-byte raw P-256 point, nullable), `install_link_hash` (64-hex, nullable), `fraud_voided_at`.
`offer.face_value`; `offer_code.reserved_amount`; `rests_on_unattestable` (row 3's input, written only by the earning
path), `review_cleared_at` (H2), `hold_detail jsonb` (what the reviewer sees), and — offer codes only —
`issued_before_hold` / `expiry_remaining` (restore the REMAINING validity after a re-hold). `UNIQUE (device_id,
reward_kind, reward_id)` + a `user_id` index on `device_reward_ledger` (the table already existed: FORCE RLS, no client
policy). Plain (invoker-rights, **not** SECURITY DEFINER, `search_path` pinned, EXECUTE `service_role` only) functions in
`app`: `activate_offer_code`, `activate_entitlement` (both now take a 6th, optional `p_hold_detail jsonb`),
`resolve_held_offer_code`, `resolve_held_entitlement`, `release_account_reservations`, `reserve_offer_for_code` (the
idempotent reservation primitive), `device_link_signals`, `mark_account_devices_fraud_voided`; and the row trigger
`app.offer_code_reservation_sync`. They own the state machine (`earned → issued | held_review`, `issued → held_review` on
a second-device re-run, `held_review` untouched by activation, terminal states refused), the budget reservation, the
expiry pause, the ledger row, and — **independently of the caller** — the database-side backstops for rows 2 and 3: an
`activate` is refused (SQLSTATE 23514) when the reward rests on an unattestable co-signal (unless a reviewer cleared it —
row 3 only), its backing play is held (never cleared by a review of the *code*), or the account has an open
`attestation_failed` signal (row 2: released **only** by the signal's own `cleared_at`; a review of one reward never
waives it — N3).

**The budget model (pinned in 0027's header; M3).** A *reservation* is the offer's claim on `budget_cap` for one code,
recorded twice and kept equal: `offer_code.reserved_amount` and `offer.budget_reserved`. One idempotent primitive takes
it (`reserve_offer_for_code`; a code that already holds one is skipped). Who takes it: (1) **the earning path, at earn
time — not built**: nothing in the repository inserts an `offer_code` today, so **the earn path currently reserves
nothing** and every reservation is taken by 2 or 3; if it later reserves, 2 and 3 find the reservation and skip;
(2) **activation** of an `earned` code that holds none reserves its face value as it issues it; (3) **entry into
`held_review` by any path** — the trigger — including the 0017 play-hold cascade, which writes only `state`. Who gives it
back: transition to `void` / `expired` (the trigger, from the code's own `reserved_amount`, so a reviewer reject
releases exactly once, and a bare `UPDATE ... SET state = 'void'` releases too); `DELETE` of the row (the trigger, when
the deleting role may update `app.offer` — `private.delete_my_data` runs as `private_definer`, which holds no grant on
`app.offer` and must not be given one, so **account deletion calls `app.release_account_reservations` first**);
redemption (`consume_offer_budget`, the redeem path's job). **Approval keeps the reservation**: it pays for the
redemption even if the offer has ended. It **never refuses**, but it never issues what the cap cannot pay either (N1):
if `budget_cap` cannot cover a reservation, a code entering `held_review` is still held, unreserved, with one
`review_item` (`held_offer_budget_unreserved`) saying so (a held code is not payable, so nothing is owed), and a **clean
activation is HELD instead of issued** (`hold_detail.heldFor = "offer_budget"`) — an issued code is payable, and issuing
it unreserved lets the offer pay out past its cap (cap 10, face 10: code A issued and reserved, code B issued with
`reserved_amount` 0, and `consume_offer_budget` for both then fails with 23514 at the till). Approving such a held code
**takes its reservation at approval** and is **refused (23514) while the cap still cannot cover it** — raise the cap or
reject. The handler asks first (`Repo#rewards.canReserveBudget`, advisory, no lock) so it can skip the vendor bit0 write for a
reward that is about to be held; the database stays authoritative. **The earn path, when built, MUST reserve at earn time**
so a code the cap cannot pay is never earned (F15). **An ended offer does not block activation** (decided, tested both ways): `offer.status` / `valid_from` /
`valid_to` gate earning and redemption; a code earned while the offer was live is honoured, exactly as §7.5 honours an
approved held code, and the code's own `expires_at` bounds it.

`held_review` semantics: a held offer code reserves and its expiry clock **pauses** (`expiry_paused_at`), whichever path
held it (H3/F13). **Approval** (`resolve_held_offer_code`) has two cases (H2):

- the code **ran the table on a device** (`activated_device_id` set: an activation held it) → `issued`; validity restored —
  the **full** term counted from the approval date for a code that was never issued, the **remaining** validity for one
  that was issued before it was held (`issued_before_hold`; a self-induced re-hold is not a free renewal);
- **no device ever ran the table on it** (a play-hold cascade, an earn-time hold) → back to **`earned`** with
  `review_cleared_at` set. It is **not** issued: it has no device, §7.5 has not run, and it must not make the account a
  "repeat user". Activation then treats **row 3** as cleared for the reward (its own unattestable basis) and **nothing
  else**: rows 1 and 4-6 still run on a real device, an unattestable *device* still holds it, and an open
  `attestation_failed` signal on the account (row 2) still holds it — raised before or after the review — until the signal
  itself is cleared (N3: the first version waived signals raised before the review, so approving a play-hold quietly
  released an account-level fraud signal). `hasPriorReward` ignores any reward with no `activated_device_id`.

Rejection voids it and the trigger releases the reservation. A held entitlement reserves nothing; the trail's
outstanding-redemption figure (§9.6, not built) reads `state = 'held_review'`.

**Account deletion and the M1 leak.** `release_account_reservations` runs in the delete transaction before
`private.delete_my_data`, in two phases: (1) lock **every** `offer_code` row of the account (`ORDER BY id FOR UPDATE`, **no
predicate**), (2) a new statement reads them and releases. The first version used `FOR UPDATE ... WHERE reserved_amount
> 0`, which under READ COMMITTED *skips* (does not wait for) a row a concurrent activation has locked but not committed;
the deletion then removed a row that committed **with** a reservation (budget leaked). Taking every code lock before the
first offer lock, and releasing in **offer-id order**, also keeps this function out of a lock cycle with an activation
(code lock → offer lock) or another release. Remaining
cycles (a scoring cascade locks a play's codes in arbitrary order) surface as SQLSTATE `40P01` / `40001`, which
`mapPgTimeoutError` now maps to a **retryable 503** (a separate set from the timeout codes; the transaction rolled back, so
nothing was changed).

**Registry.** `device_reward_ledger` was `exclude` in `private.pii_export_policy` (0022). 0028 flips it to `export` as a
**reduced projection of the caller's own rows** — `id, user_id, device_id, reward_kind, reward_id, at`; never
`devicecheck_token_hash` (the secret-key denylist) and never another account's row — because the §7.5 table *acts on* that
record, and a data-subject export that withholds a record the service acts on is the weaker position. 0028 rebuilds
`export_my_data` from 0024's final body (one added block, marked `P3f additions`; verified by diffing the two bodies) and
flips the registry row under the same self-granting `CURRENT_USER` policy dance 0017/0019/0022 use. `delete_my_data` is not
redefined (`device_reward_ledger` is already `delete_row`, and no new table or `auth.users` FK was added).

**The install-link tombstone (N4) — a documented retention exception.** The substitute counted live `device` rows, and
account deletion deletes them (`device` is `delete_row`): a fraud-voided account that deleted itself took its mark with
it, and each deleted account stopped counting toward "> 2 accounts". So `app.install_link_account` keeps, per (install,
account): the install link's **SHA-256** (never the raw id), the account's **vault-keyed HMAC pseudonym** (the exact
scheme of `app.attestation.player_pseudonym`: key id registered in `private.pseudonym_key_registry`, validated by the
write-time trigger, computed by the `SECURITY DEFINER` `private.account_pseudonyms`, the only new definer function and
the only reader of the vault here), `first_seen_at` and `fraud_voided_at`. **No user id and no FK to `auth.users`.**

- **`private.delete_my_data` does not touch it, and must not**: it is a fraud tombstone, the same class as
  `app.receipt_fingerprint` (0003/0014 — "the cross-account fraud-fingerprint retention must survive account deletion").
  It is not exported (it names nobody). It cannot be tied to a person without the vault key *and* the account id.
- **Classification.** `private.pii_retention_policy` is derived from FKs to `auth.users`; this table has none, so it is
  deliberately **absent** — asserted in the matrix (no `user_id`/`device_id`/`email` column, no FK to `auth.users`, no
  retention-policy row), so a later change that adds a user reference fails the matrix instead of silently turning a
  tombstone into a personal row. Registry docs: this section is the classification of record.
- **Rotation.** An account already recorded under *any* active key is not recorded again under the newest, so a key
  rotation does not count one account twice. A key *retired* from the vault makes its rows unmatchable (the same operational
  rule as `pseudonym_hmac`: a key the registry references must never be deleted).
- **The count** is the number of tombstone rows for the install link, so deleting an account does not lower it; after three
  accounts with deletions in between, the third is still a "> 2 accounts" account. Marking works for an account whose auth
  row is already gone (it needs only the id), so the fraud decision can still be recorded after a deletion.
- **Privacy note (needs legal review before launch, follow-up F19):** the install link hash is a persistent device
  identifier and the pseudonym is linkable by anyone holding the vault key and an account id; retention is justified as
  fraud prevention (legitimate interest) and is **indefinite until a purge exists** — the 24-month window the receipt
  fingerprint uses is the intended bound, and the purge job is not built.
- **Client contract.** `installLinkId` must be an id that **survives an app reinstall on the same device** and is the same
  for every account on it: the **Android ID** (`Settings.Secure.ANDROID_ID`, the SSAID — scoped to the app signing key,
  the user and the device, unchanged by uninstall/reinstall of an app signed with the same key, reset by a factory reset)
  `[unverified — training knowledge]`; **not** a per-install random id, an advertising id, or anything the user resets
  from settings. 16-128 characters of `[A-Za-z0-9._~-]` (the SSAID is 16 hex). Sent on every Android activation; omitting
  it holds the activation (there is nothing to link).

### P3 acceptance test (9) and (5), mapped

Unit = `supabase/tests/unit/activate-handler.test.ts` (fake Repo, scripted ports); Deno = `supabase/tests/integration/
rewards-activate.deno.test.ts` (real `withOwnership`, real SQL); pgTAP = `supabase/tests/matrix/15_rewards_activation.sql`.

| AT fixture | Unit | Deno | pgTAP |
|---|---|---|---|
| same account, second offer on the same device → issued | "same account, second offer…" | "AT 9: same account, second offer…" | activate/ledger cells §3 |
| special marker on a second trail → issued | "…special marker on a second trail…" | "AT 9: same account, special marker…" | §5 |
| same account after reinstall → issued | "…after REINSTALL…" + "own already-issued reward re-activated…" | "AT 9: …REINSTALL…" + "…OWN issued reward…" | — |
| new account on a bit0 device → `held_review`, not refused | "a new account on a bit0 device…" | "AT 9: a NEW account on a bit0 device…" | hold cells §3c |
| any account on a bit1 device → `held_review` | "ANY account on a bit1 device…" | "AT 9: ANY account on a bit1 device…" | — |
| server-side re-score reads no bits until activation | "…reads NO bits until activation" + `rewards-isolation.test.ts` | "AT 9: …RE-SCORE reads no bits…" (a real `handleEvidenceIntake` pass) | — |
| second-device redemption re-runs the table | "…SECOND device re-runs the table…" (+ flagged → held) | "AT 9: …SECOND device re-runs…" | §3b/§3d |
| held code whose offer ends is honoured, budget reserved | "…offer ends during review…" | "AT 9: a held code whose offer ends…" (real approval, real `consume_offer_budget`) | §3f, §4 |
| precedence: unattestable reward on a clean device → held; open `attestation_failed` → held | "precedence (G3-08)…" ×3 | "AT 9 precedence…" | rows 2/3 backstop cells §3h |
| `failed` raises a `fraud_signal`; no token → `failed` on capable hardware, `unattestable` otherwise | "a FAILED verdict…", "a submission with NO token…" | same | — |
| AT 5: mismatched body hash, replayed counter, wrong Play `requestHash` rejected | "AT (5)…" (real verifier) + `app-attest.test.ts`, `play-integrity.test.ts` | "AT 5: …" ×6 incl. a counter race | — |
| §4.7.7: A activates B's code / entitlement → **404** | "ownership: another user's reward is a 404…" | "§4.7.7: player A activating player B's…" | DB-level `P0002` cells |
| §4.7 item 8 rate limits: 10/user/h, 20/device/day | `enforceActivationRateLimits` tests | "rate limit: …" ×3 (real `hitRateLimitForActor`) | — |
| **Android** (A20 substitute): same account second offer / after reinstall → issued; new account on a "> 2 accounts" install → `held_review` + `multi_account_device`; a repeat user there → issued; any account on an install a fraud-voided account used → `held_review` + high-priority signal; no link key → held | "Android … substitute" ×10 (threshold exactly `> 2`, first-writer-wins link, bound install link) | "AT 9 on ANDROID …" ×4 + "Android with NO install link" + `Repo#rewards` M4 test (real `device_link_signals`, real `mark_account_devices_fraud_voided`) | §10 |
| **H1**: a valid assertion beside a swapped DeviceCheck token → `failed` | "H1: a VALID assertion next to a SWAPPED…" + "…does not bind the token hash at all" + binding tests | "H1: a VALID assertion next to a SWAPPED…" | — |

The decision table itself is additionally checked **exhaustively** (5 bit states × 3 grades × 2 × 2 × 2 = 120 inputs)
against an oracle written as a flat ordered rule list, independent of the implementation.

### Gate round 1 (FAIL: 3 HIGH, 4 MEDIUM, LOWs) — finding → fix → tests

| ID | Finding | Fix | Tests |
|---|---|---|---|
| **H1** | The DeviceCheck token was the one request field the App Attest assertion did not cover: a valid assertion from a bad-bits device could ride next to a clean device's token | iOS `BoundBody` gains `deviceCheckTokenSha256`; the handler hashes the token **before** building the binding ("none" is unchanged: it is always held) | unit: swapped token → `failed`; pre-fix binding → `failed`; binding bytes. Deno: swapped token (real SQL) |
| **H2** | Approving a held reward with no device issued it, bypassing rows 1 and 4-6, and made the account a "repeat user" | approve → `earned` + `review_cleared_at` when `activated_device_id IS NULL`; activation treats rows 2/3 as cleared for the reward; `hasPriorReward` ignores rewards with no device | unit + Deno (probe B, approve-then-activate, flagged/unattestable device, signal before/after the review, held play, entitlements) + pgTAP §9 |
| **H3 (F13)** | A play-hold cascade reserved nothing and left the clock running; also F7, M1 | row trigger `offer_code_reservation_sync` (reserve + pause on `held_review`; release on `void`/`expired`/`DELETE`); idempotent with the explicit path | pgTAP §8; Deno (real re-score cascade, approve keeps, reject releases, DELETE releases) |
| **M1** | Account deletion could leak a reservation taken by a concurrent, uncommitted activation | two-phase lock in `release_account_reservations` (no predicate); `40P01`/`40001` → retryable 503 | Deno two-session probe (`budget_reserved = 0`) and a real deadlock → 503 |
| **M2** | Only the first matching row raised its signals; the hold stored nothing for the reviewer | `matchedRows` + union of signals; `hold_detail` (bits, matched rows, primary row, DeviceCheck month) | decision-table oracle (extended); unit + Deno probe C; pgTAP |
| **M3** | Budget model unpinned; hold vs earn-time reservation; ended-offer behaviour; earn path | pinned in 0027's header and "the budget model" above; idempotent primitive; decision: ended offers do not block activation; earn path stated as not built (F15) | pgTAP §9, Deno, unit |
| **M4** | The A20 substitute was missing; the Android port claimed bits it could not write; contradictory wording | substitute from `device_link_signals` (install link / attest key / fraud mark), Android port reduced to `verifyIntegrity`, wording corrected | unit ×10, Deno ×5, pgTAP §10 |
| LOW | F6 timing | 2.5 s vendor timeout; budget documented and pinned by a test (F6) | unit |
| LOW | DeviceCheck 400 | split by body (above); unreadable 400 → 503 | unit |
| LOW | Re-hold restarted validity | `issued_before_hold` / `expiry_remaining` | pgTAP, Deno |
| LOW | `derSignatureToRaw` accepted non-minimal DER | strict DER | unit |
| LOW | `device_reward_ledger` export | reduced projection (0028) | pgTAP `14_me_export.sql` |
| LOW (recorded) | bit0 set at Apple with the activation rolled back; per-actor device bucket; row 2 sub-ms race | F14, F8, F17 | — |

### Gate round 2 (re-gate FAIL: 2 HIGH, 3 MEDIUM, 1 LOW) — finding → fix → tests

| ID | Finding | Fix | Tests |
|---|---|---|---|
| **N1** HIGH | A clean activation over the cap was issued unreserved (cap 10, face 10: A issued + reserved, B issued with 0, then the till fails) | the reservation returning "cap cannot cover" HOLDS the code instead of issuing it (`heldFor: offer_budget`, one `review_item`); approval takes a reservation and is refused while the cap is short; handler pre-check skips the vendor write | pgTAP §8b (probe G, till reconciliation, refused/accepted approval); Deno probe G; unit |
| **N2** HIGH | The offer row lock was held across Apple's `update_two_bits`; a queue on one offer 503'd | the vendor write moved BEFORE the transition (F6 rewritten, F14 widened) | Deno: 6 parallel activations × 2.4 s write, < 5 s, no 503, one write each; unit (ordering) |
| **N3** MEDIUM | Approving a play-hold quietly waived an open `attestation_failed` signal | `review_cleared_at` waives ROW 3 only; row 2 needs the signal's `cleared_at` (DB backstop, handler, repo) | pgTAP, Deno and unit probe E (open signal: approved + sibling stay held; cleared: both activate) |
| **N4** MEDIUM | The Android substitute could be erased by deleting accounts | `app.install_link_account`: pseudonymous tombstone that survives deletion; `device_link_signals` / `mark_account_devices_fraud_voided` use it; client contract pinned (SSAID `[unverified]`); retention exception documented | pgTAP §10b (real `delete_my_data`), Deno (fraud-voided account deletes itself; 3 accounts with deletions), unit |
| **N5** MEDIUM | Cascade lock-order inversion (40P01) | cascade redefined: codes (id) → offers (id) → entitlements (id); release in offer-id order; F13 corrected | Deno: 12 rounds, two plays, opposite offer order |
| LOW | postgres.js `TypeError … 'write'` after a `transaction_timeout` FATAL killed the runner | reproduced; contained in `privileged.ts` (F20) | Deno: a 13.5 s transaction → 503, no uncaught error |

### Mutation proofs (all in `/tmp` copies; nothing planted in the tree)

Each of these was applied alone to a `/tmp` copy and the named suite failed (a no-op control mutation passed): 6 on the
decision table, 14 on the handler (held release, signal at intake, fail-open on unreadable
bits, bit0-before-apply, challenge consume / kind / device, counter advance, both rate-limit caps, second-device
shortcut, both no-token grades, row-1 signal), 21 on the verifiers / adapters / request shape (counter, `rpIdHash`,
signature, key id, unregistered key, `requestHash`, package, certificate digest, device integrity, freshness, recall
bits fail-open, unrecognised DeviceCheck body, unconfigured, 403 mapping, half-configured port, bit1 clear, body-supplied
reward id, missing challenge), 16 on 0027 (rows 2/3 and held-play backstops, no reservation, cap ignored, no expiry
pause, approval not restarting validity / leaving the clock paused / releasing the reservation, reject not releasing,
ownership and device clauses, held released by activate, admin check, an `authenticated` EXECUTE grant, ledger
uniqueness, terminal states) and 13 on `Repo#rewards` / `deleteMyData` against real Postgres (offer_code / entitlement
ownership, counter monotonicity, prior-reward blind to the ledger or counting held rewards, signal de-dupe and
`cleared_at`, backing-play hold, SQLSTATE 55000 / 23514 mapping, verdict shape, deletion not releasing). Three survivors
were found on the first pass (counter-advance monotonicity, held-counts-as-prior, 55000 mapping) and closed with new
tests; the re-run caught all three.

Gate round 1 added **11 mutations on 0027** (single-phase predicate lock in `release_account_reservations` — the M1 leak;
the trigger not reserving on `held_review`; not releasing on `void`/`expired`; not releasing on `DELETE`; approval always
issuing; approval not restoring the remaining validity; approval not keeping the reservation; the backstop ignoring the
cleared flag; the backstop ignoring signal timing; activation not reserving; the install link ignoring `attest_key_id`)
and **17 on the TypeScript** (token hash not bound; only the first matched row's signals raised; `hasPriorReward` blind to
the device filter; signal timing ignored; the effective flag ignoring clearing, and the held-play flag dropped; `40P01`
unmapped; a negative and a non-minimal DER integer accepted; the DeviceCheck 400 split reverted; the 4 s vendor timeout
restored; the Android threshold `>= 2`; the install link never recorded; the handler ignoring `reviewClearedAt`; the hold
detail dropped; the Android bit1 ignored; `setBit0` attempted on Android). Each was applied alone to a `/tmp` copy and
the named suite failed; one survivor on the first pass (the `hasPriorReward` device filter — the Deno test only had a
*held* code, which the state filter excludes anyway) was closed with a test that seeds `issued` / `redeemable` rewards with
no device, and the re-run caught it. The M1 probe was also run against the *original* single-predicate loop: the deletion
then collided with the in-flight activation instead of waiting for it, and the probe failed.

Gate round 2 added **9 more mutations**, each applied alone to a `/tmp` copy and killed: a clean activation issued even
when the cap cannot reserve (N1); approval needing no cap (N1); the handler without its budget pre-check (N1); the vendor
write moved back after the transition (N2 — the 6-parallel probe then fails and so do two unit tests); the backstop
waiving row 2 for a review-cleared reward again (N3); the substitute ignoring the tombstone; the fraud mark not written to
the tombstone; `record_install_link` writing no tombstone (N4 ×3); the cascade restored to 0017's scan-order body (N5 — the
two-plays probe deadlocks, and was observed to, when the mutated schema leaked into an adjacent run); and the closed-socket
guard disabled (the LOW test then dies with the uncaught `TypeError`, failing the runner). One survivor on the first pass
(the Deno probe G passed with the DB hold removed, because the handler's pre-check held first) was closed by a direct
`applyActivation('activate')` call that bypasses the pre-check, and the re-run caught it.

### Accepted follow-ups (append-only; F-numbers are P3f's own)

- **F1. Live vendor verification is not exercised** (above). DeviceCheck host / paths / JWT claims / body / the "Failed to
  find bit state" phrase, the App Attest assertion layout (CBOR map, 37-byte `authenticatorData`, `nonce =
  SHA-256(authData ‖ clientDataHash)`, signature over `nonce` with ECDSA-SHA256), and the Play Integrity verdict field
  names are all `[unverified]`.
- **F2. App Attest key registration — BUILT, NOT YET RUN AGAINST A REAL DEVICE (updated 2026-10-02).** When this was written
  nothing verified an attestation object against Apple's root or wrote `device.attest_public_key`, so every iOS assertion graded
  `unattestable` → `held_review`. `POST /v1/devices/attest-key` (`supabase/functions/devices-attest-key/`, migration 0034) now does
  both: see "App Attest key registration" at the end of this document. **What remains is a live conformance run on a physical
  iPhone**: every step of Apple's validation procedure is implemented from training knowledge and marked `[unverified]` until that
  run (no Apple device, account or network route exists in the build environment; the attestations in the tests are synthetic).
  Until the run, treat iOS attestation as untested in production: the endpoint fails closed (a rejected registration leaves the
  device `unattestable`, i.e. held, exactly as before), so the risk of shipping it unverified is false rejections, never a false accept
  of a forged attestation.
- **F3. Android device recall (A20) is unsettled — and no longer used.** The production Android port has no persistent-bit
  methods; the two bits are the server-side substitute (above), which is weaker than device recall (a factory reset
  evades it; the install id is an unauthenticated hint). Whether Play Integrity device recall exists, and under what
  field, remains `[unverified]`; if the spike shows it, the substitute is replaced behind the same table.
- **F4. bit0 is not set when a held reward is approved** — approval has no fresh DeviceCheck token (only a hash is stored).
  A device whose first reward was released through review stays "clean". Mitigation to design: record a pending-bit0
  marker on the ledger row and set it on the account's next activation from that device.
- **F14. bit0 can be set at Apple while the activation does not complete (more reachable since N2).** The write now
  precedes the transition, so a transition that then fails (a database backstop's 23514, a deadlock, a
  `transaction_timeout` kill, a `COMMIT` failure) or ends **held** (the cap was taken between the handler's advisory
  budget pre-check and the reservation) leaves bit0 set at Apple for a reward the account never received. The retry then
  reads bit0 and, for an account with no prior reward, holds the reward (row 4, `multi_account_device`). The common case —
  a reward the cap cannot cover — is avoided by the pre-check; the residue is a race. Cheap mitigation to design: store the
  activating token's hash on the device row *before* the vendor write and treat "bit0 set + this token hash already
  recorded for this account" as not-a-second-account on the retry.
- **F5. `update_two_bits` writes both bits.** A bit1 set between the read the table ran on and the write is lost (a vendor
  API limitation; re-reading would only narrow the window and add a network round trip to an open transaction).
- **F6. Network I/O happens inside the database transaction** (reads must precede the offer lock; the vendor write must
  roll back with a failed request). **Timing budget (revised twice):** `lock_timeout` is 5 s and `transaction_timeout` 12 s.
  The vendor calls are at most **two** per request (iOS: query, then on row 6 the update; Android: Google OAuth token, then
  decode), each bounded at **2.5 s** (`VENDOR_CALL_TIMEOUT_MS`): 5 + 2 × 2.5 = **10 s** worst case, 2 s of headroom, pinned by
  a unit test against the real constants. **The vendor write now happens BEFORE the database transition (N2).** Round 1
  called `update_two_bits` after `applyActivation`, i.e. with the *offer row lock held* (the reservation locks it, and
  every lock lives to the end of the transaction); `lock_timeout` restarts per holder, so activations on one offer queued
  behind each other's vendor latency — 6 concurrent activations with a 2.4 s write gave two 503s. With the write first, the
  only lock held across vendor I/O is the caller's **own reward row** (and its device row, from the counter advance), so
  contention exists only between requests for the *same* reward or device; the offer lock is held for milliseconds. The
  later advisory-lock waits still cannot add to the budget: no vendor call happens after one is taken. Probe (Deno): 6
  parallel activations on one offer, each with a 2.4 s write, finish together in well under the 14 s a serialised queue would take (asserted < 7 s) with one write each.
- **F7. The held-review queue has no Edge Function yet.** `app.resolve_held_offer_code` / `resolve_held_entitlement` exist
  (service_role only, `p_resolved_by` must be an admin, audited) for P5.1a; the caller must authenticate the admin.
  Voiding a held code by *any* path (not only `resolve_held_offer_code`) now releases its reservation, because the
  release lives in the `offer_code_reservation_sync` trigger (H3), not in the resolver.
- **F8. Per-device rate limit is actor-scoped (accepted).** `hitRateLimitForActor` prefixes the actor's uid (as for evidence),
  so the 20/device/day bucket bounds one account's use of a device, not several accounts' use of it. Multi-account
  detection is the bits' job (and the Android substitute's), not the limiter's.
- **F9. `offer.face_value` is an addition the plan does not list** (the plan has "redemptions × face value" for
  settlement but no column). It is `ADD COLUMN IF NOT EXISTS ... DEFAULT 0` so a parallel builder adding it first cannot
  make the migration set fail; confirm the intended source of face value (OfferTerms is catalog-side). `consume_offer_
  budget` clamps `budget_reserved` at 0, so redemption must consume exactly `offer_code.reserved_amount` or it can eat
  another held code's reservation.
- **F10. `hardwareSupportsAttestation` is a client self-report** (follow-up 9, unchanged): a lying client gains
  `unattestable` instead of `failed`; both are held, neither can reach activate.
- **F11. No expiry sweeper exists.** `expiry_paused_at IS NOT NULL` must be read as "not expiring" by whatever builds it.
- **F12. CI lists — done by the coordinator** at the P3e rebase: `rewards-activate/index.ts` is in the three `deno check` /
  `deno cache --frozen` / tamper steps of `.github/workflows/ci.yml`.
- **F13. A play hold did not reserve budget — fixed (gate H3).** The 0017 cascade writes only `state`; the new
  `offer_code_reservation_sync` trigger reserves and pauses on entry to `held_review` by any path, releases on `void` /
  `expired` / `DELETE`, and is idempotent with the explicit activation path (also closes F7 and M1). **Lock order** with
  P3e's per-play scoring lock was checked and raced (both orders + a mixed load, `rewards-activate.deno.test.ts` "P3e
  interplay"): scoring takes advisory ns 1 (user, course, date) then updates `offer_code` rows via the cascade. **Round 2
  (N5) found the cascade itself deadlocking**: it locked a play's codes in scan order and each code's offer as it went (via
  the trigger), so two plays whose codes sit on the same two offers in opposite scan order deadlocked (40P01) inside
  `reserve_offer_for_code`. `app.play_held_review_cascade` (0017) is now redefined in 0027 to take every lock up front in
  **one global order**: the play's codes `ORDER BY id`, then their offers `ORDER BY id`, then its entitlements `ORDER BY
  id`, and only then UPDATE. Every writer follows code → offer: activation (its reward row, then the offer inside
  `reserve_offer_for_code`), `release_account_reservations` (all the account's codes, then offers in offer-id order),
  `resolve_held_*` (the code, then the offer). (The earlier line here, "both orders take code-then-offer", was true of
  activation and false of the cascade.) Probe (Deno): 12 rounds of two plays whose 8 codes cover the same 8 offers in
  opposite order, held at the same moment from two sessions — no 40P01.
- **F15. The earn path reserves nothing yet** (M3, stated explicitly): see "the budget model". The hold and issue paths are
  idempotent against an earn-time reservation, so building it later changes nothing here.
- **F16. DeviceCheck 400 / environment mismatch has no canary.** The split above treats an unreadable 400 as a fault of ours
  (503), but if Apple's environment-mismatch body reads as a token complaint, a production deployment configured
  `development` would grade every token `failed`. Add a deploy-time self-test against the configured environment.
- **F17. (withdrawn)** Round 1 recorded a sub-millisecond race between an `attestation_failed` signal and a review
  clearing. Round 2 (N3) removed the timing comparison altogether: row 2 depends only on the signal's `cleared_at`.
- **F18. The install link is an unauthenticated hint** (A20, accepted by the plan): evaded by a fresh id or a factory reset;
  an attacker who knew a victim's id could push the victim's install over "> 2 accounts" and cause a *review* (never a
  refusal). The tombstone makes the hint *durable*, not authenticated.
- **F19. The install-link tombstone has no purge and no privacy review.** Retention is indefinite until a job deletes rows
  older than the intended 24 months; the legal basis (fraud prevention) and the DPIA are a pre-launch item.
- **F20. postgres.js closed-socket write (contained, not fixed).** After a `transaction_timeout` FATAL, postgres.js 3.4.5
  can run a queued `nextWrite` against a null socket and throw `TypeError: Cannot read properties of null (reading
  'write')` from a timer callback — uncatchable by the request, fatal to the `deno test` runner, and a candidate to take down
  an Edge worker. Reproduced; `privileged.ts` now marks exactly that signature handled on the global `error` /
  `unhandledrejection` events (logged, nothing else swallowed). The library is pinned and hash-locked, so the real fix is an
  upgrade; revisit when the pin moves.
- **Deploy configuration.** Vendor secrets live only in the environment (never in the repo):
  `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID`, `GR_APPLE_DEVICECHECK_KEY_ID`, `GR_APPLE_DEVICECHECK_PRIVATE_KEY` (PKCS#8 PEM),
  `GR_APPLE_DEVICECHECK_ENV` (`production` | `development`); `GR_PLAY_PACKAGE_NAME`, `GR_PLAY_CERT_SHA256` (comma-separated
  base64url), `GR_PLAY_SERVICE_ACCOUNT_EMAIL`, `GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY` (PEM). The existing "pin `--config` at
  deploy time" requirement applies to this function unchanged.

## P3f gate PASS (round 3, `baa3596`, 2026-10-02): accepted follow-ups

The P3f security gate passed with no BLOCKER or HIGH; N1–N5 re-probed fixed on real Postgres.

1. **MEDIUM — domain-separate the install-link tombstone pseudonym (P1). DONE in 0029
   (`0029_install_link_pseudonym_domain.sql`).** `private.account_pseudonyms` (0027) computed `hmac(user_id::text, key)`
   with the same vault key and input as `app.attestation.player_pseudonym` (0022), so a deleted player's tombstone joined
   to their retained staff-attestation rows by equality, and service_role held an oracle for attestation pseudonyms.
   0029 redefines it (same signature, grants, inventory row, owner; the 0020/0022 ownership bracket) as
   `hmac('install_link_account:' || user_id, key)`. The "preferred" key is now the **newest by the vault's creation order**
   (`created_at DESC`, then the numeric version suffix, then name) instead of `max(name)` (lexicographic, `_v9` > `_v10`);
   this needed one more narrow column grant to `private_definer` (`SELECT (created_at)` on `vault.decrypted_secrets` — a
   timestamp, not a secret). The key *registry* was not used as the order because it lists only keys already used to write a
   row; a freshly added key is not in it yet. **Existing tombstone rows are deleted** by the migration: they cannot be
   recomputed (the table holds no user id, by design) and would stay equality-joinable — exactly the defect; nothing is
   deployed, so no count or fraud mark is lost, live `device` rows keep both signals meanwhile, and each account is
   re-recorded under the new derivation on its next activation. Rotation semantics are unchanged (an account already
   recorded under any active key is not counted twice). Tests: `15_rewards_activation.sql` (no pseudonym equals
   `hmac(A, key)` under any active key; the new derivation; `_v10` beats `_v9`; creation order beats name order; the N4
   count and fraud-mark tests unchanged) and `rewards-isolation.test.ts` (0029 redefines exactly that one function).
2. **MEDIUM, launch-blocking — F19 tombstone retention.** Pseudonymised (not anonymous) personal
   information under Law 25 / GDPR: needs a retention bound and purge job (suggested 24 months from
   `first_seen_at`, mirroring `receipt_fingerprint`), privacy-officer / PIA sign-off, and privacy-policy
   disclosure before launch.
3. **LOW — F20: partly done.** The suppressed-error stack match is pinned to the pinned module URL
   (`deno.land/x/postgresjs@v3.4.5/src/connection.js`) and the guard counts what it contains
   (`getContainedClosedSocketWrites()`, also in the log line); a Deno test pins the match (another version, another file
   of the same name, another function, another message and a non-`TypeError` are all NOT matched). **Still open:** confirm
   at deploy that the Supabase edge runtime honours `preventDefault` on the global `error` event `[unverified]`.
4. **LOW — F14 surface** is wider after the N2 reorder (bit0 can be set when the transition then fails
   or ends held); worst case remains a row-4 review, never an issued or refused reward.
5. **LOW —** `mark_account_devices_fraud_voided` writes the raw user id into `audit_log.subject_id`,
   which can re-link the tombstone for fraud-voided accounts (intended for fraud audit; revisit with F19).

## Edge role PR1 (2026-10-02): the NOBYPASSRLS login role, database side (follow-up 6, step 1 of 4)

Follow-up 6 ("move to a dedicated `NOBYPASSRLS` login role before the first real deploy") is **still open**: it closes at
PR4, when `privileged.ts` stops using `service_role`. PR1 ships only the database half, and nothing in the TypeScript
uses it yet. Full design as built, the table-to-mechanism matrix, deviations and PR2-PR4 notes:
[`docs/security/edge-role-design.md`](edge-role-design.md).

- **Migrations** `0030_edge_role_core.sql` (roles `edge_gateway` / `edge_actor` / `edge_system`; `private.actor_binding`,
  `bind_actor`, `actor_uid()`; the delegate binders; rate-limit, delete and export wrappers; the nonce, link-signal,
  list and purge definers; registries) and `0031_edge_role_policies.sql` (every grant and policy; the nonce-tombstone
  trigger-function redefinition). `edge_gateway` is created NOLOGIN: LOGIN and the password come only from
  `tools/db/provision-edge-login.sh` (env var or stdin, never an argument). `service_role`, `anon` and
  `authenticated` are untouched, so nothing that works today changes.
- **Identity is the binding, not a GUC.** An edge_actor transaction calls `private.bind_actor(uid)` once; every policy is
  `user_id = (select private.actor_uid())`. The binding is valid only for the transaction that made it, so a pooled
  connection, a rolled-back savepoint or a forgotten bind fails closed. A compromised Edge runtime can still bind any
  uid (the authenticator trust model); what changes is that the connection cannot forge identity by setting a session
  variable and every cross-user path is a named function.
- **The held-review cascade is not redefined.** It stays an invoker-rights trigger and works under edge_actor because the
  play, its codes and its entitlements belong to one user and edge_actor has UPDATE on exactly the columns it writes
  (P3f round 3's lock-order rewrite needs nothing more). The one trigger function that had to change is the nonce
  tombstone, which now calls `private.record_consumed_nonce`.
- **Checks 9-12** in `tools/db/verify-function-inventory.mjs` and `supabase/tests/matrix/10_function_inventory.sql`: the
  membership closure is clean; the live edge policies equal `private.edge_policy_allowlist` both ways (plus the checked-in
  fixture `supabase/tests/fixtures/edge_policy_exprs.txt`); edge policies read `private.actor_uid()` and no other
  identity source; no edge_system policy or privilege on a PII-registered table, and no edge privilege outside FORCE-RLS
  `app` tables. Check 2 now also compares the new `expected_edge_actor` / `expected_edge_system` EXECUTE columns. Each
  check has a must-fail fixture.
- **`supabase/tests/matrix/16_edge_role.sql`** (585 assertions) runs as a real `edge_gateway` login (it reconnects: `SET
  ROLE` is judged by the session user, so escalation cells are only meaningful on that connection). Every UPDATE cell
  asserts a ROW COUNT with a control on the actor's own row, because under RLS an UPDATE with no policy is a silent 0.
- **Accepted residual risks** (details in the design doc): R1 edge_actor can UPDATE `offer.budget_reserved` on an offer it
  holds a code on; R2 it can UPDATE its own `offer_code` / `entitlement` state directly, bypassing the activation
  functions' backstops (PR5 moves activation behind definers); R3 `private.account_pseudonyms(uuid)` accepts any uid.
- **Verification (final P3f 0027/0028/0029, rebased on `6e436a4`, both harness modes):** `tools/db/test.sh` exit 0 in
  `HARNESS_MODE=superuser` and `restricted`: pgTAP 17 files, 1302 assertions; Deno integration 145 tests; function
  inventory OK; service-role lint clean. Also green: `check-migrations-immutable.sh --self-test` and `--base 4f7117c` (29 files),
  vitest units (29 files, 494 tests), `deno check --frozen`, gitleaks. Eighteen mutation proofs, each applied to a `/tmp`
  copy, were each caught (the actor binding ignoring the transaction, a second bind allowed, a staff-issued challenge
  allowed, a broadened or open policy, a table grant to edge_system, a missing review_item read, a no-op tombstone, an
  un-prefixed rate-limit key, a delegate allowed to delete, an uncapped purge retention, a missing offer_code UPDATE
  policy (the silent-0 case), `edge_gateway` made a member of `service_role`, an `auth.uid()` policy, a check that ignores
  policy text, and policy-text drift in a fixture).

Accepted follow-ups (append-only; E-numbers are this work's own):

- **E1.** Close follow-up 6 at PR4. Until then the Edge functions still run as `service_role`.
- **E2.** PR5: revoke `service_role` DML on `app.*` and EXECUTE on `private.*`; move activation behind definers (R2);
  optionally verify the JWT in the database.
- **E3.** `[unverified]` on a real Supabase project: `CREATE ROLE` / `ALTER ROLE ... LOGIN PASSWORD` for the project's
  `postgres`, the Supavisor tenant entry and `pg_hba` limits for `edge_gateway`, and whether `log_statement` records the
  provisioning statement's password literal.
- **E4.** The earn path (not built) will need a definer: `offer_code_enforce_max_redemptions` counts only visible codes
  under edge_actor, and edge_actor cannot insert `offer_code`.

## Edge role PR1 gate PASS (`ca8b8f1`, 2026-10-02): findings to close before PR2 relies on the policies

The gate passed (no BLOCKER/HIGH): actor binding, escalation, GUC windows and checks 9–12 held under
real `edge_gateway` probes. These are scheduled as **edge role PR1b** (new migration 0032), which must
merge before PR2 routes any query through `edge_actor`:

1. **MEDIUM — provisioning leaks the plaintext password to the server log on failure**
   (`tools/db/provision-edge-login.sh`; `log_min_error_statement=error` logs the failing
   `ALTER ROLE … PASSWORD`). Send a client-computed SCRAM-SHA-256 verifier instead; fix E3 / design §2.
2. **MEDIUM — one-way columns are reversible under `edge_actor`:** `checkin_token.consumed_at` can be
   reset to NULL (presence-token replay) and `device.attest_counter` can be rolled back (defeats App
   Attest anti-replay, AT 5). Add BEFORE UPDATE one-way triggers (set-once / monotonic), add to R2.
3. **MEDIUM — own-row WITH CHECK covers `user_id` only:** an actor can write rows that reference another
   user's device or challenge (`checkin_token`, `evidence.device_id`, `push_token`,
   `offer_code.activated_device_id`), and the FK check doubles as an existence oracle. Add
   own-device / own-challenge `EXISTS` to those WITH CHECK clauses (`IS NULL OR EXISTS` for
   `activated_device_id`).
4. **MEDIUM (R1, confirmed) — shared offer budget counter writable** by any actor holding a code on the
   offer (`budget_reserved` settable within `[0, cap − used]`; `release_offer_budget` drains it), and R2
   (`earned` → `issued` directly). **R1 closure (reserve/release behind definers) is now a precondition
   of PR4**, not optional PR5.
5. **LOW —** `private.delete_my_data` reads `pg_catalog` relations unqualified, and `edge_actor` holds
   TEMP, so a temp `pg_constraint` shadows it (fails closed via the post-condition). Qualify
   `pg_catalog.*` in a new migration; add an inventory check for unqualified relations in reachable
   definers.
6. **LOW —** check 9 misses ADMIN-only membership; check 12 covers too few schemas and never checks
   schema CREATE. Extend both.
7. **LOW —** 0030 does not reject a pre-existing misconfigured `edge_*` role (SUPERUSER / BYPASSRLS /
   REPLICATION / foreign membership); add an asserting DO block.
8. **LOW —** delegate preconditions are caller-controlled for `edge_system` (it can insert its own open
   backlog row); reword the design doc (moot under R6).
9. **LOW —** `review_item` SELECT shows all kinds on own codes; `audit_log` INSERT does not tie
   `subject_id` to the actor's play; `install_link_account` INSERT does not tie to the actor's device
   hash / key. Tighten.
10. **LOW —** add session-reuse pgTAP cells for the three new GUC windows (P3a follow-up 1).
11. **NIT —** compare `app.edge.link_device_id` as text (a non-uuid session value breaks reads with
    22P02); `bind_actor` does not exclude soft-deleted / banned users `[unverified]`; `purge_fix_coords`
    accepts 1-day retention; `rewards-isolation.test.ts` misses a later `ALTER FUNCTION … SECURITY
    DEFINER` (inventory check 3 backstops it).

## Edge role PR1b (2026-10-02): the gate findings closed in 0032 (follow-up 6, step 1b of 4)

All eleven findings of the PR1 gate (the section above) are closed in `supabase/migrations/0032_edge_role_hardening.sql`
(0030/0031 are merged and untouched), the provisioning script, the inventory checks and the matrix. Follow-up 6 is
still open until PR4; R1 and R2 of PR1 are **closed**, which makes the budget closure no longer a PR4 precondition
(it is done). Design as built: [`docs/security/edge-role-design.md`](edge-role-design.md).

1. **MEDIUM, provisioning leaked the plaintext (closed).** `tools/db/provision-edge-login.sh` computes the SCRAM-SHA-256
   verifier client-side (python3 stdlib) and sends `PASSWORD 'SCRAM-SHA-256$4096:...'`. New
   `tools/db/test-provision-edge-login.sh` (run by `test.sh`): a real SCRAM login with the plaintext succeeds through a
   temporary `pg_hba` rule, a wrong and a missing password are refused, a FAILED provisioning (as a role without
   CREATEROLE) logs a verifier and no plaintext, and the old plaintext form leaks into the same log (the control).
   **E3 update:** the `log_statement` caveat is gone; what stays `[unverified]` on a real Supabase project is the
   `CREATE ROLE`/`ALTER ROLE` privilege of the project's `postgres`, the Supavisor tenant entry and `pg_hba` limits.
2. **MEDIUM, reversible one-way columns (closed).** BEFORE UPDATE triggers: `checkin_token.consumed_at` is set-once for
   every role; `device.attest_counter` never decreases. Must-fail and control cells in `16_edge_role.sql` 7c.
3. **MEDIUM, own-row WITH CHECK covered only `user_id` (closed).** `checkin_challenge`, `checkin_token`, `evidence` and
   `push_token` INSERT policies require the referenced device (and challenge) to be the actor's own;
   `offer_code.activated_device_id` is moot (no UPDATE at all). **The existence oracle is closed, not merely
   documented:** RLS `WITH CHECK` runs before the foreign-key trigger, so a foreign id and a nonexistent id fail the same
   check with the same SQLSTATE and message (compared string for string in 7d).
4. **MEDIUM, R1 + R2 (closed).** edge_actor holds no UPDATE on `offer` / `offer_code` / `entitlement`, no INSERT on
   `device_reward_ledger`, nothing on `review_item`, and no EXECUTE on `app.activate_*`, `reserve_offer_for_code`,
   `release_offer_budget`, `release_account_reservations`. Activation is `private.activate_offer_code_for_actor` /
   `activate_entitlement_for_actor` (no user argument; they call the UNCHANGED P3f functions as `private_definer` under
   actor-keyed policies); the held-review cascade's body moved unchanged into `app.hold_play_rewards`, reached by
   edge_actor through `private.hold_play_rewards_for_actor`; `delete_my_data_for_actor` releases the account's
   reservations itself. P3f's 0027/0029 functions are not edited. Must-fail: setting the budget counter, calling
   `release_offer_budget`, setting a code's or entitlement's state. Must-pass: activation (issued, held, held for budget,
   idempotent replay), the cascade (also under a rescore delegate), deletion handing a shared offer's reservation back.
5. **LOW, `delete_my_data` unqualified catalog reads (closed).** Redefined from its 0022 body with `pg_catalog.`
   qualified; new inventory check 13 flags an unqualified `pg_*` relation in any SECURITY DEFINER body.
6. **LOW, checks 9 and 12 (closed).** 9 flags ADMIN OPTION on an edge-role membership held by anything but a superuser or
   CREATEROLE role; 12 covers every non-system schema (extension-owned relations exempt) and checks schema CREATE. Both
   have must-fail fixtures.
7. **LOW, misconfigured pre-existing edge role (closed).** An asserting DO block at the top of 0032.
8. **LOW, delegate preconditions (documented).** They are caller-controllable for edge_system (it can insert its own open
   backlog row); stated honestly in the design doc, moot under R6, not restricted (the importer needs that INSERT).
9. **LOW, `review_item` / `audit_log` / `install_link_account` (closed).** `review_item` is unreachable for edge_actor;
   the `audit_log` INSERT is tied to the actor's own play; the tombstone INSERT is tied to the actor's own device's link
   hash and to the key that produced the pseudonym.
10. **LOW, GUC-window session reuse (closed).** `16_edge_role.sql` 10j and 10k: windows read empty after a COMMIT, a
    planted non-uuid value does not raise in a definer's read, planted windows do not widen an export or a list, the
    purge window works across a COMMIT.
11. **NIT (closed).** `pd_device_link_read` compares the device GUC as text; `purge_fix_coords` refuses retention under 7
    days; `rewards-isolation.test.ts` also catches a later `ALTER FUNCTION ... SECURITY DEFINER`.
    **Still open `[unverified]`:** `bind_actor` does not exclude soft-deleted / banned `auth.users` (the harness shim has
    no such columns); check on a real project before PR2.

Findings noticed while closing these, for the PR4 gate: an actor with a compromised runtime can still un-hold its own play
(`play.held_review` is writable by design: the scorer lifts holds) and choose its own device's `install_link_hash`; both
sit inside the R6 trust boundary (design doc R2 note and R8).

**Verification (PR1b, on `3ec13a7` = main `7250568`'s tree for 0001-0031).** `tools/db/test.sh` exit 0 in
`HARNESS_MODE=superuser` and `restricted` (a fresh cluster each): pgTAP 17 files, 1403 assertions (`16_edge_role.sql` 678,
`10_function_inventory.sql` 50); Deno integration 145 tests; function inventory OK; service-role lint clean; the new
provisioning proof passes. Also: PG16 (all 17 files and the inventory script), `16_edge_role.sql` three runs in a row
on one cluster in each mode (re-runnable), units 29 files / 495 tests, the lint's own 112 tests, `deno check --frozen`,
`check-migrations-immutable.sh --base 7250568` (31 files) and `--base 4f7117c` (29), `--self-test`, gitleaks. 23
mutations were applied to `/tmp` copies (each budget/state/ledger/review_item write left granted, the cascade definer's
held-play check, a delegate let through, deletion not releasing, the cascade trigger forced onto its direct lane, each
M2 trigger weakened or never firing, each M3 device/challenge check dropped, both L5 ties dropped, the device GUC cast
back to uuid, the retention minimum, delete_my_data left unqualified, a broadened `pd_edge_act_play_select`) and every one
was caught except one EQUIVALENT mutant (dropping the owner check inside `hold_play_rewards_for_actor`: the actor-keyed
`pd_edge_act_play_select` policy already hides another user's play from that function, so the two layers are redundant by
design). Two provisioning mutations (the plaintext back in the statement; a corrupted verifier) are caught by the new proof,
and eight pre-existing misconfigurations of an edge role (LOGIN, BYPASSRLS, REPLICATION, CREATEROLE, membership of
`service_role`, a foreign member with SET, INHERIT, ADMIN) are each refused by 0032's assertion block while a clean cluster
applies it.

## Owner decisions (2026-10-02)

Recorded from Matt, today. They bind the work below and the launch checklist.

- **Fix-coordinate retention (the §8.6 exception): KEEP re-pick**, with the 30-day `FIX_COORDS_RETENTION_DAYS` limit at stub or split-family
  courses (`rescoreBacklog.purgeFixCoords` / `private.purge_fix_coords` enforce it). **It must be disclosed in the privacy label.**
- **Install-link fraud tombstone (`app.install_link_account`, F19): retention is 24 months from `first_seen_at`**, mirroring
  `receipt_fingerprint`. Implemented in 0033 (`private.purge_install_link_tombstones`, below). Before launch it **still needs privacy-officer /
  PIA sign-off and a privacy-policy disclosure**.
- **Git history is NOT rewritten** for the workers.dev subdomain / slug in `fa1429a`: the values are low-sensitivity and already replaced.
- **Merge bar: CI green AND security gate PASS.**

## Edge role PR2 (2026-10-02): the TypeScript behind `EDGE_DB_MODE` (follow-up 6, step 2 of 4)

Follow-up 6 is still open until PR4 (the default flips, `legacy` is deleted, the lint pass lands). PR2 adds the temporary switch in
`supabase/functions/_shared/privileged.ts` (`legacy` default = today's path; `edge` = `edge_actor` through `GOLFRAVEN_EDGE_DB_URL`, connecting
as `edge_gateway`), the startup self-check, `openScopedTx`, and 0033. Design as built, the PR3 boundary and the **behaviour differences between
the modes**: [`docs/security/edge-role-design.md`](edge-role-design.md) section 11.

- **CI runs the whole Deno integration suite in BOTH modes** (`tools/db/test-deno-integration.sh`; `tools/db/test.sh` clones the database once per
  mode and generates the `edge_gateway` test password at runtime), in both HARNESS_MODEs. New `edge-role.deno.test.ts` (11 tests): the self-check
  refuses a non-`edge_gateway` / BYPASSRLS / superuser URL and a membership of `service_role` / `authenticated`, as a plain Error, not cached; an
  UNSCOPED raw query through `openScopedTx` returns 0 foreign rows (and an unscoped UPDATE changes only the bound actor's row); a forgotten bind and a
  bind of the wrong uid fail closed before the operation runs; the `edge_system` kind reads no personal data; a rate-limit hit uses the bare key.
- **A finding the suite made, now closed: dropping `FOR UPDATE` from `lockOwnReward` is NOT safe** (the brief asked for it on the argument that the
  activation definers lock the row). The handler decides hold-vs-issue from state it reads before those functions lock; under a race the second request
  turned an already-issued code into `held_review`. 0033 adds `private.lock_own_reward_for_actor` (the same `FOR UPDATE`, taken by a definer for the bound
  actor; a row lock lasts to the end of the transaction), and edge mode calls it. Legacy keeps its `for update` verbatim.
- **PR3 boundary:** `import-catalog` stays on the LEGACY pool in `edge` mode (so it needs both URLs): the importer repo, the drain's list reads and both
  purges are `withSystemCatalogImport`. Not small: the importer statements, the drain's `queued_input` re-read as the row's owner (the definer list omits
  it), new orchestrator signatures and unit tests. The drains' per-row user transactions do run as edge_actor, binding the owner with `bind_actor`, not a delegate.

- **Verification (PR2 on the npm:-specifier base `b63a018`, 2026-10-02):** `tools/db/test.sh` green in HARNESS_MODE=superuser and =restricted, each on a
  fresh cluster, on **PostgreSQL 17 and again on PostgreSQL 16**: pgTAP `Files=17, Tests=1439, Result: PASS` (matrix 16 is plan 711); the Deno integration
  suite **156 passed / 0 failed in `EDGE_DB_MODE=legacy` AND 156 / 0 in `EDGE_DB_MODE=edge`** (each on its own clone of the migrated database);
  `verify-function-inventory: OK`; `service-role-lint: clean`. Also green: unit suite (29 files, 495 tests), `service-role-lint` tests (4 files, 142; the four
  structural pins on `privileged.ts` were updated for `openScopedTx` and `buildRepo(..., mode)`, the lint's rules are unchanged -- that is PR4),
  `deno check --frozen` and `deno cache --frozen` on every entry point against a fresh `DENO_DIR`, `check-migrations-immutable.sh --base d0dc79d` (32 files
  byte-identical) and `--self-test`, `gitleaks dir` (no leaks). Three test-harness traps closed on the way: `Deno.env` is process-wide, so
  `edge-role.deno.test.ts` sets `EDGE_DB_MODE=edge` per test and restores it (a file-level set had turned every later file of the `legacy` pass into an
  edge-mode run); postgres.js v3.4.5 reads a URL password only from userinfo or `PGPASSWORD` (a `?password=` query parameter is sent to the server as a
  startup parameter and refused), so the test harness hands the generated password over as `PGPASSWORD`; and the `transaction_timeout FATAL` test
  raced its own 13.5 s sleep against a 12 s kill plus a fixed 1.5 s wait (edge mode's slightly longer set-up tipped it, 3 of 3 in isolation) -- it now polls
  for the guard, and says SKIPPED (not a pass) on a server without the PostgreSQL 17 `transaction_timeout` GUC.

- **Mutation proofs for the 0033 pieces (2026-10-02, `/tmp` copies only, matrix 16 unless noted; 23 mutants):** the first pass killed 12 and left 11
  alive, and the survivors were the same layered-defence shape: the purge retention is enforced twice (the `private_definer` policies and the function body's
  own cutoff), and the hold post-condition's two branches mask each other when the swapped-in body is a pure no-op, so a mutant of one layer was hidden by
  the other. Matrix 16 now has section 11 (harness role, cells 706-711; plan 711): the two policies proved alone (`private_definer` sees and deletes only
  rows older than 24 months; the READ policy is widened inside a rolled-back transaction so the DELETE policy stands alone), the function body proved alone
  (both policies widened in a rolled-back transaction, the 23-month row is still kept), and the post-condition proved per branch (a deliberately incomplete
  `app.hold_play_rewards`, rolled back, that skips the entitlements, and one that skips the codes; plus the unswapped control). After that every mutant is
  killed except one: **L3, dropping `AND user_id = v_uid` from `lock_own_reward_for_actor`, is an equivalent mutant** (the actor-keyed
  `pd_edge_act_offer_code_*` / `pd_edge_act_entitlement_*` policies of 0032 independently hide every other user's row from `private_definer`; the predicate
  repeats the same rule on purpose). Killed: lock without `FOR UPDATE` (either table), no-actor guard removed, extra EXECUTE grant (matrix 10 inventory),
  post-condition removed or weakened in either branch or accepting `issued`, cascade dispatch forced to either lane or keyed on `session_user`, retention
  12 or 36 months in the body or in either policy, read or delete policy `USING (true)`, cutoff dropped from the body, bound check removed, `LIMIT` ignored,
  EXECUTE granted to `edge_actor`, `PUBLIC` revoke dropped. Section 11 runs as the harness role in both HARNESS_MODEs (a restricted `migration_owner` gets
  `SET ROLE edge_actor` through a `GRANT ... WITH SET TRUE` that the cell's own `ROLLBACK` undoes).

### PR1b gate LOWs and NITs (all recorded; fixed where cheap)

- **LOW-1 (closed in 0033).** `play_held_review_cascade` chose its lane with `has_table_privilege('app.offer_code', 'UPDATE')`; a role with the table
  privilege but RLS-limited visibility (`private_definer`) would have held 0 rows silently. It now dispatches on `current_user = 'edge_actor'` (the
  definer lane) and every other role keeps the direct lane; and `private.hold_play_rewards_for_actor` has a **post-condition**: after the hold, no code or
  entitlement of the play may remain in a non-held, non-terminal state (it raises 55000).
- **LOW-2 (closed).** Check 13 now also catches comma lists (`FROM a, pg_class c`) and `DELETE ... USING pg_roles`, with must-fail fixtures (and a
  clean fixture for qualified comma-list members) in `10_function_inventory.sql`; `verify-function-inventory.mjs` carries the same pattern.
- **LOW-3 (documented, R2).** `p_decision` stays a caller-supplied argument of `private.activate_*_for_actor` (`activate` or `held_review`): the
  DeviceCheck verdict, the §7.5 decision table and the "prior reward on this device across accounts" check are **TypeScript-only**. The database
  backstops rows 2 and 3 (an open `attestation_failed` signal, an unattestable basis, a held play, an unreserved budget) but cannot decide the rest; a
  compromised runtime can therefore choose `activate` for a reward it should have held, within those backstops. Inside the R6 boundary; a database-side
  decision table is not planned.
- **LOW-4 (documented).** `Repo#device.ensureOwn` already uses `ON CONFLICT (id) DO NOTHING` plus a re-read. What remains is an existence oracle on the
  `app.device` primary key: a probe with another user's device id gets 409 `device_owned_by_other_user`, a fresh id succeeds. The id is an
  unguessable uuid the caller must already hold; it reveals "this id is registered to someone", nothing else. Same in both modes; accepted.
- **NIT (closed).** With `--password-env`, `provision-edge-login.sh` unsets the variable before it spawns any child; `test-provision-edge-login.sh`
  proves it with a psql stand-in that records its environment.
- **NIT (noted, design doc section 9).** The App Attest key re-registration path (not built) needs a purpose-built definer: the monotonic counter trigger
  (0032 M2) blocks the counter reset a new key implies, and edge_actor cannot write `attest_key_id` / `attest_public_key`.
- **NIT (noted).** A single-CTE challenge+token insert is refused under edge_actor (the token's own-challenge `EXISTS` cannot see a row the same statement
  inserts); the Repo already inserts them in two statements.
- **Gate ruling, recorded:** un-holding your own play (`play.held_review` is writable by edge_actor, and the scorer legitimately lifts holds) releases
  **nothing today** (the cascade is one-way). It **must be closed before the earn-path definer ships (E4), and no later than the PR4 gate.**

### Install-link tombstone retention (owner decision, 0033)

`private.purge_install_link_tombstones(p_max_rows integer)` (SECURITY DEFINER, owned by `private_definer`, `search_path = ''`): deletes
`app.install_link_account` rows whose `first_seen_at` is more than **24 months** old, oldest first, at most `p_max_rows` (1..100000) per call, and returns the
count. The retention is the constant `v_retention` in the function body; two ROW-NARROW `private_definer` policies (`pd_purge_install_link_read` /
`_delete`, in the allowlist and the fixture) repeat the cutoff so the function cannot see or delete a younger row even if its body were wrong. EXECUTE:
`service_role` and `edge_system` only (inventory row; `edge_actor` is refused, with a cell). `16_edge_role.sql` proves a 25-month-old row and a 40-month-old row
are purged (the bound is honoured, oldest first), a 23-month-old row and a young one are kept, and the NULL / 0 / over-100000 bounds are refused. The import /
drain pass calls it where it calls the fix-coordinate purge (`drainRescoreBacklog`, `RescoreBacklogResult.tombstonesPurged`).

### Accepted follow-ups (append-only)

- **E5 (launch-blocking).** Both retention purges (`purge_fix_coords`, 30 days; `purge_install_link_tombstones`, 24 months) run ONLY inside a catalog import's
  drain pass. **Schedule them independently of an import** (a cron / scheduled function) before launch, so a quiet catalog cannot stop retention. Until then the
  retention promises in the privacy label depend on an import happening.
- **E6.** Before launch: privacy-officer / PIA sign-off and a privacy-policy disclosure for the install-link tombstone; disclose the fix-coordinate re-pick
  exception in the privacy label (owner decisions above).
- **E7 (PR3).** Run `import-catalog` entirely as edge_system with delegate binders; then `edge` mode needs one URL. **Closed by edge role PR3** (section "Edge role PR3" below).
- **E5 (CLOSED in code by edge role PR4b; scheduling is a deploy step).** `retention-purge` runs all four retention classes as `edge_system`, independently of an import; schedule it hourly (design doc section 15). The two `service_role`-only TTL purges (`purge_consumed_nonce`, `purge_rate_limit_buckets`) were left unscheduled as an owner decision; **closed by edge role PR4c / migration 0040** (owner decision 2026-10-02: `edge_system` EXECUTE on exactly those two, and two more `retention-purge` steps; design doc 14.8).

## Edge role PR3 (2026-10-02): the system path (follow-up 6, step 3 of 4)

Follow-up 6 is still open until PR4. PR3 moves the system path of `import-catalog` onto `edge_system` and the delegate binders: design as built, the PR4 blockers and the
`[unverified]` items are in [`docs/security/edge-role-design.md`](edge-role-design.md) section 13. **No migration (there is no 0039)** and no grant, policy, allowlist row, fixture or
definer was added: every importer statement already fits the 0031 `edge_system` column grants and policies, and the cross-user reads and purges already had definers (0030, 0033).
FORCE RLS is untouched; nothing was given to `edge_system` on a PII table (check 12 unchanged).

- **`withDelegatedActor(delegate, actor, op)`.** `edge`: one transaction that starts as `edge_system`, binds through `private.bind_delegate_for_queued_evidence(evidence_id)` (valid only while
  the evidence is `queued_catalog`) or `private.bind_delegate_for_rescore(backlog_id, play_id)` (valid only while the backlog row is open and the play is at its course), then acts as `edge_actor`;
  `private.actor_uid()` must equal the owner the caller EXPECTS (the system list's `user_id`) before `op` runs. `legacy`: exactly `withOwnership`. The drain re-reads `queued_input` as the row's
  owner (`Repo#evidence.readQueuedInput`); the list omits it in both modes. Orchestrator signatures: `drainQueuedCatalog(importerRepo, withDelegatedActor, ...)`,
  `drainRescoreBacklog(importerRepo, withDelegatedActor, ...)`; the rescore page request is capped at 500 (`MAX_RESCORE_PAGE`, the definer's own clamp).
- **The importer repo as `edge_system`.** `withSystemCatalogImport` in `edge` runs the existing statements as `edge_system`, with three of them through definers (`list_queued_catalog`,
  `list_rescore_plays`, `purge_fix_coords`; the tombstone purge was already one). `import-catalog` in `edge` mode needs `GOLFRAVEN_EDGE_DB_URL` only.
- **Sign in with Apple (section 12, item 3).** Left as is: `signin-revocation-drain` already runs as `edge_system` through `openScopedTx("system")` and acts on no account, so it has no
  use for a delegate. The OTP-proven cross-account link stays `501` in `edge` mode; **the decision to build a proof-bound definer is deferred** (recorded as a PR4 blocker).
- **Carried PR2 LOWs / NITs.** (1) The design doc now says the 24-month tombstone purge runs in BOTH modes (the "legacy byte-for-byte" claim was wrong since 0033). (2) The edge self-check is
  periodic (5 minutes / 1000 transactions; a failure is never remembered; concurrent callers share one check). (3) `tools/db/test.sh` no longer puts the throwaway `edge_gateway` password
  inside a `su -c` string (stdin instead). (4) Supavisor transaction mode with `prepare: true` on the edge pool is documented as a PR4 pre-deploy check `[unverified]`, behaviour unchanged.
- **PR4 blockers** (detail in the design doc): delete `legacy` and add the lint pass; the cross-account link (build it or ship the 501); E5 (schedule both purges independently of an import);
  the Supavisor / `prepare` check and the real provisioning of `edge_gateway` (both `[unverified]`); the R2 `held_review` ruling; the deploy config for `import-catalog` (edge URL only); the
  self-check interval is an unmeasured default.
- **Tests.** `supabase/tests/integration/edge-system-path.deno.test.ts` (12 tests, forced to `edge` mode): the whole system path with `SUPABASE_DB_URL` unset and again pointing at an unusable host (with
  a control that the same URL breaks `legacy`); a delegate binds only the named row's owner, and an unscoped query inside it sees 0 foreign rows; a delegate for evidence that is not `queued_catalog`, a
  closed backlog row or a play at another course is refused before any work runs; naming A's row while expecting B fails closed; a delegate-bound transaction is a system delegate (it cannot export; the
  user-bound control can); the real queued and rescore drains open every per-row transaction with the delegate for that row and its owner; the purges run through the `edge_system` definers (with EXECUTE
  revoked from `edge_system` they stop; superuser harness) and the retention bounds are the database's. `edge-role.deno.test.ts` gained the periodic self-check cell (superuser harness). Unit:
  `edge-selfcheck-gate.test.ts` (9, fake clock), `edge-system-path-isolation.test.ts` (10 source pins), orchestrator signatures and delegate refs in `drain-orchestrator.test.ts` and
  `catalog-promotion.test.ts`. pgTAP matrix 16 gained cells 712-713 (below).
- **A layered-defence finding, closed with cells.** Mutation proof showed that deleting the `status = 'queued_catalog'` predicate from `bind_delegate_for_queued_evidence` left every pgTAP cell and the
  whole Deno suite green: `pd_queued_catalog_read` hides a non-queued row from `private_definer`, so the same `P0002` and message come out of the policy's NOT FOUND. Likewise the binder's
  `p.course_id = v_course` is masked by `pd_rescore_play_read` (plays at a course with SOME open backlog row; observed the same way). Cells 712 and 713 widen the policy to `true` in a rolled-back transaction, prove with a control that
  the row IS then visible to `private_definer`, and expect the body's refusal; each fails when its predicate is removed. (The other layer, a mutant that widens `pd_queued_catalog_read` to `USING (true)`, passes pgTAP and the Deno suite and is caught by `tools/db/verify-function-inventory.mjs` against `supabase/tests/fixtures/definer_policy_exprs.txt`: `expected using_expr="(status = 'queued_catalog'::app.evidence_status)" ... got using_expr="true"`.)

- **Verification (PR3 on `fb91e05`, 2026-10-02, PostgreSQL 17, a fresh cluster per run).** `tools/db/test.sh` green in HARNESS_MODE=superuser and =restricted: pgTAP `Files=21, Tests=1866,
  Result: PASS` (1864 before; matrix 16 is plan 713); the Deno integration suite **211 passed / 0 failed in `EDGE_DB_MODE=legacy` AND 211 / 0 in `edge`**, in each harness mode (198 / 198 before: 12 new
  tests in `edge-system-path.deno.test.ts` and 1 in `edge-role.deno.test.ts`); `verify-function-inventory: OK`; `service-role-lint: clean`. The superuser-only cells (the periodic self-check, the
  self-check mutation cells, the purge EXECUTE-revoke cells) print `skipped` under HARNESS_MODE=restricted and run under `superuser`. Unit suite 42 files / 793 tests (40 / 767 before), `service-role-lint`
  tests 4 files / 316, `pnpm -r typecheck` exit 0, `deno check --frozen` and `deno cache --frozen` exit 0 over every CI entry point on a fresh `DENO_DIR`,
  `check-migrations-immutable.sh --base fb91e05` (38 files byte-identical) and `--self-test`, `gitleaks dir` no leaks.
- **Mutation proofs (`/tmp` copies only, a fresh cluster each; nothing mutated was left in the tree).** (1) `withDelegatedActor` binds with `bind_actor` (`userBind`) instead of the delegate: **6 Deno tests
  fail**, among them the two that drive the REAL queued and rescore drains (each calls the public `withDelegatedActor` with the drain's own arguments and expects the account-export definer to refuse
  the transaction as a system delegate). (2) The `queued_catalog` predicate removed from `bind_delegate_for_queued_evidence`: **pgTAP cell 712 fails**; before 712 existed this mutant passed every pgTAP
  cell and all 24 Deno tests of the two edge files (the layered defence above), so the Deno suite alone does NOT kill it. (2b) The binder's course predicate removed from `bind_delegate_for_rescore`:
  **cell 713 fails**; with matrix 16 reverted to its pre-PR3 text this mutant also passes every pgTAP cell and the Deno suite. (3) `withSystemCatalogImport` routed back to the legacy pool in `edge` mode: **5 Deno tests fail** (the legacy-URL-unset and unusable-URL tests, the missing-edge-URL test, and
  both purge tests, which need the `edge_system` definers). (4) The periodic self-check disabled (success remembered for the pool's life): **1 Deno test fails** (the periodic cell) **and 6 unit tests fail**.
  (5) Widening `pd_queued_catalog_read` to `USING (true)`: caught only by `verify-function-inventory.mjs` (above).

## App Attest key registration (2026-10-02): follow-up F2 closed in code, not yet on a device

New Edge Function `supabase/functions/devices-attest-key/` (thin entrypoint) over `supabase/functions/_shared/rewards/`, and one
migration, `supabase/migrations/0034_attest_key_registration.sql` (0033 is another builder's, 0035 Sign in with Apple's; 0001-0032 are
untouched). It lets an iOS install register its App Attest key, so `rewards-activate` can grade that device `attested`.

> ⚠ **LIVE VERIFICATION IS NOT EXERCISED.** There is no iPhone, Apple account or network route to Apple in the build environment. Every
> statement below about Apple's attestation object, certificate chain and validation procedure is `[unverified — training knowledge]`
> until a real-device run (follow-up K1). The tests build synthetic attestations (a throw-away root, an intermediate and a leaf with the
> nonce extension) with Web Crypto, so they prove the server is **self-consistent and fails closed**, not that a real device's
> attestation verifies. The one real Apple artifact exercised is the pinned root certificate (parsed; fingerprint pinned; see below).

### What was built

| Piece | File | Notes |
|---|---|---|
| Endpoint | `devices-attest-key/index.ts`, `_shared/rewards/attest-key-handler.ts`, `attest-key-request.ts` | `POST /v1/devices/attest-key`; JWT, strict body, rate limits before the transaction, `withOwnership`; unconfigured = 503 before any read or write |
| Verifier | `_shared/rewards/app-attest-registration.ts` | pure, DI'd; `createAttestationVerifier(config, { sha256 })`; every failure a named reason, nothing throws to the caller |
| Parsers | `der.ts`, `cbor-strict.ts`, `x509-lite.ts` | strict DER (minimal lengths, minimal non-negative INTEGERs, exact times), strict CBOR (no tags/floats/indefinite/64-bit/duplicate keys), a chain checker for exactly `leaf <- intermediate <- anchor` (ECDSA P-256/P-384, SHA-256/384, via Web Crypto). **No new dependency; `deno.lock` and the import map are unchanged.** |
| Pinned trust anchor | `_shared/rewards/apple-app-attest-root.ts` | Apple's App Attestation Root CA as public data; see "Trust anchor" |
| Binding | `_shared/rewards/string-binding.ts` (+ `attestKeyChallengeString` in the verifier); also used by the iOS branch of `activate-handler.ts` | see "Challenge and clientDataHash" |
| Repo seam | `privileged.ts` | one `attestKey: buildAttestKeyRepo(trx, uid)` line in `buildRepo`, one delimited "App Attest key registration additions" section appended at the end (repo + config loader), and a one-statement change to `Repo#rewards.deviceAttestState` (below) |
| Schema | `0034_attest_key_registration.sql` | three columns, the redefined counter trigger, `app.register_attest_key`, the edge wrapper, registries; **no new table** |
| Reused | `activate-handler.ts#consumeLiveChallenge` (now exported, param type narrowed, behaviour unchanged) | the SAME single-use live challenge check as activation |

### Endpoint contract

`POST /v1/devices/attest-key`, body (exactly these five fields; unknown fields are a 400):

```
{ "deviceId": "<uuid>", "challengeId": "<uuid>", "nonce": "<unpadded base64url>",
  "keyId": "<44-char standard base64 from generateKey>", "attestation": "<base64 CBOR attestation object>" }
```

Obtain the challenge from `POST /v1/checkin/challenge` first (a LIVE challenge: 120 s, single-use, bound to the device and the caller;
the SAME pattern and code activation uses; no new challenge table). Responses: **201** `{deviceId, keyId, replaced:false}` (first
registration), **200** `{..., replaced:true}` (a reinstall's replacement), **409** `key_already_registered` (that key is already the
device's; nothing is consumed) or `key_previously_retired`, **422** `attestation_rejected` (the attestation did not verify; ONE generic
code, the reason is logged server-side only) / `challenge_not_consumable` (also the answer for another user's device and for a
nonexistent one: no existence oracle; this holds on EVERY path that can say it, including the database's own `P0002` from
`app.register_attest_key` if the device vanished between the handler's own-device read and the write: `privileged.ts#attestKeyError` maps it to
this same 422, not to a 404 `no such device`, which was an existence oracle; pinned by a Deno cell that calls the repo directly with a foreign and
a nonexistent id) / `platform_mismatch`, **429**, **503** `attestation_not_configured`.

**A failed verification still spends the challenge.** It is returned, not thrown, so the transaction commits with the challenge consumed:
one challenge gives one guess, not a retry loop against the verifier. (A thrown error would have rolled the consumption back.) It raises
**no** `fraud_signal`: the likeliest cause of a rejection is an honest build/configuration mismatch (a development build against a
production deployment: wrong aaguid), and an account-wide `attestation_failed` signal would hold every reward the account has; the device
simply stays `unattestable`, as today.

### Challenge and clientDataHash (the §7.5 interop note)

The first design hashed `SHA-256(canonical_body ‖ RAW nonce bytes)`, the construction `binding.ts` used for activation. The mobile
builder's library spike found that the recommended React Native module, `@expo/app-integrity` 57.0.2, **takes the challenge as a string
and hashes that string with SHA-256 itself** before calling App Attest (for both `attestKeyAsync` and `generateAssertionAsync`)
`[unverified: relayed, not checked here]`. Raw nonce bytes do not survive a round trip through a JS string, so a client built on it could
not produce the old binding. Registration therefore uses a **string binding**:

```
S              = {"challengeId":"<uuid>","deviceId":"<uuid>","keyId":"<keyId>","nonce":"<nonce>","platform":"ios","purpose":"attest_key_registration"}
clientDataHash = SHA-256(UTF-8(S))
```

keys sorted, no whitespace, UUIDs lowercase, `keyId` the string `generateKey` returned, **`nonce` the unpadded base64url STRING the
challenge endpoint returned, not decoded**. The client passes `S` as the module's `challenge`. `S` is printable ASCII with no quote or
backslash, so a template literal and `JSON.stringify` over sorted keys agree and there is no encoding question. Nothing is weakened: the
nonce string in `S` is the one the server just consumed against the stored SHA-256 of its decoded bytes; `purpose` separates a
registration hash from an activation hash. Implementation: `string-binding.ts` (generic, `computeStringBinding(sha256, fields)`) and
`attestKeyChallengeString` / `computeAttestKeyBinding`; unit-pinned byte for byte.

**The nonce spelling is canonical (security-gate NIT-1).** The nonce string goes into `S` as text AND is decoded to
bytes for the challenge hash, so a decoder that tolerates non-canonical base64url would let one consumed challenge be bound under several
strings (the last character of a length-`n mod 4 != 0` value carries unused trailing bits that `atob` ignores: `AA`, `AB` and `AP` all
decode to the single byte `0x00`). `binding.ts#fromBase64UrlStrict`, the decoder `consumeLiveChallenge` uses for both endpoints, now
requires the round trip `toBase64Url(decode(s)) === s`; a non-canonical spelling is a 400 before the challenge is read or consumed.
Pinned by `rewards-binding.test.ts` (exhaustive over one byte, plus the 2- and 3-character cases and a length sweep proving canonical
values still decode) and `activate-handler.test.ts` (the non-canonical spelling of a real nonce: 400, verifier never called, challenge
still usable with the honest spelling). Not covered: `checkin/token-handler.ts` has its own decoder (it consumes the nonce but binds
nothing, and is not part of an App Attest or Play Integrity binding); it is unchanged.

**The same problem applied to the existing iOS activation assertion, so it uses the SAME binding (changed 2026-10-02, before anything
shipped; the path was unreleased and no client exists).** `activate-handler.ts#assessActivatingDevice` used to compute the iOS
`clientDataHash` as `computeRequestBinding(sha256, bound, nonceBytes)` = `SHA-256(canonical_body ‖ raw nonce bytes)`, which a
string-hashing module cannot produce. The iOS branch now calls `computeIosActivationBinding` (`string-binding.ts`), with `req.nonce`
(the string `consumeLiveChallenge` just consumed). **Android is unchanged**: Play Integrity's `requestHash` is a string the app computes
itself (a SHA-256 over a `Uint8Array` in JS), so `binding.ts` still serves it. `binding.ts` is otherwise untouched.

**One contract for both iOS endpoints.** In both, `clientDataHash = SHA-256(UTF-8(S))` and the client passes `S` as the module's
`challenge` (`attestKeyAsync(keyId, S)` for registration, `generateAssertionAsync(keyId, S)` for activation). `S` is canonical JSON: keys
sorted, no whitespace, printable ASCII, UUIDs lowercase, the nonce the unpadded base64url STRING the challenge endpoint returned (not
decoded):

| Endpoint | `S` (keys in this order) |
|---|---|
| `POST /v1/devices/attest-key` | `{"challengeId":…,"deviceId":…,"keyId":…,"nonce":…,"platform":"ios","purpose":"attest_key_registration"}` |
| `POST /v1/rewards/{id}/activate` (iOS) | `{"challengeId":…,"deviceCheckTokenSha256":"<hex sha256 of the DeviceCheck token sent>","deviceId":…,"nonce":…,"platform":"ios","purpose":"reward_activation","rewardId":…}` |

`purpose` domain-separates the two (and both from the Android raw-bytes `requestHash`). **H1 is preserved**: the DeviceCheck token's hash is
inside `S`, so a valid assertion from one device still cannot ride next to another device's clean token (the swapped-token must-fail case,
P3f AT-5 / H1, passes unchanged in behaviour: unit and Deno). The request body, `request-shape.ts`, the verifier (`app-attest.ts`, which
takes `clientDataHash` as given) and the decision table are unchanged. Tests moved: `activate-handler.test.ts` (the verifier is handed the
hash of the literal string, and not the raw-bytes form), `rewards-binding.test.ts` (new string-form cells: literal, every field incl. the token
hash, domain separation), `rewards-activate.deno.test.ts` and `attest-key.deno.test.ts` (their assertion builders). No pgTAP pins the binding.
Mutation checks: reverting the iOS branch to raw bytes, and dropping the token hash from `S`, each fail several unit tests.

Separately, and independent of the binding: the module reportedly has **no DeviceCheck token API and no config plugin**, so the App Attest
entitlement must be added by hand and activation's `deviceCheckToken` still needs a native module (or another library); that gap is the mobile
builder's, recorded here only because it decides whether a custom native module exists anyway.

**This contract (both endpoints, the string form, the module's hashing of a UTF-8 string, lowercase UUIDs) is `[unverified]` and needs a
real-device run** before any client is built against it.

### The verification procedure, step by step (every step `[unverified — training knowledge]`)

Apple's server-side validation of an attestation object, as implemented in `app-attest-registration.ts` (reason codes in brackets; the
verifier returns the first that fails, in this order):

| # | Step | Reason on failure |
|---|---|---|
| 0 | the client's key id is the canonical 44-char standard base64 of 32 bytes; `clientDataHash` is 32 bytes; the object is base64 and at most 16 KiB | `key_id_malformed`, `attestation_malformed_base64`, `attestation_too_large` |
| 1 | decode the CBOR map: exactly `fmt` = `"apple-appattest"`, `attStmt` = exactly `{x5c: [credCert, intermediate], receipt}`, `authData`; `authData` = `rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖ aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE_Key`, flags AT set / ED clear, nothing after the key | `attestation_malformed_cbor`, `attestation_bad_structure`, `attestation_bad_fmt`, `authdata_malformed` |
| 2 | verify the x5c chain to the pinned root: names chain by byte equality, every certificate valid at `now` (± 5 min), the intermediate a CA, the leaf not a CA and P-256, each signature verifies | `chain_parse`, `chain_names`, `chain_validity`, `chain_not_a_ca`, `chain_leaf_is_ca`, `chain_leaf_key`, `chain_signature` |
| 3 | `nonce = SHA-256(authData ‖ clientDataHash)` equals the single OCTET STRING in the credCert extension `1.2.840.113635.100.8.2` (accepted as `SEQUENCE { OCTET STRING }` or `SEQUENCE { [1] { OCTET STRING } }`) | `nonce_missing`, `nonce_mismatch` |
| 4 | SHA-256 of the credCert's public key (the 65-byte uncompressed point) equals the key id | `key_id_mismatch` |
| 5 | `rpIdHash` = SHA-256(`"<TeamID>.<BundleID>"`) | `rp_id_mismatch` |
| 6 | `counter` = 0 | `counter_not_zero` |
| 7 | `aaguid` = `appattestdevelop` (development) or `appattest` + seven `0x00` bytes (production): **16 bytes either way** (the brief said "plus 9 zero bytes"; `appattest` is already 9 of the 16) | `aaguid_mismatch` |
| 8 | `credentialId` = the key id | `credential_id_mismatch` |
| + | extras, refuse-only: the COSE key is the credCert's key; the key is a valid P-256 point | `cose_key_mismatch`, `public_key_invalid` |

Not done: the `receipt` (an opaque Apple-signed blob for Apple's fraud-metric endpoint) is parsed as bytes and ignored. Deliberately not
done: revocation, name constraints, key usage / EKU, and refusing on an **unrecognised critical extension** (the chain is rooted in a
pinned Apple CA, so the check buys nothing and an unknown Apple extension would turn into a false rejection; follow-up K5).

### Trust anchor

Apple's App Attestation Root CA is **pinned in code** (`apple-app-attest-root.ts`, public data). `createAttestationVerifier` takes
`trustAnchorDer` as a constructor parameter; the only production value is `APPLE_APP_ATTEST_ROOT_DER`, set in
`privileged.ts#loadAttestKeyVerifierConfig` and nowhere else. Tests construct a verifier with a throw-away root. Pinned by tests
(`attest-key-isolation.test.ts`): `createAttestationVerifier` is built only by `devices-attest-key/index.ts`; `trustAnchorDer` is assigned
exactly once outside the verifier, in `privileged.ts`, from the pinned constant; no source mentions an anchor/root environment variable;
the Deno suite sets plausible variable names and shows the anchor does not move.

- **Provenance `[unverified against a second source]`.** Fetched 2026-10-02 from
  `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem` by an agent whose outbound TLS passes through a
  TLS-terminating egress proxy, so the bytes are "what the proxy served for Apple's URL". Subject = issuer =
  `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`; EC P-384, `ecdsa-with-SHA384`; valid 2020-03-18 .. 2045-03-15; serial
  `0B:F3:BE:0E:F1:CD:D2:E0:FB:8C:6E:72:1F:62:17:98`; SHA-256 of the DER
  `1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32`. **Before this ships, a human compares that
  fingerprint with the one Apple publishes (or fetches the URL from a clean machine) and confirms they are equal** (follow-up K2). A unit
  test pins the SHA-256 of the embedded bytes to the constant and checks the certificate parses, is a CA, is self-signed and signs itself;
  it cannot tell you the constant was right to begin with.

### Schema (0034) and the re-registration decision

No table is added, so there is nothing new to classify in `private.pii_retention_policy` / `pii_export_policy`, and **no edge_actor policy**
(edge_actor reaches the key columns only through the definer; its column grant on `app.device` still excludes `attest_key_id` /
`attest_public_key` and now the two new columns). What changed:

- `app.device` gains `attest_registered_at` (set only by the registration function) and `attest_retired_key_hashes text[]` (the SHA-256 of
  the last 16 retired key id strings); `CHECK` constraints cap the list at 16 and require a key id and public key whenever
  `attest_registered_at` is set. Neither column is exported or exposed through `api.my_device`.
- **`app.register_attest_key(p_user_id, p_device_id, p_key_id, p_public_key)`**: invoker-rights, the shape of `app.activate_*`
  (`service_role` today; `private_definer` for the wrapper). It checks the key is a 65-byte uncompressed point **and that the key id is
  the base64 SHA-256 of it** (the database refuses to pair an id with a key that does not hash to it), locks the caller's own iOS device
  row, refuses the same key (`55000`) and a retired key (`23514`), writes the key, and audits (`audit_log`
  `device.attest_key_registered` / `device.attest_key_replaced`, with 16-hex hash prefixes and the counter the old key reached; never a key
  id or key). A first registration leaves the counter as it was.
- **`private.register_attest_key_for_actor(p_device_id, p_key_id, p_public_key)`**: `SECURITY DEFINER`, owned by `private_definer`, the
  only EXECUTE for `edge_actor`; reads the BOUND `kind = user` actor (a system delegate is refused), calls the function above as
  `private_definer` under the new actor-keyed policy `pd_edge_act_device_update` (registered in `private.definer_policy_allowlist` and
  `definer_policy_exprs.txt`) and a column grant limited to what the function writes. `app.register_attest_key` itself is **not**
  callable by `edge_actor`. PR2-PR4 note: `Repo#attestKey.register` becomes `select private.register_attest_key_for_actor(deviceId, keyId, publicKey)`;
  `deviceKey` and `deviceAttestState` are plain reads inside edge_actor's SELECT grant.
- **Re-registration (a reinstall means a new key).** The Secure Enclave key does not survive a reinstall; an install that kept its device id
  asks to register the new key on the SAME row. The old counter (say 40) cannot carry over (the new key's assertions start at 1), but
  0032's trigger forbids any counter decrease. Decision: **a counter may fall only when a key is replaced by a key this row has never used,
  and that is decided by the CONTENT of the UPDATE, not by who runs it.** The redefined `app.device_attest_counter_monotonic()` allows a
  decrease iff all of: the new counter is 0; the key id and the public key both changed (neither NULL); the OLD key's hash is in the NEW
  retired list; and the NEW key's hash is in neither the OLD nor the NEW retired list. So no assertion ever signed under a key the server
  has seen can be replayed against a lowered counter: the lowered counter belongs to a key with no history. Everything else (the same key,
  a hand-written rollback, a swap that "forgets" to retire, a retired key coming back) is `23514`.
  **Correction (security-gate NIT-2; migration `0036_attest_hardening.sql`).** As shipped in 0034 the trigger did NOT refuse "forgetting a
  retired entry": it checked the three list conditions above and nothing about the rest of the list, so a hand-written replacement whose NEW
  list silently omitted some OTHER retired key was accepted (and that key could then be registered again). 0036 redefines the same
  function (`CREATE OR REPLACE`; same owner, `search_path`, ACL and inventory row, no grant or policy touched) so that, inside the one
  decrease branch, the NEW list must equal EXACTLY what `app.register_attest_key` writes: the OLD list with the replaced key's hash
  appended, newest 16 kept (FIFO). That is stricter than "OLD is a subset of NEW" and has no special case at the cap: at 16 the oldest drops
  and the rest keep their order, anything else (a dropped or reordered entry, a smuggled extra one, the wrong entry dropped at the cap) is
  `23514`; pgTAP `17_attest_key_registration.sql` section 7b. **Not enforced at 0036 (closed by 0038, next paragraph):** the trigger was
  `BEFORE UPDATE OF attest_counter`, so a statement that did not assign `attest_counter` did not fire it and a bare
  `UPDATE ... SET attest_retired_key_hashes` was not covered by any trigger; only `service_role` and `private_definer` hold UPDATE on that
  column and the only code that writes it is `app.register_attest_key`. The retired list is FIFO-capped at 16 (a key that aged off could return, but that needs a fresh Apple attestation, and Apple is
  believed to allow `attestKey` once per key `[unverified]`; follow-up K6).
  **Correction (security-gate LOW-A; migration `0038_attest_trigger_key_change.sql`).** Everything above that says "a retired key coming back
  is `23514`" and "the counter may fall only for a replacement" described what the trigger was MEANT to enforce; at 0036 it decided on "the
  counter went down", not on "the key changed", and returned at once when the counter had not fallen. As `service_role` (or `private_definer`) three
  hand-written statements were accepted: **P15** `SET attest_key_id = <retired key>, attest_public_key = <its public key>, attest_counter =
  <the old value>` (a retired key returns with its old counter window reopened; the retired list still names it); **P16** the same swap
  without assigning the counter (the trigger did not fire); **P17** wipe the retired list (no counter change, no trigger), then replace
  onto the retired key. Only `service_role` and `private_definer` can write those columns and `app.register_attest_key` refuses a retired key, so this was
  defence in depth, but the sentence was not true of the database. 0038 drops and recreates the same trigger
  (`device_attest_counter_monotonic_trg`) as `BEFORE UPDATE OF attest_counter, attest_key_id, attest_public_key,
  attest_retired_key_hashes` and redefines the same function (`CREATE OR REPLACE`; owner, empty `search_path`, ACL and the
  `private.function_inventory` row unchanged; no grant, policy or RLS setting touched) so it decides on whether the KEY changed, by
  content, never by role: **key unchanged** (id and public key both equal) means the counter may not decrease and the retired list may not
  change (a key that is not changing is not re-judged: rows written before 0038 are left alone); **whenever the key changes, whatever the shape,
  the NEW key must be WHOLE and BOUND** (security-gate LOW A/B on the first 0038): both columns non-null, and `attest_key_id =
  encode(sha256(attest_public_key), 'base64')`, the exact expression `register_attest_key` checks (0034). Without it the "never used before" test compared
  the key-id LABEL, so a retired public key came back under a fresh label, a key id with no public key was accepted on a keyless device (and
  then blocked `register_attest_key` there for good), and a key id paired with another key's public key was accepted; each is now `23514`, as is a cleared key.
  The retired-list membership checks therefore run on a bound identity. **First registration** (no key id and no public key before; the bound key is required as above) means the counter and the list stay as they are (the counter
  is left alone because `register_attest_key` leaves it alone; it is 0 on every reachable keyless row, and the existing suite registers
  a keyless device that sits at 5); **replacement** (both before, both after, both different) means exactly what
  `register_attest_key` writes: counter 0, the new (bound) key's id hash in neither the OLD nor the NEW list (the OLD-list test is a wall of its own: at the 16-entry cap the FIFO drops the oldest retired entry from the NEW list, so a replacement ONTO that key is caught only by it; security-gate LOW C), the NEW list equal to (OLD list ||
  hash of the replaced key) trimmed to the newest 16, and `attest_registered_at` set; **anything else is `23514`**.
  **Clearing a key is refused** (NEW key NULL while OLD is not, or a half-key): no legitimate path clears a key, because a device is
  deleted, never updated, when its account goes (`private.delete_my_data` and the `auth.users` cascade use the DELETE policy
  `pd_delete_device_user_id`), and a cleared-then-reinstalled key is the rollback this closes. What is still NOT enforced, stated: the public key's own shape beyond the 65-byte CHECK (`register_attest_key` also requires the leading `0x04`; a hand-written key with another leading byte is still accepted); the trigger
  cannot tell a VERIFIED registration from an unverified one (Apple's chain is checked in TypeScript), so `attest_registered_at` is only required
  to be set on a replacement, not proven (and not required to move forward: it is the writing transaction's `now()`, and two registrations racing for the row lock take it in the opposite order to their start times, which `attest-key.deno.test.ts` "two concurrent registrations" caught in a first draft); a statement touching none of the four columns is not covered; `TRUNCATE`, `ALTER TABLE ... DISABLE
  TRIGGER` and a superuser are outside any row trigger. Proved by pgTAP `17_attest_key_registration.sql` (sections 5b, 6, 7, 7b: P15, P16, P17,
  a key change at a counter that is not 0, a key change onto a retired key, a list change with the key unchanged, clearing a key, the
  at-cap FIFO accept and refuse, a retired public key under a fresh label, half keys and mismatched pairs at first registration and at replacement, the at-cap replacement onto the oldest retired key, and must-pass cells for every legitimate shape, including a correctly bound first registration and replacement). Test fixtures that wrote keys by hand in a shape the new trigger refuses were
  changed to a legitimate shape, not the trigger to fit them (`rewards-activate.deno.test.ts#registerKey` now replaces the placeholder key the
  way `register_attest_key` would, then advances the counter, and every fixture key id is now DERIVED from its key (`registerKey`, `newDevice`'s per-device placeholder, the shared key in `15_rewards_activation.sql`); the pgTAP A5 cell that set a retired list by hand now builds that state through the function).
  Alternatives rejected: leave the counter alone on replacement (the new key's first 40 assertions would fail as replays and raise an
  account-wide `attestation_failed`); a per-key counter in a side table (a new table with all its registry rows, for what two columns and a
  trigger do); a role-based exemption in the trigger (then every role that may hold it holds a rollback).
- **An attested grade requires a REGISTERED key.** `Repo#rewards.deviceAttestState` (privileged.ts, a one-statement change inside the
  P3f section) now returns the stored key id and public key only when `attest_registered_at` is set, i.e. only for a key written by
  `app.register_attest_key` after a verified attestation. A key written any other way reads as "no key" and grades `unattestable`, never
  `attested`. The §7.5 decision table and `app-attest.ts` are unchanged; `activate-handler.ts` changed only in the iOS binding (see the
  interop note) and the exported challenge helper. The activation suites changed only for that binding and one line in
  `rewards-activate.deno.test.ts#registerKey`, which now also sets `attest_registered_at` (it stands in for a verified registration).
- After a replacement the OLD key's assertions fail `key_id_mismatch` (graded `failed`, as for any wrong key) and the new key's start from
  counter 1: both proved end to end against real Postgres through the real activation handler.
  **That holds for a replacement that committed BEFORE the activation read the device. Security-gate LOW-1 found the in-flight case and it
  is closed.** `deviceAttestState` reads the row without a lock, the verifier then runs with no database, and
  `advanceAttestCounter` writes. Under READ COMMITTED a registration that commits in that window changes the row the UPDATE lands on: the
  old `UPDATE ... WHERE id AND user_id AND attest_counter < $new` carried no key predicate, so it re-evaluated against the NEW row
  (counter 0), wrote the retired key's counter (say 41) onto it, returned "advanced", and the activation was graded `attested` and
  issued on a retired key, while the new key's next 41 assertions failed as replays and held the account. `advanceAttestCounter` now takes the
  key id the assertion was verified against and adds `AND attest_key_id = $key` (privileged.ts; the same statement in both
  `EDGE_DB_MODE`s: `edge_actor` already holds SELECT on `app.device`, and its UPDATE grant is still `attest_counter` / `last_seen` etc. only;
  no migration, no grant or policy change). Zero rows fails closed exactly like a lost replay race: `failed`, the
  reward held, never `attested`. **Reason, since NIT-A:** the handler re-reads the device (only on this failure path, same transaction) and records `key_replaced` when the key it
  verified against is no longer the device's key, and `counter_replay` otherwise (the counter was not higher, or the device is gone); no schema change
  (`fraud_signal.detail` is jsonb), same grade, same held outcome, and the same account-wide `attestation_failed` signal as before. The signal is deliberately kept: a
  retired key's assertion reaching the server is a reinstall racing an activation or a captured assertion, and a reviewer has to see which; the reason
  tells them, and clearing the signal is still a human act. A registration that has not yet committed cannot interleave either: the advance takes the device row lock
  first and the registration (which locks the same row) waits. Proved by `attest-key.deno.test.ts` ("race: ...", an `IosPort` whose
  `verifyAssertion` runs the REAL verifier on K1 counter 41 and then commits a K2 registration through the real repo before returning; run
  in both modes: the reward is held, the signal says `key_replaced` (it said `counter_replay` before NIT-A), K2's counter stays 0 and K2's counter-1 assertion then issues),
  `activate-handler.test.ts` (the same interleaving over the fake repo) and pgTAP `17_attest_key_registration_edge.sql` section 5b (the
  statement as `edge_actor`: 1 row for the current key, 0 for another key, 0 for a replay).

### Configuration

Read **only** in `privileged.ts` (`loadAttestKeyVerifierConfig`); a missing or malformed variable means unconfigured and the endpoint
answers 503 before any read or write: `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID` (the same two the DeviceCheck/assertion path reads; the
App ID is `<team>.<bundle>`) and **`GR_APPLE_APPATTEST_ENV`** (`production` | `development`: which aaguid an attestation must carry). It
is its own variable rather than `GR_APPLE_DEVICECHECK_ENV` because it is a property of the app build's entitlement, DeviceCheck's is a
property of the API host, and registration needs no DeviceCheck credential; in a normal deployment the two agree. There is no
environment-mismatch canary (a deploy configured `production` receiving a development build rejects with `aaguid_mismatch`, logged
server-side; compare follow-up F16). The trust anchor is **not** configuration. Rate limits (`devices-attest-key:user` 10/h,
`devices-attest-key:device:<id>` 10/day) have no plan-stated numbers.

### Tests (what each proves)

- **Unit (vitest)**: `app-attest-registration.test.ts` (verifier, parsers, pinned root, binding; every must-fail below),
  `attest-key-handler.test.ts` (order of checks, challenge discipline, ownership, rate limits, request shape),
  `attest-key-isolation.test.ts` (source-level guarantees), the file list in `rewards-isolation.test.ts` extended.
- **pgTAP**: `17_attest_key_registration.sql` (service_role lane, 136 assertions: schema, privileges, first registration, the counter,
  replacement, the trigger decided by content including hand-written writes, the FIFO cap, validation and ownership, who can read or write
  the new columns, export and deletion) and `17_attest_key_registration_edge.sql` (the edge_actor lane as a real `edge_gateway` login, 54
  assertions: every registration proved by reading the row back, direct writes closed, the counter cannot be lowered by edge_actor, foreign
  device, delegate refused, stale binding).
- **Deno integration** (`attest-key.deno.test.ts`, real `withOwnership`, real SQL): registration and audit, a key written outside the
  verified path is not handed to the verifier, replacement, the same key, a failed attestation spends the challenge, a replayed challenge and
  two concurrent requests on one challenge, another user's device, Android, an uncommitted-first-registration row-lock probe, the database's own
  refusals, account deletion, the config loader, the production wiring rejecting a test-root chain, and **two end-to-end tests through
  `handleActivation` with the real assertion verifier** (before registration: held `unattestable`; after: `attested` and `issued`; after a
  reinstall: the new key verifies from counter 1 and the old key is `failed`).
- **Must-fail cells**: wrong root, same-name root with another key, broken chain, wrong issuer name, intermediate not a CA, leaf claiming to
  be a CA, expired / not-yet-valid leaf, wrong x5c count, non-P-256 leaf, wrong nonce, missing nonce extension, a replayed or re-bound
  challenge / device / key, wrong rpIdHash (and a verifier configured for another app), nonzero counter, wrong aaguid in both directions,
  keyId mismatch, credentialId mismatch, COSE mismatch, bad flags / trailing bytes / truncated authData, wrong fmt, malformed key id /
  base64 / oversize, malformed CBOR (truncated, trailing, indefinite, tag, junk), structurally wrong objects, malformed DER (trailing
  byte, non-minimal length, mutated TBS, v1, mismatched inner algorithm, padded signature INTEGER), another user's device, a nonexistent
  device, another user's challenge, another device's challenge, a prefetched / expired challenge, a wrong nonce, an Android device.
- **Mutation proofs** (applied to `/tmp` copies, nothing planted in the tree), each caught by the named layer: verifier checks removed
  one at a time (nonce, rpIdHash, counter, aaguid, key-id hash, credentialId, COSE key, fmt, chain names, intermediate signature, leaf
  signature, validity, intermediate-is-CA, DER minimal / negative INTEGER, trailing certificate bytes, binding purpose / device / nonce
  dropped, key sorting) by the unit suite; handler (failure thrown instead of returned, device ownership, platform check, same-key
  pre-check, unconfigured accepted) by the unit suite; SQL (trigger allows any decrease, a role-based exemption, no retired check, the
  OLD list not checked, no key-id-hash check, no owner in the device select, an edge grant on the app function or on a key column, a
  broadened `pd_edge_act_device_update`, a delegate allowed, no FIFO trim, audit actions swapped, first registration resetting the counter)
  by pgTAP or the standalone inventory check; and (Deno) the registered-key gate removed, the row lock removed, an error mapping removed,
  and the trust anchor read from the environment (also by the isolation test).

### Accepted follow-ups (K-numbers are this work's own)

- **K1. Live conformance run on a physical iPhone.** Run a development build, `generateKey` + `attestKey`, POST the result, and confirm
  a 201. Each reason code is a lead if it fails: `chain_*` (the intermediate's actual extensions, basicConstraints, validity),
  `nonce_*` (the extension's DER shape), `aaguid_mismatch` (environment), `cose_key_mismatch` (an extra check not on Apple's list),
  `authdata_malformed` (flags), `attestation_bad_structure` (extra `attStmt` keys). Then repeat with a production-environment build
  (TestFlight) against a `production` deployment, then run an activation with the registered key (this also exercises the assertion verifier's
  own unverified layout, F1). The same run settles the string-binding contract above and the activation proposal.
- **K2. Compare the pinned root's fingerprint with Apple's published one** (provenance above).
- **K3. The `receipt` is ignored.** It could feed Apple's fraud-metric endpoint; not built.
- **K4. One key per device row; a second account on the same install needs a new key.** Apple allows `attestKey` once per key, so two
  accounts cannot register the SAME key, and `app.device_link_signals` (which links device rows by `attest_key_id`) therefore does not link
  two accounts on one iOS install by key. iOS multi-account detection is DeviceCheck's job (the bits), as before.
- **K5. Unrecognised critical extensions are not rejected** (above).
- **K6. The retired-key history is bounded at 16.**
- **K7. Rate-limit numbers (10/h, 10/day) have no plan-stated source.**
- **K8. No iOS client exists.** The wire contract above is the specification; see the interop note for the library question.
- **K9. No environment-mismatch canary** (compare F16).
- **K10. Certificate-validity skew is ±5 minutes** (clock skew between this server and Apple's issuance). Apple's credential certificates
  are believed short-lived `[unverified]`; if the live run shows a leaf already expired at attestation time, this is the knob and the
  reason code is `chain_validity`.

## O12 — Sign in with Apple, server side (2026-10-02): `me-signin-methods`, the provider-grant revocation on deletion

Build plan §3.4 (Auth row, linking rules (1)-(5)), §4.4 (`signin_provider_token`), §4.7 item 8 (rate limits), §4.8 (envelope
encryption, the client-secret expiry check), §7.8 (Apple 5.1.1(v)), P4 AT (17)-(19). Migration **`0035_signin_providers.sql`**
(0033 is the edge-role PR2 migration and 0034 is App Attest's; 0001-0034 are untouched). **Nothing here has been exercised against Apple, Google or a
real Supabase Auth**: there are no credentials and no route to them in the build environment. The provider adapters are proven against a
synthetic Apple (run-time-generated keys, a scripted `fetch`), the database half against the real harness cluster. Every Apple-specific
fact is marked `[unverified — training knowledge]` where it is used; the P4 spike against a real service id and key confirms them (list below).

**This closes the P3d gate round 2 accepted follow-up 1** ("provider rows are deleted BEFORE real Apple/Google revocation exists"), for
Apple and, in the same shape, for the Google *revocation* half (Google *capture* is a TODO, below). `DELETE /v1/me` now queues the grant,
revokes it at the provider, and only then deletes; a failed revocation is retried for 72 h and logged and never blocks the deletion.

### What was built

| Piece | Where |
|---|---|
| `me-signin-methods` Edge Function: `GET` list; `POST {action: link \| unlink}` | `supabase/functions/me-signin-methods/index.ts`, `_shared/signin/methods-handler.ts`, `request-shape.ts` |
| Apple identity-token verification (RS256 against Apple's JWKS; `iss`, `aud`, `exp`, `iat`, `sub`, the **nonce** binding) | `_shared/signin/apple-id-token.ts` |
| Hardened outbound HTTP (https + host allow-list, `redirect: "error"`, timeout, stream size cap, no body in any error) | `_shared/signin/safe-fetch.ts` |
| Apple client secret, minted server-side as an ES256 JWT from the `.p8` with Web Crypto; cached, re-minted before expiry, **fails closed** | `_shared/signin/apple-client-secret.ts` |
| Authorization-code exchange and token revocation (Apple); token revocation (Google) | `_shared/signin/apple-client.ts`, `google-client.ts`, `production.ts` |
| Envelope encryption (AES-256-GCM per-row DEK, wrapped by a Vault-held KEK) | `_shared/signin/envelope.ts`, `private.get_signin_token_kek` |
| Durable revocation queue + runner + drain endpoint | `private.signin_revocation_queue` (0035), `_shared/signin/revocation.ts`, `supabase/functions/signin-revocation-drain/index.ts` |
| `DELETE /v1/me` orchestration: queue, revoke, then delete | `_shared/me/delete-orchestrator.ts` (new), `me-delete/index.ts`, `_shared/me/delete-handler.ts` |
| Configuration (the only env reads) | `loadAppleSiwaConfig()` in the O12 section at the end of `_shared/privileged.ts` |
| Monthly client-secret expiry check (§4.8) | `_shared/signin/secret-expiry.ts`, `tools/apple/check-siwa-secret-expiry.mjs` |
| Tests | `supabase/tests/matrix/17_signin_providers.sql`, `18_signin_providers_edge.sql`, `integration/signin-methods.deno.test.ts`, `unit/signin-*.test.ts`, `unit/fake-signin-repo.ts` |

### The §3.4 rules, and where each is enforced

| Rule | Enforcement |
|---|---|
| (1) one account per verified email | `private.signin_find_account_by_email` (service_role only, deterministic `ORDER BY`; an edge_actor reaches it through `signin_find_account_by_email_for_actor`, which refuses unless a kind = `user` actor is bound: F7) on the (verified) email in the Apple token; a match with another account is never merged. The database refuses to move or duplicate an identity (`signin_link_identity`, 23505 → 409 `identity_conflict`; one Apple per account → 409 `provider_already_linked`). An **unverified** email claim is neither matched nor stored. |
| (2) never auto-link a social sign-in whose email matches an existing account; email OTP proof first | A link whose Apple email belongs to *another* account is refused, 409 `email_proof_required`, with **no exchange, no write**. With `emailProof.code` the OTP is verified (`EmailOtpVerifier`, Supabase Auth `verifyOtp`) for *that address*; only a verified proof links the identity, and it links to **the account the proof was for**, not to the caller. The attempt is **reserved before the code is checked**, in one statement that checks the cap and increments (`private.reserve_signin_otp_attempt`; F3: the earlier peek-then-record let 20 parallel wrong proofs all reach the verifier), and given back only for a proof that succeeded or never reached a verdict. So at most **5 wrong proofs per target email per hour reach the verifier, then 429 even for a correct code**; a transport failure is not counted. The session `verifyOtp` creates for the proven account is signed out (`signOut({scope:"local"})`) immediately (F5); a proof for a different account than was looked up is 409 `email_proof_mismatch`. **Edge mode (0039, "Edge role PR4a" below): the `501` this row used to carry is gone.** After the OTP verifies, a single-use proof row is minted by `edge_system` (bound to the caller, the target, the address and the Apple subject; checked against the target's own `auth.users` row and GoTrue's sign-in stamp) and redeemed by the bound caller, which links and stores the token for the proof's target, never the caller. |
| (3) a private-relay address is its own email | Stored and flagged as given. A relay address never takes the proof path (409 `email_belongs_to_another_account` if it matches another account); a relay account links only from this endpoint, signed in, to the **caller**. |
| (4) unlink only while another method remains | `private.signin_unlink_identity`: one transaction, per-account advisory lock, 55000 → **422 `last_sign_in_method`**. Two concurrent unlinks of a two-method account leave exactly one (integration test, 3 rounds). |
| rate limits | 10/user/h on link and unlink (`hitRateLimitForActor`, before the transaction opens); 5 failed OTP proofs per target email per hour (`private.reserve_signin_otp_attempt` / `release_signin_otp_attempt`, bucket key built in the database from a sha256 of the email — no address is ever in a bucket key; since 0037 `reserve` returns the hour window it charged and `release` takes that window, and the edge lane calls the `_for_actor` wrappers, see Round 3). `GET` (list) is not limited. |
| "another user's id" | The request has **no field that names an account**; `userId` / `user_id` / `uid` / `email` in a body are *rejected* (400), not ignored. Everything is the authenticated caller's own account; another account's method is 404, another account's Apple identity is 409. |

### Design decisions

**Envelope encryption (§4.8) — exactly how.** Per row: a fresh random 32-byte **DEK** encrypts the refresh token with AES-256-GCM (fresh 12-byte
IV); a **KEK** held in **Supabase Vault** wraps the DEK with AES-256-GCM (fresh IV). Both layers carry AAD: the token layer binds the
provider, the wrap layer binds the `kek_id`, so a ciphertext cannot be moved to another provider's row or another KEK. Layout of both blobs:
`0x01 || iv(12) || ciphertext+tag`. Stored in the existing `app.signin_provider_token` columns (`refresh_token_ciphertext`, `dek_wrapped`,
`kek_id`). The KEK is one 32-byte key, base64, in a Vault secret named `siwa_token_kek_<id>`; `private.get_signin_token_kek(NULL)` returns the
**newest** (wraps a new DEK), `(<id>)` a named one (unwraps a stored DEK). **The crypto runs in the Edge runtime, not in the database**: the
plaintext token and the DEK never travel as a query parameter (Postgres logs the parameters of a failing statement), only ciphertext and the
wrapped DEK do; the KEK comes back as a function *result*, never as a parameter or in a message. Why Vault and not an external KMS: the plan's
"otherwise Vault" branch, with no vendor contract requiring otherwise; a KMS would implement the same two-method `Kek` shape and nothing else
changes. **Honest limit (design doc R6):** any runtime allowed to call `get_signin_token_kek` can read the KEK, which is the §4.8 "decrypted only
inside connector functions" boundary, not a stronger one. **Nothing exports the token**: `0022`'s `pii_export_policy` keeps
`signin_provider_token` = `exclude` (a pgTAP cell asserts it), and the Edge `me-export` is untouched.

**The revocation queue.** `private.signin_revocation_queue` holds a copy of the grant's envelope (ciphertext, wrapped DEK, `kek_id`, never
decrypted in the database) and **no column that names a user**, so it survives the account deletion without being a personal row — which is
why it has no `pii_retention_policy` / `pii_export_policy` classification (neither registry has anything to classify: no FK to `auth.users`;
a pgTAP cell asserts no such FK and no user/email/handle-named column, so a future one fails). Idempotent on `(provider, md5(ciphertext))`: a
retried `DELETE /v1/me` re-reads the same still-present grant row and gets the *same* queue row back, attempts and backoff intact. `claim` leases
rows (`FOR UPDATE SKIP LOCKED`; a held row is skipped, never waited for — integration test with a real second session) and first expires what is
past 72 h (material wiped, status `expired`, `RAISE LOG` with queue id and provider only); `complete` records `revoked` (material wiped) or a
*short machine code* (CHECK-constrained to `[a-z0-9_:.-]{1,64}`, anything else becomes `unclassified`: a provider response could echo a token)
and a backoff of 1 min doubling to 6 h. A superseded token (a re-capture with a different refresh token) is queued as `replaced`.
**The order in `DELETE /v1/me`:** (1) enqueue in its own committed transaction; (2) revoke at the providers with no transaction open — *before*
the provider rows are deleted (the integration test observes the grant row still present from inside Apple's revoke call); (3) delete. Step 2
never throws: a failed or impossible revocation (provider down, Apple unconfigured, KEK missing, decrypt failure) is recorded and logged
(`{event:"signin_revocation", queueId, provider, outcome, attempts, error}` — no user, no token) and the deletion proceeds. `me-delete`'s
response now carries per-provider `signinProvidersRevoked: [{queueId, provider, status: revoked | queued_for_retry, error?}]`. A retry of the
whole request after a partial failure completes and adds no second queue row. The Auth user (and its identities) is deleted afterwards, as
before.

**The drain.** `signin-revocation-drain` is system work: `POST`, authenticated by the **service-role key as the bearer** (constant-time
compare in `privileged.ts`; the gateway's JWT check alone would also admit an anon key), runs ≤ 25 due rows and purges finished rows older than
30 days. It is a deploy step to schedule it (below); nothing in this repo schedules it.

**Apple verification details.** Header `alg` must be exactly `RS256` (none/HS256/RS512/ES256 are refused *before any key is touched*); `kid`
looked up in a JWKS fetched through the hardened fetcher and cached 1 h (an unknown `kid` refetches at most once a minute; stale-if-error for up
to 24 h, then fail closed); `iss` exactly `https://appleid.apple.com`; `aud` the configured client id (a string, or an array of exactly that
one); `exp` in the future; `iat` not in the future (60 s skew); `sub` non-empty; **`nonce` mandatory**: the claim must equal SHA-256-hex of the
client's raw nonce (Apple's native flow), compared in constant time. **The raw value is never accepted as the claim** (F1: a token holder can read the claim, so accepting `claim === raw` let anyone holding an id_token verify it with `rawNonce = payload.nonce`, binding nothing; the request-shape floor for the raw nonce is now 16 characters); a token without a nonce is refused. The code
returned by the exchange must belong to **the same Apple user as the identity token** (the id_token Apple returns is verified too, minus the
nonce); otherwise 422 `authorization_code_mismatch` and the grant that was just minted is revoked. If the database write fails after the
exchange, the unrecorded grant is revoked too (best effort, logged if it fails): no live token nobody can revoke.

**Client secret (§4.8).** Minted **only on the server**, as an ES256 JWT (`kid` = the key id; `iss` team id, `sub` client id, `aud`
`https://appleid.apple.com`, `exp` = +10 min), from the `.p8` with Web Crypto; cached and **re-minted when under 2 minutes remain**; an
absent/blank/unparseable key throws `NotConfiguredError` on first use and nothing substitutes a default (the unit suite's must-fail set covers
five unconfigured shapes and five unusable-key shapes). A one-line PEM with literal `\n` (how an env var carries it) is accepted. The
long-lived (≤ 6 months) secret that **Supabase Auth's own** Apple provider setting needs is a *different artifact*; that is the one the monthly
check guards.

### Configuration — the only env reads, all in `privileged.ts` (`loadAppleSiwaConfig`)

| Variable | Meaning |
|---|---|
| `GR_APPLE_TEAM_ID` | Apple developer team id (shared with the DeviceCheck configuration) |
| `GR_APPLE_SIWA_CLIENT_ID` | the client id: the app's **bundle id** for the native flow (the token's `aud`) |
| `GR_APPLE_SIWA_KEY_ID` | the Sign in with Apple key's id |
| `GR_APPLE_SIWA_PRIVATE_KEY` | that key's `.p8` contents (a secret; never logged, never sent to a client) |

**Any one missing or blank → unconfigured → 503 `provider_not_configured` on every Apple operation, never a fallback** (integration test:
none set, three of four, a blank key). For `DELETE /v1/me` unconfigured does *not* block: the grant is queued as `not_configured_apple`.
Also read by the drain and the OTP verifier through existing variables only (`SUPABASE_URL`, `SUPABASE_ANON_KEY`,
`SUPABASE_SERVICE_ROLE_KEY`). **Supabase Auth's own Apple provider configuration is a deploy/dashboard step, documented, not built**: enable
the Apple provider; give it the Services ID / bundle id as the client id, the team id, the key id and a **pre-generated client-secret JWT**
(≤ 6 months), and put the *same* client id in `GR_APPLE_SIWA_CLIENT_ID`.

### Deploy steps this build cannot do (need real accounts)

1. Create the Sign in with Apple key and the Services ID / App ID capability under the organisation Apple account (P0 prerequisite for P4).
2. Set the four `GR_APPLE_*` function secrets; configure Supabase Auth's Apple provider (above). Register the custom SMTP domain with Apple's
   private relay `[unverified; A78]`.
3. Create the KEK in Vault: one 32-byte key, base64, named `siwa_token_kek_v1` (e.g. `select vault.create_secret(encode(gen_random_bytes(32),
   'base64'), 'siwa_token_kek_v1')` `[unverified — Vault's creation API]`). **Never delete a `siwa_token_kek_*` secret while any
   `signin_provider_token` or pending queue row still names its id; there is no re-wrap job yet, so until there is one a KEK is never retired.**
4. Schedule `signin-revocation-drain` (e.g. every 5 minutes, `POST` with `Authorization: Bearer <service-role key>`).
5. **Run migration 0035 on a real Supabase branch first** and check the two `[unverified]` database assumptions below.
6. Calendar the client-secret re-mint, and run the expiry check monthly (next section).

### The monthly client-secret expiry check (§4.8)

`APPLE_SIWA_CLIENT_SECRET_JWT=<the secret pasted into Supabase Auth> node tools/apple/check-siwa-secret-expiry.mjs [--warn-days 30]` (or the JWT
on stdin). Exit **0** if more than 30 days remain; exit **1** if it is expired, expires within 30 days, is malformed or has no `exp` (it never
passes by default); exit 2 with no input. It prints when the secret expires, never the secret. Plain Node, no dependencies; the decision logic
is mirrored in `_shared/signin/secret-expiry.ts` and one unit test runs both against the same fixtures. **Not wired to a scheduler**: a
scheduled job needs the JWT as a secret in some CI or cron environment, which is an operator decision (the server's own secrets are 10
minutes long and cannot expire on anyone; only the dashboard copy can).

### Needs live credentials or a device (not proven here)

- Apple's real JWKS / token / revoke endpoints and shapes, the nonce convention a real iOS build produces, `invalid_grant` vs. other 400 bodies.
- `signInWithIdToken` / `linkIdentity` behaviour in Supabase Auth, and **GoTrue's automatic linking by email** (below).
- Supabase Auth's `verifyOtp` error statuses (a wrong/expired code is read as 400/401/403/404/422; anything else throws and is not counted).
- A real private-relay address through custom SMTP.
- Android and web sign-in (a *Services ID*, a different `aud`): `GR_APPLE_SIWA_CLIENT_ID` is one value today.

### `[unverified — training knowledge]` (all of it, in one place)

Apple: the issuer string; the JWKS URL `https://appleid.apple.com/auth/keys` and RS256/`kid`; the token and revoke URLs, their form fields and
status/error conventions; the client-secret claim set and the ≤ 6-month limit; `email_verified` / `is_private_email` possibly being strings; the
hashed-nonce convention. Google: `https://oauth2.googleapis.com/revoke` and its `invalid_token` 400. Supabase: **(a)** that the project's
`postgres` role can `GRANT` on `auth.identities` to `private_definer` and that table carries no RLS hiding its rows from a non-owner definer
(the same class of caveat as Vault, above); **(b)** GoTrue's `auth.identities` columns (`provider_id`, `identity_data`, the generated `email`,
`ON DELETE CASCADE` from `auth.users`) and that a row INSERTed there is accepted by GoTrue as a real identity — **Supabase's supported surface
for linking an id-token identity server-side is not known to this build; if the P4 spike finds one, swap the link/unlink definers for it (the
Edge code reaches them only through `SigninRepo`)**; (c) Vault accepting `siwa_token_kek_<id>` names and `decrypted_secrets` exposing
`created_at` (0029 already relies on the latter); `verifyOtp`'s error statuses.

### The honest gap that matters most: sign-in itself happens inside GoTrue

§3.4 rule (2) says a *social sign-in* whose email matches an existing account must not auto-link. **A sign-in done natively through Supabase
Auth (`signInWithIdToken`) happens inside GoTrue, which this server never sees**, and GoTrue links same-verified-email identities
automatically by default `[unverified — training knowledge]`. What this build enforces is every path that goes through `me-signin-methods`
(link while signed in, the OTP-proven link, unlink, grant capture). To make rule (2) true at the sign-in moment the P4 spike must either turn
GoTrue's automatic linking off, or route the first social sign-in through a pre-check. Until it does, a player can still be auto-linked by
GoTrue before this endpoint is ever called. Also for P4: **a native sign-in creates the Apple identity without going through this endpoint, so
no refresh token is captured**; the client must call `link` with the token and the authorization code right after sign-in (it is idempotent:
`created: false`, and the token is stored) or the grant will not be revocable.

### Residual risks and accepted follow-ups (O-numbers are this work's own)

- **O1. The nonce is client-chosen and not single-use.** Fixed in round 2 (F1): the claim must be `sha256(raw)` and the raw fallback is gone, with must-fail
  cells for a raw-valued claim and for the token's own claim submitted as the raw nonce. What remains, **not built on purpose** (a contained change, but not a small
  one: a server-issued nonce needs a new table, a definer, registry rows and a new endpoint, plus a client-contract change, and it would balloon this PR): the nonce
  is still chosen by the client, so it binds a token to a client-held secret and to the caller's session, not to "issued by us, used once". A replay still needs the
  caller's valid JWT *and* the single-use authorization code. **Remaining O1 work:** `POST /v1/me/signin-nonce` returning a random value stored hashed with a short
  expiry in a private table, consumed (deleted) by the same transaction that links; `link` then refuses an unknown or already-consumed nonce.
- **O2. Google capture is a TODO(P4).** `link` for Google is 501 `provider_not_supported` (it needs Google's code exchange and a native-flow
  decision). The Google *revoker* is built and unit-tested, so nothing changes in the queue once capture exists.
- **O3. One Apple client id.** Android/web (Services ID) needs a second `aud` and a secret with `sub` = that id. Note for that work: the `nonce` claim rule is
  `sha256(raw)` only, so a web flow must send `sha256(raw)` as the `nonce` parameter to Apple as well (Apple echoes it unchanged); a web client that sends the raw value is refused.
- **O4. KEK rotation has no re-wrap job.** A new KEK wraps new DEKs; old KEKs must stay while any row names them.
- **O5. Edge-role lane (E-numbers continue the PR1 list).** Rebased onto PR2's `EDGE_DB_MODE`. 0035 ships the `_for_actor` wrappers (edge_actor) and
  grants the queue operations and the KEK reader to `edge_system`, with **no new edge policy and no new edge table grant** (every edge path is a
  definer; `edge_actor` still reads `(user_id, provider)` only; check 10's allowlist is unchanged and the two new tables are invisible to checks
  11/12). In `edge` mode `privileged.ts` runs per-user ops through the `_for_actor` definers, the OTP counter as the actor, and the queue ops and
  KEK reader as `edge_system` (`openScopedTx("system")`); the full Deno suite passes in both modes. Open PR3 items: (i) the **OTP-proven link to
  another account** had no edge definer on purpose (it would be an "attach an identity to any account" primitive) and answered
  `501 email_proof_link_unavailable` in `edge` mode only; **closed by PR4a (migration 0039, "Edge role PR4a" below): a proof-bound definer pair, not a definer that takes the target**; (ii) `private.signin_find_account_by_email` is service_role only and an edge_actor reaches it through `signin_find_account_by_email_for_actor`, which requires a kind = `user` binding (F7: it was callable by any edge_actor with no binding check); a bound user still gets an id-only existence answer (no worse than R3); the edge-mode refusal to link another account's identity (`mustBeSelf`) has its own integration cell that calls `repo.signin.linkIdentity(otherUid, ...)` directly (F4); (iii) retire `SIGNIN_SYSTEM_ACTOR` with the legacy path in PR4.
- **O6. The OTP verification is not bounded by the vendor timeout** (Supabase Auth, through supabase-js): only the 15 s request race bounds it.
- **O7. `GET` (list) is not rate-limited** (the plan's 10/user/h is for linking); it is one cheap read.
- **O8. `auth.identities` is written by a definer.** A GRANT the grantor may not make (no GRANT OPTION) does **not** fail: PostgreSQL only warns ("no privileges
  were granted"). The earlier claim that a refused grant fails the migration loudly was wrong. 0035 now asserts every privilege it needs with
  `has_column_privilege` / `has_table_privilege('private_definer', 'auth.identities', ...)` right after the GRANTs and RAISEs if one did not take (F8). Proved by a
  mutation: the H2 approximation role stripped of DELETE on `auth.identities` gives the warning and then `0035: the GRANT DELETE ON auth.identities TO private_definer
  did not take effect`. A pgTAP cell asserts the privileges are held.
- **O9. F2 (MEDIUM, non-blocking, `[unverified]`): unlinking `email` may not end email access.** `signin_unlink_identity('email')` removes the `auth.identities`
  row only. GoTrue's email-OTP sign-in most likely looks the user up by `auth.users.email`, so the address may still sign in after the unlink: unlink is **not** a
  security control for the email method, and nothing here says it is (no API or UI text claims it; 0035 and `request-shape.ts` say so in a comment). **P4-spike
  item:** with a real project, unlink `email` on an account that holds another method and check whether `signInWithOtp` for that address still issues a session.
- **O10. F6 residual.** The delete transaction now re-enqueues under the per-account lock (the lock is held to commit), so no grant is stored between "queued" and
  "deleted" and none is deleted unqueued. A `link` that waits on that lock runs after the commit and can store a grant for a user whose rows are gone but whose
  `auth.users` row still exists until `deleteAuthUser`; that grant is cascade-deleted unqueued. Late grants caught by the second enqueue are revoked right after
  the commit, from the durable queue, not before the rows are deleted. **Corrected in round 3 (2026-10-02, N2); the wording above ("a few milliseconds", "needs the account's
  owner to link Apple while deleting the same account") understated it, and the "tombstone" it said was needed has been checked, not assumed:**
  - **How long the window is.** It opens when the delete transaction commits and closes when `deleteAuthUser` returns. In between, `orchestrateMeDelete` runs step 4
    (`runRevocationsBestEffort` over the late grants: the revocations run in parallel, each bounded by `SIGNIN_VENDOR_TIMEOUT_MS` = 3 s, plus the claim and complete
    round trips), and only then does the entrypoint call `deleteAuthUser` (an HTTP call to the Auth admin API; this file gives it no timeout of its own, only the 15 s request race around the whole handler, which abandons the response but does not cancel the call). So the window is
    **up to about 3 s plus two database round trips plus the Auth call, not milliseconds**, and a `deleteAuthUser` that throws (the response is then an error and
    the caller retries) leaves it **open until the retry succeeds**. It is also not only for a link that was *waiting* on the lock: any `me-signin-methods` request that
    carries the still-valid session and starts after the commit gets through, because `signin_link_identity` only checks that `auth.users` has the row and
    `signin_store_token` only that the account holds the identity.
  - **What it costs.** If `deleteAuthUser` then succeeds, `auth.identities` and `app.signin_provider_token` both cascade away from `auth.users`, with no queue row for the new grant:
    the refresh token minted at Apple during that request is **never revoked at Apple** (the 5.1.1(v) gap this feature exists to close, for one grant, in a narrow race). If
    `deleteAuthUser` fails, the account survives with that identity and grant until the user deletes again (the retry's enqueue does queue it).
  - **The gate's cheap closure was investigated and cannot be built on what exists.** The suggestion was that the link / store definers refuse when the app-side row
    `delete_my_data` removes is gone. That needs a row every account is guaranteed to hold. None is: `app.profile` has no `INSERT` path in this repository (no migration,
    no Edge function; `INSERT` is revoked from `anon` and `authenticated` in 0009; `supabase/tests/helpers.sql` is the only writer), no trigger on `auth.users`
    exists in 0001-0036, and every other table `private.pii_retention_policy` lists (`device`, `push_token`, `play`, ...) is created by use, so an account that
    signed in by email OTP and linked Apple holds none of them. A refusal keyed on "the row is gone" cannot tell "deleted" from "never created", so it would either refuse
    every such user or refuse nobody. **No row was invented** (a deletion tombstone is a new table with its own retention and registry classification), so 0037 does not
    touch the link / store definers and there is no race cell for it.
  - **Closing it properly (not built; for a later round, each needs its own gate):** (a) a deletion tombstone written by `delete_my_data` in the same transaction and checked by
    link / store under the per-account lock (the install-link tombstone is the precedent: keyed so it names no person); or (b) make the session unusable *before* the
    delete commits, by banning the Auth user first through the admin API `[unverified: GoTrue's ban semantics for an already-issued access token (it is a JWT, valid until it expires) were not checked]`.
    Until then this is a documented, bounded residual, not a closed finding.
- **O11. Accepted NIT residuals:** the queue's idempotency key is `(provider, md5(ciphertext))`, so a grant re-queued more than 72 hours after the first row expired
  is a new row; expiry is lazy (applied when a claim runs); the envelope's AAD binds provider and kek id but not the user or the row, which is deliberate (the
  queue row has no user id) and means a ciphertext moved between rows of the same provider decrypts. The `verifyOtp` session sign-out is best effort (a failure is
  logged and does not fail the proof); the session is in memory only and never leaves the function.

### Verification (rebased onto App Attest `0daf155`; 0035 follows 0034)

- **`tools/db/test.sh`, the FULL harness, exit 0 in `HARNESS_MODE=superuser` and `restricted`** (a fresh cluster each, each on its own port): the two
  H2 no-`migration_owner` checks apply 0035; pgTAP **21 files, 1773 assertions** (`17_signin_providers.sql` and `18_signin_providers_edge.sql` beside
  the App Attest and edge-role files; `10_function_inventory.sql` passes unchanged); the Deno integration suite runs in BOTH `EDGE_DB_MODE`s,
  **189 tests per mode** (legacy and edge, 17 of them `signin-methods.deno.test.ts`); `verify-function-inventory.mjs` OK (checks 1-13, `edge_policy_allowlist`
  unchanged, the 8 new `private_definer` policies in the checked-in fixture); service-role lint clean. (One unrelated catalog-promotion test,
  `split_from conflicts fail closed`, failed once in edge mode on a salt-derived id and passed on the rerun and in the other harness mode.)
- Units: **40 files / 756 tests** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`); the lint's own **243** tests.
  `deno check --frozen` and `deno cache --frozen` (fresh `DENO_DIR`) over the entrypoint lists in CI (11 and 11 files, including `devices-attest-key` and the
  three sign-in entrypoints), both exit 0; **no new dependency, no new import specifier** (every import is relative; the lint's positive allow-list passes).
- `check-migrations-immutable.sh --base 0daf155` (34 files byte-identical) and `--self-test`; `gitleaks dir` no leaks; `pnpm -r typecheck` passes for every
  workspace project (`apps/site` after `GOLFRAVEN_DEMO=1 node scripts/emit-indexability.mjs`).
- **Edge mode, as built.** Per-user sign-in operations call the `_for_actor` definers as `edge_actor`; the OTP counter runs as the actor; the queue operations and
  the KEK reader run as `edge_system` (`openScopedTx("system")`). No grant or policy was added or broadened. The one behavioural difference is the OTP-proven
  link to another account: `501 email_proof_link_unavailable` in `edge` mode only (unit cells in `signin-methods-handler.test.ts`, a mode-aware integration
  test); recorded as the PR3 item under O5.
- **60 mutations (run before the rebase), each applied to a `/tmp` copy, every one CAUGHT** (5 survived the first pass and each is now closed by a new cell). TS (44): the id-token
  `iss` / `aud` / `exp` / nonce-mismatch / missing-nonce / signature-ignored / `alg`-check / reason-drift / JWKS-refetch-floor mutations; handler: rule (2) removed,
  relay on the proof path, OTP cap not enforced, a transport failure counted, a proof for another account accepted, another Apple user's code accepted,
  unrecorded grant not revoked, an unverified email trusted, Google link allowed, a second Apple ID allowed; orchestrator: delete before revoke, revocation
  errors blocking the deletion; revocation: failure code dropped, failures recorded as success, unconfigured Apple treated as revoked, no backoff growth;
  envelope: provider / kek id not in the AAD, a constant DEK, a constant IV, a kek-id mismatch tolerated; client secret: never re-minted, an unusable key
  falling back instead of failing closed, a lifetime past Apple's ceiling; safe-fetch: redirects followed, allow-list by suffix, no stream size cap, no timeout,
  http allowed; Apple client: `invalid_grant` not a grant error, every 400 on revoke treated as revoked, a 5xx on revoke treated as revoked; request shape:
  an unvalidated OTP code, unknown (user-id) fields ignored; expiry check without its 30-day threshold. SQL (11): the last-method check removed, the
  identity-conflict check dropped, enqueue resetting a queued row, `pd_signin_token_select` broadened to `true`, the KEK reader granted to `authenticated`,
  FORCE RLS removed from the queue, `service_role` granted the queue, claim without a lease, claim without `SKIP LOCKED` (caught by the Deno suite with a real second
  session), purge deleting pending rows, an arbitrary error string stored. `privileged.ts` (5, against the real cluster): `55000` no longer mapped to 422, a half-set
  Apple configuration counted as configured, the drain's bearer check always true, OTP failures not persisted, `23505` no longer mapped.
- **Not run:** PG16 (the harness defaults to PG17, `supabase/config.toml`'s pin); any test against a real Supabase project, Apple or Google; prettier and any deploy (out of scope).

### Round 2: security gate findings F1-F8 (on `main` 67f0b2c; 0035 edited in place, it is not merged)

| Finding | Fix | Proof |
|---|---|---|
| **F1** (MEDIUM, blocking) raw-nonce fallback | `claim === sha256Hex(raw)` only; request-shape floor 16 chars; O1 records the remaining server-issued-nonce work | 2 must-fail cells (a raw-valued claim; the token's own claim submitted as the raw nonce); mutation: fallback restored, both fail |
| **F3** OTP cap was check-then-act | `reserve_signin_otp_attempt` (one statement: cap check + increment) before verifying, `release_signin_otp_attempt` on success / transport failure | 20-parallel Deno cell (verifier called exactly 5 times), a unit twin, 7 pgTAP cells; mutation: a peek-then-record handler fails the Deno cell; mutation: the SQL cap removed fails 4 pgTAP cells |
| **F4** `mustBeSelf` untested | integration cell calling `repo.signin.linkIdentity(otherUid, ...)` and `storeToken(otherUid, ...)` directly in `edge` mode | mutation: `mustBeSelf` made a no-op fails exactly that cell |
| **F5** `verifyOtp` left a live GoTrue session | `makeEmailOtpVerifier` signs the session out (`scope: "local"`) | recording-fake cell (called on success, not on a refused code, a failed sign-out does not fail the proof); mutation: sign-out removed fails it |
| **F6** link between enqueue and delete | `signin_enqueue_revocations` takes the per-account lock; the delete transaction re-enqueues first and the late grants are revoked after the commit | a race cell (a grant stored during the Apple call is revoked), a lock cell (a link waits for the commit), a unit twin; mutations: second enqueue removed and lock removed each fail their cell |
| **F7** unbound email lookup | core is service_role only; `signin_find_account_by_email_for_actor` requires a kind = `user` binding; `ORDER BY u.id` | 4 pgTAP cells; mutation: binding check removed fails 2 |
| **F8** refused GRANT only warns | `has_column_privilege` / `has_table_privilege` assertions after the GRANTs, RAISE if one did not take | a pgTAP cell; mutation: the H2 approximation role without DELETE gives the warning, then the RAISE |
| NIT | RSA modulus >= 2048 bits on JWKS import (a 1024-bit key cell); `16_edge_role.sql` cell 708 echo no longer has an apostrophe inside `\echo` (the echo prints) | |
| **F2** (non-blocking) | documented as O9, a P4-spike item; no behaviour change, no text claims unlink ends email access | |

Numbers: `tools/db/test.sh` exit 0 in `HARNESS_MODE=superuser` and `restricted`; pgTAP **21 files, 1784 assertions** (`17_signin_providers.sql` 150, `18_signin_providers_edge.sql` 65); the
Deno suite **195 tests in each of `EDGE_DB_MODE=legacy` and `edge`**; vitest **40 files / 762 tests**; the lint's own **316** tests; `pnpm -r typecheck` clean; `deno check --frozen` and `deno cache --frozen`
(fresh `DENO_DIR`) exit 0; `gitleaks dir` no leaks; `check-migrations-immutable.sh --base 67f0b2c` and `--self-test` OK. The F3 concurrency cell is vacuous in `edge` mode (the proof path
answers 501 there, O5) and is proved in `legacy`.

### Round 3: non-blocking follow-ups L1, L2, N1, N2 (on `127970f` = `main` b8fed5b + the App Attest hardening commit; migration **0037**, 0001-0036 untouched)

| Finding | Fix | Proof |
|---|---|---|
| **L1** any `edge_actor` connection could call the OTP counter functions with no bound user (`release` is a decrement: it resets any address's brute-force counter; `reserve` burns an address's five attempts) | `peek_` / `reserve_` / `release_signin_otp_attempt_for_actor`, each calling `signin_bound_user` first (the F7 shape: unbound and system-delegate are 42501); EXECUTE on the three cores **revoked from `edge_actor`** (service_role keeps them); `privileged.ts` `buildSigninSystemOps(trx, mode)` calls the wrappers in `edge`, the cores in `legacy`; 4 inventory rows added/changed | 18 new pgTAP cells in `18_signin_providers_edge.sql` (unbound x3, system delegate x3, cores not callable unbound x3 and bound x3, privilege counts x3, a bound flow); mutations: binding check removed from the three wrappers fails 6 cells; cores re-granted to `edge_actor` fails 7 cells plus `10_function_inventory.sql` |
| **L2** `release` decremented the CURRENT hour window, not the one the reservation was taken in (a proof straddling the top of the hour refunded a window that never paid) | `reserve_signin_otp_attempt` returns `(o_attempts, o_window_start)`; `release_signin_otp_attempt(p_email_hash, p_window_start)` decrements exactly that window and refuses a non-hour-aligned or NULL one (22023); the one-argument release is dropped; `OtpFailureCounter.reserve` returns `{used, windowStart}`, `release` takes the window; the handler passes the reservation's window | 11 pgTAP cells in `17_signin_providers.sql` (a release naming the previous window moves that window and not the current one; none-row no-op; misaligned / NULL refused; the old signature gone), a Deno cell (real database, both modes), a unit cell that moves the clock mid-proof; mutations: SQL release on the current window fails 3 + 1 pgTAP cells and the Deno cell; handler releasing a window computed at release time fails 3 unit cells |
| **N1** the unit F3 cell's verifier was instant, so the round-1 peek, verify, record shape still passed it | the unit verifier now yields for 25 ms (a real round trip), the same as the Deno cell | mutation: the handler restored to peek, verify, record FAILS the unit F3 cell (`expected 20 to be 5`); the same mutation against the instant verifier PASSES that cell (only the L2 cell, which needs the release, fails), so the delay is what closes it |
| **N2 / O10** a link that waited on the per-account lock can store a grant between the delete's commit and `deleteAuthUser` | **not closed, deliberately.** The gate's closure needs an app-side row every account holds; there is none (see O10), and a tombstone table was not to be invented. O10 is corrected instead: the window is not "a few milliseconds" | n/a (nothing built, so no race cell); the evidence for "no such row" is the O10 text |

0037 touches no table, column, table grant, policy or RLS setting (FORCE RLS untouched); `private.edge_policy_allowlist` and `private.definer_policy_allowlist` are unchanged. The only grants it changes are EXECUTE (three revoked from `edge_actor`, three wrappers granted to it, the two recreated cores granted to `service_role` only). Every new definer is `SECURITY DEFINER`, owned by `private_definer`, `search_path = ''`, created inside the `GRANT CREATE ON SCHEMA private` bracket, with `private.function_inventory` rows. The migration needs `UPDATE, DELETE` on `private.function_inventory` for the old release row, so it uses 0032's temporary current-user policy and revokes it again.

**Honest limits.** (1) A BOUND user actor can still `release` / `reserve` for any address (the counter is keyed by the target address's hash); L1 closes "any connection", not "a signed-in caller going around the Edge code" (edge-role-design.md §12). (2) The Deno L2 cell is proved in `legacy` and `edge` against correct code, but its mutation (SQL release on the current window) was run in `legacy` only. (3) A rollover cannot be produced inside one pgTAP transaction (`now()` is fixed), so the L2 pgTAP cells stage it as "the reservation sits in the previous window's bucket row", which is what the database sees; the unit cell moves a fake clock mid-proof. (4) The in-database `now()` window arithmetic and the Edge code's `windowStart` round trip as an ISO string with millisecond precision (hour-aligned, so exact).

Numbers: `tools/db/test.sh` exit 0 in `HARNESS_MODE=superuser` and `restricted` (each a fresh cluster; both H2 no-`migration_owner` checks apply 0037); pgTAP **21 files, 1835 assertions** (`17_signin_providers.sql` 162, was 150; `18_signin_providers_edge.sql` 83, was 65); the Deno suite **198 tests in each of `EDGE_DB_MODE=legacy` and `edge`** (one new); `verify-function-inventory.mjs` OK; vitest **40 files / 767 tests** (one new; the F3 and L2 cells run with the 25 ms verifier); the lint **316** tests and clean over `supabase/functions`; `pnpm -r typecheck` exit 0; `deno check --frozen` and `deno cache --frozen` (fresh `DENO_DIR`) over the 11 CI entrypoints exit 0; `check-migrations-immutable.sh --base 127970f` (36 files byte-identical) and `--self-test` OK; `gitleaks dir` no leaks. Not run: prettier (out of scope), any deploy, a real Supabase project.

## Edge role PR4a (2026-10-02): the proof-bound cross-account Sign in with Apple link in `EDGE_DB_MODE=edge` (migration `0039_signin_proof_bound_link.sql`)

The owner decided (2026-10-02) to build the OTP-proven link in `edge` mode rather than ship the `501 email_proof_link_unavailable` as the production answer (the PR3 blocker, O5 (i)). Migrations 0001-0038 are untouched
(`check-migrations-immutable.sh --base 10e3afa`, 38 files byte-identical). Full design, the options considered and the trust argument against R6:
[`docs/security/edge-role-design.md`](edge-role-design.md) section 12.1. **Nothing here has been exercised against a real Supabase Auth**: the OTP is a scripted verifier that stamps `auth.users.last_sign_in_at` the way GoTrue
is believed to.

> **Superseded in part by 0041 ("Edge role PR #35" below):** the minter is no longer `edge_system` but the dedicated role `edge_signin_minter`, the mint also takes a GoTrue session id, and the address and subject are hashed in the database only. Read the PR #35 section for the current shape; the rows below describe 0039 as it merged.

### What 0039 contains

| Object | What |
|---|---|
| `private.signin_email_proof` | The single-use proof: `caller_user_id`, `target_user_id` (both FK to `auth.users ON DELETE CASCADE`), `provider`, `email_hash`, `sub_hash` (sha256 of `provider:subject`), `created_at`, `expires_at` (the minter sets 5 minutes; a CHECK caps 10), `consumed_at`; `caller <> target`. FORCE RLS, **no edge or client grant**, `UPDATE (consumed_at)` only, four `private_definer` policies (check-7 GUC form: the proof id, the account-deletion window, or an hour past expiry). |
| `private.signin_record_email_proof(...)` | The only writer. **`edge_system` EXECUTE only.** Refuses inside any actor-bound transaction; refuses unless the address hashes to the target's current `auth.users.email`; refuses unless the target's GoTrue `last_sign_in_at` is within 60 s; caller and target must exist and differ; deletes a bounded batch of hour-stale proofs. |
| `private.signin_link_identity_with_proof_for_actor(...)` | **`edge_actor` EXECUTE only**, `kind = 'user'` binding. Per-account advisory lock on the target, `FOR UPDATE` on the proof; refuses a proof that is consumed, expired, issued to another caller, for another provider / subject hash / address hash, or whose address no longer belongs to the target; refuses an unverified or relay email; then consumes it and calls the 0035 cores (`signin_link_identity`, `signin_store_token`) on **`proof.target_user_id`**. One call links AND stores the token (the proof is consumed once). |
| `private.purge_signin_email_proofs()` | `edge_system`, `service_role`; run by `signin-revocation-drain`. |
| `private.delete_my_data` | Redefined from 0032's body with exactly ONE added statement (delete the account's proofs as caller or target); the diff against 0032 is that one hunk. |
| Grant | `GRANT SELECT (last_sign_in_at) ON auth.users TO private_definer`, **asserted** in the migration (a refused grant only warns, O8). |
| Registries | `pii_retention_policy` (2 rows, `delete_row`), `pii_export_policy` (`exclude`), `definer_policy_allowlist` (4) + `definer_policy_exprs.txt`, `function_inventory` (3). `edge_policy_allowlist` and its fixture unchanged. |

TypeScript: `SigninRepo.proofBoundLink` (true in `edge`) and `linkIdentityWithProof`; `SigninDeps.emailProofs` (`signinEmailProofs()`, mints through `openScopedTx("system")` in its own committed transaction); the handler mints right
after the OTP verifies (and after the 5/hour cap's reserve and release, F3/L2 unchanged), before the Apple code exchange, and redeems in the same transaction that used to link and store. `crossAccountLink` is true in both modes;
`mustBeSelf` stays (the direct path refuses another account, now `403 cross_account_link_requires_proof`). The F5 sign-out is untouched. `legacy` is unchanged (direct link to the proven account; deleted in PR4b). The drain also purges proofs.

### The trust argument against R6, in one paragraph

A fully compromised runtime can already `bind_actor(<any uid>)` and call the 0035 self-link wrapper, and it holds the GoTrue service key, so the proof path **adds nothing to and removes nothing from R6**. What it adds is against a
handler bug or an injected statement in a per-user transaction: that actor cannot mint (no EXECUTE, and `SET ROLE edge_system` inside a bound transaction is refused by the minter), and can redeem only a proof issued to it, for
that Apple subject and that address, that the database itself checked against the target's own email and GoTrue's sign-in stamp. A runtime that skips verifying the OTP cannot mint unless the target signed in within 60 s.

### Tests

- **pgTAP** `19_signin_proof_link.sql` (58 cells: structure, constraints, scoping, purge, account deletion, session reuse) and `19_signin_proof_link_edge.sql` (78 cells, as the real `edge_gateway` login): edge_actor cannot
  mint (unbound, bound, and as edge_system inside a bound or delegate transaction); the minter refuses a wrong address, a stale / absent / future sign-in stamp, caller = target and bad arguments; an unbound actor and a system delegate
  cannot redeem; a proof for sub A cannot link sub B (or another provider or address); an expired, consumed (replayed), other-caller or changed-hands proof is refused; the link lands on the TARGET and the caller gains no method; the duplicate
  identity, one-Apple-per-account and last-method rules hold; the committed flow; retention (the minter removes an hour-stale proof and leaves a 15-minute one).
- **Two real sessions** `tools/db/test-signin-proof-concurrency.sh` (wired into `test.sh`): session A redeems and holds the transaction, B waits (>= 0.8 s) and is refused `28000 already used`; and 6 symmetric races, each with exactly one winner, one
  identity and one grant on the target, none on the caller.
- **Deno, `legacy` and `edge`** (`signin-methods.deno.test.ts`, 33 tests per mode, was 24): the full OTP-proven flow succeeds in both modes and lands on the proven account (identity AND grant, the stored token decrypts); the **OTP cap holds under 20-parallel
  load in `edge` now** (the F3 cell no longer skips it); the F5 sign-out happens in the full flow in both modes; edge-only cells (they `return` in `legacy`): replay refused, sub A cannot link sub B / another provider / address, other caller and the target
  itself cannot redeem, an expired proof, the minter refusing with no GoTrue sign-in (409 before any code is exchanged), concurrent redemption (4 parallel, 3 rounds: exactly one winner), account deletion and the purge.
- **Unit** `signin-methods-handler.test.ts` (+16): order verify, mint, exchange, redeem; the proof carries exactly caller / target / address hash / subject hash and neither raw value; no mint on a wrong code, a transport failure or a changed-hands
  proof; mint refusal is 409 with nothing exchanged and the OTP attempt given back; no minter on a proof-bound repo is 503 before any OTP is spent; a refused redemption revokes the grant; single use; `mustBeSelf`; the OTP cap in the proof shape.

### Mutation proofs (each applied to a world-readable `/tmp` copy, the whole suite then run, every one CAUGHT)

| Mutation | Caught by |
|---|---|
| link to `actor_uid()` instead of the proof's target | pgTAP edge (3 cells fail, then the file aborts on a later error), concurrency script, Deno `edge` (5 of 33 fail) |
| skip the consumed check | pgTAP edge (3), concurrency script (both sessions win), Deno `edge` (replay, concurrent) |
| skip the subject-hash binding | pgTAP edge (4), Deno `edge` (sub A / sub B) |
| skip expiry | pgTAP edge (1), Deno `edge` (expired) |
| grant proof minting to `edge_actor` | pgTAP 19 (3 cells), `10_function_inventory.sql`, `verify-function-inventory.mjs` (`edge_actor EXECUTE expected=f actual=t`) |
| also: remove the GoTrue sign-in corroboration | pgTAP edge (3), Deno `edge` (1) |
| also: allow minting inside an actor-bound transaction | pgTAP edge (2) |
| also: omit the proof deletion from `delete_my_data` | pgTAP 19 (2), Deno `edge` (1) |
| also: skip the caller binding (`caller_user_id <> actor`) | pgTAP edge (2), Deno `edge` (1) |
| also: remove the minter's stale-row purge | pgTAP edge (1) |

### Not verified (`[unverified]`), in one place

- **GoTrue**: that `verifyOtp` stamps `auth.users.last_sign_in_at` (recalled from its token-issuing path, not read from a live project); that `auth.users.last_sign_in_at` exists and is `SELECT`-grantable to `private_definer` on the real project
  (0016 already relies on the same mechanism for `id, email`; the migration asserts it); the clock skew between GoTrue and the database. Where the stamp is not written every mint refuses with `409 email_proof_refused`: fail closed, visible at once in the P4 spike.
- Everything the O12 section lists as unverified is still so (Apple, `verifyOtp`'s error statuses, `auth.identities` columns, GoTrue's automatic linking by email).
- The `edge` handler path was exercised against a scripted OTP verifier and the real harness cluster, never against Supabase Auth.

### Verification

- **`tools/db/test.sh`, the FULL harness, exit 0 in `HARNESS_MODE=superuser` AND `restricted`** (a fresh cluster each, ports 5745 / 5746): pgTAP **`Files=23, Tests=2012, Result: PASS`** (21 files / 1876 on `10e3afa`; +136 =
  58 in `19_signin_proof_link.sql` and 78 in `19_signin_proof_link_edge.sql`; `10_function_inventory.sql` and `16_edge_role.sql` pass unchanged); `tools/db/test-signin-proof-concurrency.sh` PASS (blocking case: B waited ~1.3 s then was
  refused; 6 symmetric races, one winner each); the Deno integration suite **220 passed / 0 failed in `EDGE_DB_MODE=legacy` AND 220 / 0 in `edge`, in each harness mode** (211 per mode before; +9, all in `signin-methods.deno.test.ts`,
  24 to 33 tests); `verify-function-inventory.mjs: OK` (checks 1-13, `edge_policy_allowlist` and its fixture unchanged, the 4 new `private_definer` policies in `definer_policy_exprs.txt`); service-role lint clean. The superuser-only cells print
  `skipped` under `restricted`, as before.
- **Unit**: `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` **42 files / 809 tests** (793 before; +16 in `signin-methods-handler.test.ts`); the lint's own **4 files / 316** tests; `pnpm -r typecheck`
  exit 0 for every workspace project (`@golfraven/catalog-tools...` built first, `pnpm install --frozen-lockfile`, `GOLFRAVEN_DEMO=1 node scripts/emit-indexability.mjs` in `apps/site`); `deno check --frozen` and `deno cache --frozen` over
  the 11 CI entry points on a fresh `DENO_DIR`, both exit 0 (no new import specifier: every import is relative); `check-migrations-immutable.sh --base 10e3afa` (38 files byte-identical) and `--self-test` OK; `gitleaks dir` no leaks.
- **Not run**: prettier (out of scope, never run), any deploy, a real Supabase project, Apple, Google or GoTrue; PG16 (the harness uses PG17).

## Edge role PR4b (2026-10-02): edge is the only mode (follow-up 6, step 4 of 4)

Design as built, the runbook and the rulings: [`docs/security/edge-role-design.md`](edge-role-design.md) sections 14 and 15. **No migration** (the planned `0040` was not needed; `check-migrations-immutable.sh --base 8cd86f7`: 39 files byte-identical). FORCE RLS, grants, policies, `edge_policy_allowlist` and checks 9-13 are untouched.

- **Deleted:** `EDGE_DB_MODE`, the `service_role` pool and every `SET LOCAL ROLE service_role`, `SUPABASE_DB_URL` as a database input, every legacy repo branch, `SIGNIN_SYSTEM_ACTOR`, the legacy rate-limit buckets, `SigninRepo.crossAccountLink` / `proofBoundLink`, the second Deno pass. Tests deleted (legacy-only): the `EDGE_DB_MODE` accepts-only-legacy/edge cell, the "legacy mode is broken by that URL" control, three handler unit cells (the 501 guard, "no cross-account route still links own", "legacy shape"); the service_role-shape pins of `with-ownership.test.ts` were rewritten. One existing cell was re-aimed, not deleted: `catalog-drain-resilience` NEW-2 provoked its lock timeout by holding the evidence row, which the drain now skips by design; it holds the play row the re-score upserts instead.
- **Still uses the service-role key:** `adminClient` (`auth.admin.deleteUser`) and `isServiceRoleBearer` (a constant-time bearer comparison for `signin-revocation-drain` and `retention-purge`). Nothing connects to Postgres as `service_role`.
- **Lint pass:** `privileged-lint.ts`, eight rules, 20 must-fail fixtures; see the design doc 14.3. `.savepoint(` is allowed in `withOwnershipBatch` (its only caller) and the service key in `isServiceRoleBearer`; both widen the brief and are justified there.
- **E5:** `retention-purge` (hourly; bearer, 12/hour rate limit, 10 batches x 5000 rows and 30 s per run, per-step try-lock, per-step failure isolation). Added to the CI `deno check` / `deno cache` lists.
- **PR3 gate P1:** `readQueuedInput` locks the row `FOR UPDATE SKIP LOCKED`; edge_actor's existing column `UPDATE` suffices, no grant added.
- **R2 ruling:** a legitimate path clears `held_review` (the scorer, `upsertFromScore`), so it stays writable both ways, inside R6; pinned by a Deno cell and one pgTAP cell.

### Tests

New: `retention-purge.deno.test.ts` (10 cells: each class purged and a young row of each kept, a pending revocation row never purged, idempotent re-run, bounded run, database bounds, bad bearer and absent key, 6 concurrent runs x 2 rounds, a held step skipped, one class failing (superuser harness), the rate limit), `retention-purge-handler.test.ts` (20 unit cells), the two P1 cells and the R2 cell in `edge-system-path` / `edge-role`, `privileged-lint.test.ts` (+ 21 fixtures).

### Verification (final tree, after the container restart; nothing from before it is counted)

- **`tools/db/test.sh`, exit 0 in `HARNESS_MODE=superuser` AND `restricted`** (fresh clusters, ports 5701 / 5702): pgTAP `Files=23, Tests=2012, Result: PASS` (unchanged: the R2 pgTAP check extends an existing cell); all three concurrency scripts PASS; Deno integration **232 passed / 0 failed once, in each harness mode** (was 220 per mode x 2 passes; the superuser-only cells print `skipped` under `restricted`); `verify-function-inventory.mjs: OK`; service-role lint clean.
- **Unit:** `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` 43 files / 826 tests (was 42 / 809); lint package 5 files / 356 tests (was 4 / 316); `pnpm -r typecheck` exit 0 (`pnpm install --frozen-lockfile`, `@golfraven/catalog-tools...` built, `emit-indexability` first).
- `deno check --frozen` and `deno cache --frozen` over the 12 CI entry points on fresh `DENO_DIR`s: both exit 0. `gitleaks dir`: no leaks. Migrations immutable (above).
- **Not run:** prettier (out of scope), any deploy, a real Supabase project, Supavisor, `pg_cron`.

### Mutation proofs (each on a world-readable `/tmp` copy or a cloned lab database, never in the repo; every one CAUGHT)

| Mutation | Caught by |
|---|---|
| reintroduce a `SUPABASE_DB_URL` read | lint `privileged-db-url` (exit 1) |
| `set local role service_role` / `... postgres` / `... ${role}` | lint `privileged-forbidden-role` (3 mutations) |
| service-role key read outside the two functions | lint `privileged-service-key` |
| stray `.begin(` / stray `.savepoint(` / a second `postgres(` pool | lint `privileged-stray-transaction` (2), `privileged-stray-pool` |
| `set_config(` / `current_setting(` in TS | lint `privileged-guc-in-ts` (2) |
| a reintroduced `EDGE_DB_MODE` read; a computed `Deno.env.get`; `Deno.env.toObject()`; a `service_role` literal outside the memberships array | lint `privileged-edge-db-mode`, `privileged-env-access` (2), `privileged-forbidden-role` |
| remove the drain row lock | the two P1 cells (2 of 14 in `edge-system-path`) |
| remove each of the four purges from `retention-purge` | `retention-purge.deno` (7, 3, 4, 2 failures) |
| remove the per-step try-lock / the bearer check / the batch cap / the rate limit | `retention-purge.deno` (1, 2, 1, 1 failures) |
| make `held_review` one-way (a trigger on a cloned database) | the R2 Deno cell and the pgTAP 16 cascade cell (the file aborts at test 500) |

### `[unverified]`

Everything in the design doc's runbook (section 15): Supavisor transaction mode with `prepare: true`, the hosted `ALTER ROLE ... LOGIN` / tenant user / `pg_hba` for `edge_gateway`, `pg_cron` + `pg_net` as the scheduling mechanism, that the platform injects `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_DB_URL`, whether the hosted admin role may EXECUTE the two `service_role`-only purges, and the self-check interval (an unmeasured default).

## Edge role PR4c (2026-10-03): the hygiene purges, the bounded sign-in purges, the lint's second pass (follow-up to PR4b)

Design as built and the runbook additions: [`docs/security/edge-role-design.md`](edge-role-design.md) sections 14.8 and 15. **One migration, `0040_retention_hygiene_purges.sql`** (`check-migrations-immutable.sh --base d4ab836`: 39 files byte-identical). FORCE RLS, table and column grants, policies, `edge_policy_allowlist`, `definer_policy_allowlist`, their fixtures and checks 9-13 are untouched.

- **The one new grant (owner decision 2026-10-02):** `GRANT EXECUTE ON FUNCTION private.purge_consumed_nonce() TO edge_system;` and `GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets() TO edge_system;`. Nothing else is granted to anyone. The migration asserts it with `has_function_privilege` (`edge_system`, `service_role` yes; `edge_actor`, `anon`, `authenticated` no) and fails itself if it did not take; the inventory (`expected_edge_system = true` for exactly these two) is what proves no other function gained a grant.
- **Redefinitions (all `private_definer`, `search_path = ''`, ownership bracket):** `purge_consumed_nonce()` (`CREATE OR REPLACE`, still `bigint`), `purge_signin_email_proofs()` and `purge_signin_revocation_queue(interval)` (`CREATE OR REPLACE`), each now bounded at 5000 rows per call by a constant inside the definer; **`purge_rate_limit_buckets()` is `DROP`ped and recreated** (same name, no arguments) because it returned `void` and a batched step needs the count (`CREATE OR REPLACE` cannot change a return type); its `service_role` grant was re-made (0007's), not widened. Why the two hygiene functions needed a bound at all: both were age-bounded and neither was row-bounded (one `DELETE` of the whole backlog; `purge_rate_limit_buckets` had never run).
- **`retention-purge`:** two more steps (`consumed_nonce`, `rate_limit_buckets`); the two sign-in steps are batched (they were one pass each, LOW-3); the catalog import's own fix-coordinate and tombstone purges take the same per-step try-lock (NIT).
- **`<uid>:me-delete:user`:** removed by `purge_rate_limit_buckets` once its window started more than 2 days ago (the me-delete window is one day: gone 1-2 days after its window ends, kept before). Proved against the real flow, not a hand-built row.
- **LOW-1 (lint):** `openPool()` takes no parameter and reads `GOLFRAVEN_EDGE_DB_URL` itself; `privileged-env-access` is now an allow-list on `Deno`; `privileged-stray-pool` also covers non-call driver references, an `openPool` parameter or argument, and a driver call not fed the constant read inside `openPool`; three new rules (`privileged-global-access`, `privileged-computed-member`, `privileged-unsafe-sql`); a `+` chain of string literals is folded and scanned. Allow-lists, each with its reason, because the real file has them: `globalThis.addEventListener` (the closed-socket containment hook). No allow-list for computed members (all 101 in the real file are numeric literals) and none for `.unsafe(` (the real file has none).
- **LOW-2:** `isServiceRoleBearer`'s `key === ""` guard is now covered (unset and empty key; NBSP, U+3000 and other trims-to-empty bearers; the function and the whole handler).
- **LOW-4:** `me-export` and `me-push-token` added to the three CI `deno` lists, and `supabase/tests/unit/ci-function-lists.test.ts` fails if any `supabase/functions/*/index.ts` is missing from any of them.
- **LOW-5:** runbook: deploy order, connection-limit sizing against 5 per worker, `verify_jwt` and the non-JWT secret keys, `SUPABASE_DB_URL` as a live credential, schedule notes for the six steps.

### Tests

New: `supabase/tests/matrix/20_retention_hygiene_purges.sql` (63 cells, every group a rolled-back transaction: who may execute what by name and by a real call as `edge_actor` unbound / user-bound / delegate-bound, `anon`, `authenticated`, `edge_system`, `service_role`; each purge removes only expired rows and a live row survives; the `<uid>:me-delete:user` flow; 5003 expired rows give 5000 / the rest / 0 for each of the four bounded purges; the two floors enforced twice are proved alone with the policies widened), 8 Deno cells in `retention-purge.deno.test.ts` (the me-delete bucket, a backlog over several batches for the four bounded steps, a full batch is exactly `RETENTION_DEFINER_BATCH_ROWS`, the import's purges honour the try-lock, LOW-2 x3, the hygiene steps fail without the grant), 3 unit cells (`retention-purge-handler.test.ts`), `ci-function-lists.test.ts` (6), and 26 lint cells + 17 must-fail fixtures.

### Verification (final tree; nothing from before the last edit is counted)

- **`tools/db/test.sh`, exit 0 in `HARNESS_MODE=superuser` AND `restricted`** (fresh clusters, ports 5717 / 5718, `DENO_DIR` unset, `npm_config_engine_strict=false`): pgTAP `Files=24, Tests=2075, Result: PASS` in both (was 23 / 2012: the new file is 63 cells); the 11 concurrency `PASS` lines in each; Deno integration **240 passed / 0 failed in each harness mode** (was 232; the superuser-only cells, now including the "without the grant" cell, print `skipped` under `restricted`); `verify-function-inventory.mjs: OK`; service-role lint clean.
- **Unit:** `pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts` 44 files / 835 tests (was 43 / 826); lint package 5 files / 382 tests (was 356); `pnpm -r typecheck` exit 0 (`pnpm install --frozen-lockfile`, `@golfraven/catalog-tools...` built, `emit-indexability` first).
- `deno check --frozen` and `deno cache --frozen` over the 14 CI entry points (13 functions and `_shared/privileged.ts`, taken from the CI step itself) on fresh `DENO_DIR`s: both exit 0. `gitleaks dir . --config .gitleaks.toml`: no leaks (13 MB). `check-migrations-immutable.sh --base d4ab836`: 39 of 39 byte-identical.
- **Not run:** prettier (out of scope), any deploy, a real Supabase project, Supavisor, `pg_cron`, the full `pnpm -r build` before `gitleaks` (the working tree and the `dist/` directories that already existed were scanned).

### Mutation proofs (each on a world-readable `/tmp` copy, deleted afterwards; never in the repo; every one CAUGHT)

| Mutation | Caught by |
|---|---|
| `GRANT ... TO edge_system` dropped from 0040 (migration assertion left intact) | the migration itself (`0040: ... EXECUTE for edge_system is f but must be t`) |
| the `service_role` re-grant of `purge_rate_limit_buckets` dropped | the migration itself |
| the same two with the migration's own assertion disabled | matrix 20 (3 not ok, file aborts at 53 of 63) and the inventory gate |
| an extra `edge_actor` grant on the nonce purge / an extra `anon` grant on the bucket purge | matrix 20 (3 / 1 not ok) and the inventory gate (`expected=f actual=t`) |
| the inventory not updated for the two grants | the inventory gate (`verify-function-inventory.mjs`) |
| `LIMIT` removed from each of the four purges | matrix 20 (2 not ok each) and the Deno exact-batch cell (4 x) |
| `v_limit` 5000 to 4000 in one definer / `RETENTION_DEFINER_BATCH_ROWS` to 4000 | matrix 20 + 2 Deno cells / the exact-batch Deno cell |
| the 7-day predicate dropped from the nonce body (policy still holds) / the 1-hour predicate dropped from the proof body / the nonce cutoff on `consumed_at` instead of the expiry | matrix 20 layered cells (the policy alone masks each otherwise) |
| bucket purge `2 days` to `0 days` (purges the current window) | matrix 20 (3 not ok) and 3 Deno cells |
| remove the `consumed_nonce` step / the `rate_limit_buckets` step from `retention-purge` | `retention-purge.deno` (4 / 5 failures) |
| the two sign-in steps unbatched again | `retention-purge.deno` (2 failures) |
| `isServiceRoleBearer`'s `key === ""` guard removed | `retention-purge.deno` (2 failures: key unset, key empty) |
| the import's fix-coordinate / tombstone purge try-lock removed | `retention-purge.deno` (1 failure each) |
| each lint rule (13 mutants of `privileged-lint.ts`: the `Deno` allow-list, the global object, `eval` / `Function`, `import()`, the non-call driver reference, the `openPool` parameter, the `openPool(arg)` call, the pool URL constant, `a[k]`, the computed destructure, `.unsafe(` arguments, a destructured `unsafe`, the concatenation fold) disabled | `privileged-lint.test.ts` (2 to 7 failures each; each fixture is flagged by exactly one finding so a neighbouring rule cannot mask it) |
| the real `privileged.ts`, mutated (a copy): `const { env } = Deno` then a computed name; `globalThis.Deno.env.get(k)`; `const pg = postgres; pg(url)`; `openPool("postgres://...")`; `openPool(dbUrlArg?)`; the driver fed a literal URL; `db["be" + "gin"]`; `db[k]`; `t.unsafe("SET LOCAL " + "ROLE postgres")`; `eval(...)` | the lint on the copy (a finding of the matching rule each time; the unmutated copy has none) |
| `me-export` / `me-push-token` dropped from a CI list; a new function directory listed nowhere | `ci-function-lists.test.ts` (2 / 2 / 2 / 3 failures) |

### `[unverified]`

The runbook additions in design section 15 (item 0 deploy order's isolate-recycling remark, 3a, 7): isolate counts and pooler pool sizes, `verify_jwt` defaults and the non-JWT secret keys against the bearer pattern, and whether the platform injects `SUPABASE_DB_URL`. Nothing was run against a real Supabase project, Supavisor or `pg_cron`; prettier was not run.

## Edge role PR #35 (2026-10-03): hardening the proof-bound link after the PR #31 gate, and the PR #34 lint finding (migration `0041_signin_proof_hardening.sql`)

The PR #31 gate passed 0039 with L1 (LOW), L2 (LOW/NIT) and N2 (NIT); the PR #34 gate left one LOW in the privileged-file lint (LOW-1). All four are addressed here. Migrations 0001-0040 are untouched
(`check-migrations-immutable.sh --base ed2defe`: 40 files byte-identical; `--self-test` OK). Base: `ed2defe` (identical in content to main `93e732d` after PR4c merged). Design, the options and the **changed trust argument**:
[`docs/security/edge-role-design.md`](edge-role-design.md) section 12.1.1. **Nothing here has been exercised against a real Supabase Auth**: the session row and its `session_id` claim are scripted.

### What 0041 contains

| Finding | What was built | Not built, and why |
|---|---|---|
| **L1 (a)** any unbound `edge_system` transaction (drain, queue, import, retention) could mint | The role `edge_signin_minter` (NOLOGIN NOINHERIT NOBYPASSRLS, a member of nothing); `edge_gateway` a member `INHERIT FALSE, SET TRUE`; `USAGE` on `private` and `EXECUTE` on `signin_record_email_proof` **moved** from `edge_system` (the 0039 five-argument function is dropped, a six-argument one is created); `openScopedTx` kind `"signin_mint"`; lint rule `privileged-mint-scope`; checks 2, 9, 10, 12 and the self-check/provisioning updated; the "no actor bound" precondition holds under the new role. | A second login for the minter (a credential boundary instead of a privilege boundary): it would need a second pool and secret; recorded as a design option, not a defect (design 12.1.1, "What was not built"). |
| **L1 (b)** bind the proof to the session `verifyOtp` created | Built. The mint takes `p_session_id` and refuses unless `auth.sessions` has that id **for the target**, created within 60 s; `private.signin_email_proof.session_id` under a UNIQUE index (one session, one proof); `EmailOtpResult` carries `sessionId` (the access token's `session_id` claim) and `closeSession()`; the handler signs out exactly that session after the mint, in a `finally`. `private_definer` gets `SELECT (id, user_id, created_at) ON auth.sessions` (asserted). | Columns are `[unverified — training knowledge]`: `auth.sessions.id / user_id / created_at`, that `verifyOtp` creates the row, that the token's `session_id` claim is its id, that the grant is legal on a hosted project. Built anyway because every failure is closed (every mint refuses, visible at once in the P4 spike), the columns are the three most basic of the table, and GoTrue's own `/logout` identifies the session by that claim. The P4 spike item and its order are in design 12.1.1. |
| **L2** normalisation | The mint takes the RAW address and the RAW subject and does `lower(btrim())` and `sha256` itself, with the redemption's expression; JavaScript hashes neither. The OTP failure counter's bucket is keyed on the **target account the database resolved** (`sha256("signin-otp-target:" \|\| owner uid)`), so no spelling buys fresh attempts. | The Apple claim is still trimmed and lower-cased once at parse time (`apple-id-token.ts`); every comparison after it is the database's (design 12.1.1, L2 fact 1). |
| **N2** stale proofs visible to any `private_definer` code | `pd_signin_proof_select` / `_delete` admit stale rows only inside the purge window `app.signin.proof_purge = 'on'` (check-7 form), opened and closed by `purge_signin_email_proofs` and the mint's own bounded cleanup. `definer_policy_allowlist` rows and `definer_policy_exprs.txt` regenerated. | |
| **PR #34 LOW-1** lint | `privileged-driver-import` (exactly one driver import, by the specifier `postgres`; any other import / re-export / `require(` naming `postgres` or `postgresjs`, a second value import of the specifier, `createRequire`, `node:module`); any member named `Deno` (`x.Deno`, `this.Deno`, `e.currentTarget.Deno`, a destructure key) under `privileged-global-access`; `.file(` and a destructured `file` under `privileged-unsafe-sql`; `privileged-mint-scope`. A dynamic `import(` of anything was already `privileged-global-access`. The CI function-list guard now also fails if any of the three deno steps has a step-level `if:` or `continue-on-error:` (the NIT). | |

**The grants, all of them:** `GRANT edge_signin_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE`; `GRANT USAGE ON SCHEMA private TO edge_signin_minter`; `GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) TO edge_signin_minter`
(the move; `edge_system` loses its EXECUTE with the dropped function); `GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer`. Nothing else is granted to anyone; `edge_policy_allowlist` and its fixture are unchanged (`private.definer_policy_allowlist` and `definer_policy_exprs.txt` change for the two N2 policies).

**Provisioning and the self-check.** `tools/db/provision-edge-login.sh` creates nothing and grants nothing; it now refuses to bless a login next to a misconfigured minter (LOGIN, INHERIT, a member of any role, `edge_gateway`'s grant with INHERIT / ADMIN or without SET, any such row) and only notes when 0041 is not yet applied;
`test-provision-edge-login.sh` proves the accept and five refusals (it re-grants by the original grantor so the cluster ends with exactly the row it started with, in both harness modes). `assertEdgeConnectionSafe` needed no list change (a deny-list of privileged roles; its membership-closure walk already refuses a BYPASSRLS role anywhere in the closure); a Deno cell proves the closure is exactly the four roles and
that the minter made BYPASSRLS is refused by both the gate and the `signin_mint` transaction's own assertion. `private.function_inventory.expected_edge_signin_minter` is a new column (true for one function).

### The trust argument, changed (full table in design 12.1.1)

An injected statement in a system lane that cannot change role **can no longer mint at all** (`42501`): that is (a), a privilege boundary. One that can also switch role (`SET ROLE` / `set_config('role', ...)`: `edge_gateway` holds `SET` on all three roles) **can reach the minter role**, exactly as it can already reach `edge_actor`
and `bind_actor(<any uid>)` (R6, unchanged); it still **cannot mint without the victim's live session id**, which no edge role can read: that is (b), a secret. The pgTAP cell `KNOWN LIMIT (R6)` pins the first half so the role is not read as more than it is. R6 itself is unchanged, and closing it is PR5.

### Tests

- **pgTAP**: `19_signin_proof_link.sql` 58 to **78** (the role by the catalog: attributes, no membership, `edge_gateway`'s one SET TRUE / INHERIT FALSE row, one executable function, no relation / sequence / CREATE / policy / `auth.sessions` privilege; the old function gone; the unique index; the N2 window: nothing visible or deletable with no window, only the exact value `on` opens it, only stale rows through it);
  `19_signin_proof_link_edge.sql` 78 to **127** (as the real `edge_gateway` login: `edge_system` cannot mint, bound or unbound or as a lane; `edge_actor`, a bound actor, a system delegate and the delegate-as-`edge_actor` cannot; the minter inside a bound / delegate transaction is refused; the minter can read and call nothing else and cannot `SET ROLE` to `service_role` / `authenticated` / `private_definer` / `postgres`;
  the `KNOWN LIMIT (R6)` cell; session refusals: unknown id, another account's fresh session, a 10-minute-old one, a future-dated one, a second mint on one session in the same and in a later transaction, a NULL session; and the L2 cells: spaces, case, TAB, NBSP, EM SPACE, U+0130 for an ASCII i, a target whose own address contains U+0130, plus tags, and the subject as exact bytes, each for the mint and the redeemer, asserted against the plain SQL comparison in whatever database they run);
  `10_function_inventory.sql` 53 to **70** (checks 2, 9, 10 and 12 for the role, with 11 must-fail cells). Whole matrix: 24 files, **2161 tests** (was 2075), PASS in both harness modes.
- **Deno** (`signin-methods.deno.test.ts` 40 tests, was 33; `edge-role.deno.test.ts` +1; whole suite **248**, was 240): a mint attempted from inside an `edge_system` transaction with a perfectly valid argument set is refused `42501` and the same arguments through the real minter work; `edge_system` cannot read `auth.sessions`; the `signin_mint` transaction runs as the minter and can do nothing else and refuses a bind;
  the session refusals through the real minter; verifyOtp's session is signed out after the mint on every handler path (success, a mint the database refuses, an address that changed hands) and its id is never logged; `sessionIdOfAccessToken` (base64url, padding, a non-uuid, a missing claim, garbage); the full flow's order is verifyOtp, mint, sign-out of exactly that session; the L2 end to end (nine spellings through the real mint and redeemer; four through the handler); the self-check and the minter.
- **Concurrency** `tools/db/test-signin-proof-concurrency.sh` (mints as the minter with a session): blocking case and 6 symmetric races, one winner each.
- **Unit** (`pnpm --filter @golfraven/rules exec vitest run ...`): **44 files / 842 tests** (835 before: +4 in `signin-methods-handler.test.ts` for the session binding, sign-out on every path, the fake minter's session rules and the per-target counter key; +3 CI guard cells); the lint's own **5 files / 401 tests** (382 before: +19 = 13 new must-fail fixtures, one cell each, the must-pass fixture extended with the minter shapes, and 6 edge-case tests).

### Mutation proofs (each applied to a world-readable `/tmp` copy, the relevant suites then run, every one CAUGHT; no mutated text is left in the tree)

| Mutation | Caught by |
|---|---|
| re-grant the mint EXECUTE to `edge_system` (a following migration, so 0041's own assertions are bypassed) | matrix 10 (the `edge_system EXECUTE mismatches` block raises), matrix 19 (1 cell), matrix 19 edge (2), `verify-function-inventory.mjs` (check 2), Deno `PR35 L1` |
| drop the no-actor-bound check from the minter | matrix 19 edge (3: the minter in a bound transaction, a delegate binding, the delegate as `edge_actor`) |
| give the minter an extra privilege: `SELECT` on `app.play` / on the proof table / on `auth.sessions`, or `EXECUTE` on the purge | matrix 10 (check 12 / the minter's EXECUTE block, 3-4 cells), matrix 19 (1-3), matrix 19 edge (1-2), `verify-function-inventory.mjs` (check 12 / check 2) |
| normalisation mismatch, in the database (the mint no longer lower-cases the address) | matrix 19 edge (7 cells, and the file aborts on the first accepted mint) |
| normalisation mismatch, in the Edge code (`input.email.trim().toLowerCase()` before the mint) | Deno `PR35 L2` (1 of 248) |
| drop the session check from the minter | matrix 19 edge (4: unknown id, another account's session, a stale one, a future one) |
| the `signin_mint` kind opens as `edge_system` | Deno (16 of 248: every mint, the L1 cells, the self-check cell) |
| the session is signed out BEFORE the mint / never signed out | Deno (5 / 2 of 248) |
| lint, on a copy of the real `privileged.ts`: a second driver import by the pinned URL; `createRequire(...)("postgres")`; `e.currentTarget.Deno` and `this.Deno` inside the real `addEventListener` listeners; `t.file(...)`; the minter role outside `openScopedTx`; the `signin_mint` kind in `withSigninSystem`; a computed kind; an alias of `openScopedTx` | each exits 1 naming `privileged-driver-import` / `privileged-global-access` / `privileged-unsafe-sql` / `privileged-mint-scope`; the real file is clean |
| CI guard, on a copy of `ci.yml`: a step-level `if:` and, separately, `continue-on-error:` on the `deno check` step | `ci-function-lists.test.ts` (1 cell each) |

### Not verified (`[unverified]`), in one place

- **GoTrue** (as 0039, plus): `auth.sessions.id / user_id / created_at`; that `verifyOtp` creates the row and commits it before returning; that the access token's `session_id` claim is that id; that the grant is legal for the migrating role on a hosted project; the 60 s windows against the database clock. Where any of it is untrue every mint refuses (`409 email_proof_refused`; no `session_id` logs `signin_otp_session_id_missing`): fail closed.
- Everything 0039 and the O12 section list as unverified is still so. The `edge` handler path was exercised against a scripted verifier and the real harness cluster, never against Supabase Auth.
- `pnpm -r typecheck`: 12 of 13 projects pass; `tools/catalog` fails with `Cannot find module 'esbuild'` in `test/neutrality.ts` in this sandbox (the file and its dependencies are untouched by this change; `@golfraven/catalog-tools...` was built first as the PR4a notes require).

### Verification

- **`tools/db/test.sh`, exit 0 in `HARNESS_MODE=superuser` AND `restricted`** (ports 5742 / 5743, private log dir): pgTAP `Files=24, Tests=2161, Result: PASS` in each; `tools/db/test-signin-proof-concurrency.sh` PASS; `test-provision-edge-login.sh` OK (the new accept + five refusals); the H2 `no migration_owner` checks (both approximations) pass with the new `auth.sessions` grant; the Deno integration suite **248 passed / 0 failed** in each;
  `verify-function-inventory.mjs: OK`; service-role lint clean.
- `deno check --frozen` and `deno cache --frozen` over the CI entry points on a fresh `DENO_DIR`: both exit 0; `supabase/tests/deno.lock` unchanged (no new import specifier). `check-migrations-immutable.sh --base ed2defe`: OK (40 files). `gitleaks dir . --config .gitleaks.toml`: no leaks.

## checkin-token: real attestation verification (2026-10-03), replacing the STUB

`checkin-token` (`POST /v1/checkin/token`) used to ignore any attestation token and grade every request from the client's own
`hardwareSupportsAttestation` claim, so it could never produce `attested`. It now verifies a presented App Attest assertion (iOS) or Play
Integrity token (Android) with the **same verifiers `rewards-activate` uses**, over a **check-in-specific binding**, and grades per §4.5 G3-08.
No migration: the token row already records `attestation_grade`, and the counter advance, the signal insert and the token insert all run as
`edge_actor` through statements `rewards-activate` already uses.

### Request (strict: unknown keys are refused with 400, at the top level and inside the block)

```
POST /v1/checkin/token
{ "challengeId": "<uuid>", "nonce": "<unpadded base64url, as the challenge returned it>", "hardwareSupportsAttestation": boolean,
  "attestation": OPTIONAL, one of
    { "platform": "ios",     "keyId": "<base64>", "assertion": "<base64 CBOR>" }
    { "platform": "android", "integrityToken": "<token>" } }
```

`deviceId` is **not** a field: the server reads the device from the challenge row (the client sent it to `POST /v1/checkin/challenge`) and binds
it. `challengeId` must now be a UUID (a non-UUID was an unhandled 500 before). With an attestation the nonce must be the **canonical** unpadded
base64url spelling (400 otherwise), because the iOS binding carries the nonce as text and the Android binding as bytes.

### The binding (what the attestation commits to); the mobile client must reproduce these exactly

Purpose string (domain separator, a different message from activation `reward_activation` and registration `attest_key_registration`):
`golfraven/checkin-token/v1`. All ids are the lowercase UUID strings; `userId` is the JWT `sub` verbatim; `deviceId` is the device the challenge
was issued to; `nonce` is the string `POST /v1/checkin/challenge` returned.

- **iOS.** `S` = canonical JSON (keys sorted, no whitespace, `JSON.stringify` escaping; `/` is not escaped):
  `{"challengeId":"<c>","deviceId":"<d>","nonce":"<nonce text>","platform":"ios","purpose":"golfraven/checkin-token/v1","userId":"<u>"}`.
  Pass `S` as the `challenge` of `generateAssertionAsync(keyId, S)` (the module hashes it with SHA-256: `clientDataHash = SHA-256(UTF-8(S))`).
- **Android.** `canonical_body` = `{"challengeId":"<c>","deviceId":"<d>","platform":"android","purpose":"golfraven/checkin-token/v1","userId":"<u>"}`
  (UTF-8). `requestHash = base64url_no_padding(SHA-256(canonical_body ‖ raw nonce bytes))` (the nonce decoded from its base64url text); pass it as
  the Play Integrity `requestHash`.
- **Recorded vectors** (computed independently with Python `hashlib`; `rewards-binding.test.ts`): challenge `cccccccc-cccc-4ccc-8ccc-cccccccccccc`,
  device `bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb`, user `uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu`, nonce bytes `01..20` hex = text
  `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA`: iOS `clientDataHash` = `3c695d6c71722843731e7a80e63d987d628181755c5925db5401f9d36b8077e5`;
  Android `requestHash` = `8CGJ1X3iXQCcqYH4U7fjJrnceadzDEz5avKmy_idkl0` (hex `f02189d5...925d`).

### Grading

| Case | Grade | Signal |
|---|---|---|
| valid attestation over the binding | `attested` | none |
| iOS: key registered to THIS user's device, signature valid, `rpIdHash` right, counter strictly greater, stored counter advanced atomically (`UPDATE ... WHERE attest_key_id = $key AND attest_counter < $new`) | `attested` | none |
| attestation presented but invalid (wrong purpose / nonce / challenge / device / user, replayed or non-increasing counter, lost advance race, replaced key, key of another account (**`rekey: true`**, with the plain "key id is not the registered one" case: see "Stale App Attest key recovery"), malformed, wrong Android `requestHash` / package / certificate / `deviceIntegrity` / freshness, Google's 400 "cannot decode") | `failed` | `fraud_signal(attestation_failed)` via `raiseAttestationFailedIfNone` (one open per account; detail = `{challengeId, deviceId, platform, reasons, source:"checkin-token"}`, no key material). A counter LOWER than the stored one carries `counter_out_of_order`, an EQUAL one `counter_not_monotonic` / `counter_replay` (see "Attestation follow-ups") |
| iOS attestation on a device with NO registered key | `unattestable` (`key_not_registered`), as activation. **The answer carries `rekey: true`** (below) | none |
| no attestation, and the claim says capable **or** the device row has shown it can attest (a registered key, a prior `attested` token, or an `attested` activation verdict, 0043) | `failed` | `attestation_failed` via the SAME `raiseAttestationFailedIfNone` (one open per account; since the follow-ups the no-attestation path no longer inserts one per request); detail `{challengeId, deviceId, platform:null, reasons:["no_attestation_token"] (+ `"device_has_attested_before"` when the evidence, not the claim, decided), source:"checkin-token"}`, the same vocabulary as activation |
| no attestation, claim says incapable, no such evidence | `unattestable` | none |

A failed attempt **spends its challenge** (the failure is returned as a graded token, never thrown), so there is no free second guess on one nonce.

**Vendor / transport errors never grade `failed`.** Play Integrity unreachable / 5xx / 429 / not JSON, a Google OAuth failure, our service-account credentials
rejected, or a deployment with no configuration for the presented platform: `503 attestation_unavailable` / `503 attestation_not_configured` — the same choice
`rewards-activate` makes (`activate-handler.ts#mapVendorError`). The transaction rolls back, so the challenge is **not** consumed, nothing is issued and no
signal is raised; the client retries (a prefetched challenge lasts 24 h; a live one 120 s, so a live session fetches a new one). Grading `unattestable` on an
outage was rejected: it would let an outage mint tokens that count as co-signals. App Attest assertion verification is local cryptography, so only the Android
path can hit a vendor. DeviceCheck is not used here.

### Idempotent redemption

A repeat redemption of an **already consumed** challenge — same account, same nonce (its hash equals the stored hash; the device is the challenge's own),
while the token it issued is **unexpired and not yet consumed by a fix** — returns that token: the **original jti, expiry and grade**, same 201, no new token.
Nothing is re-verified, re-graded, re-counted or re-signalled: a repeat iOS assertion with the same counter is not a counter failure, and a better attestation in
the repeat never upgrades a `failed` / `unattestable` first grade (a repeat answers even while the vendor is down or unconfigured). It works after the 120 s live
challenge has expired, for as long as the 15 minute token lives. A request that loses the atomic consume to an identical concurrent one answers the same way.
Everything else about a used challenge stays `422 challenge_used` (another nonce, an undecodable nonce, no token, an expired or consumed token); another account is 404.

### The no-attestation rule, and activation

`hardwareSupportsAttestation` is a self-report. A request without an attestation is `failed` whatever it claims when the server has evidence that THIS DEVICE ROW can
attest: iOS, a **registered** App Attest key (`deviceAttestState` returns a key only for a verified registration, 0034); either platform, a token previously issued on
the device graded `attested` (`Repo#checkinToken.hasAttestedOnDevice`), or an activation verdict of `attested` recorded on it (`Repo#rewards.hasAttestedVerdictOnDevice`,
sticky, migration `0043`; before the follow-ups the Android half counted check-in tokens only). **Narrowed for honest clients, not closed:** the evidence is bound to a
device ID that the client chooses (up to `MAX_DEVICES_PER_USER` = 20 per account), so an attacker claims "incapable" on a device id that has never attested and is still
believed (see "Attestation follow-ups", LOW-2, for what that costs and the account-level variant that was NOT implemented). **Cost to an honest client:** once a
device has shown it can attest, a check-in that omits the attestation is `failed` and raises the signal, which holds the account's activations (§7.5 row 2).
The rule is ONE function, `rewards/attestation-evidence.ts#gradeNoAttestation`, called by both `checkin-token` and `rewards-activate` (`kind:"none"`; reason
`device_has_attested_before`); each handler used to carry a verbatim copy. **Still open:** a device that never registered a key and never attested can still claim
`false` and be believed, as before.

### Architecture

- The earning side (`_shared/checkin`, `checkin-token`) may import only the verification-only rewards modules (`binding`, `string-binding`, `app-attest`,
  `play-integrity`, `play-integrity-client`, `vendor-http`, `verification-ports`, `types`); none names a persistent-bit call. `production-ports.ts` (which holds the
  DeviceCheck adapter) re-exports `buildAndroidPort` from the new `rewards/verification-ports.ts`, so both entrypoints grade a Play Integrity token with one
  implementation. `rewards-isolation.test.ts` pins the allow-list, the absence of bit-reading names in it, and that only `checkin-token/index.ts` wires the ports.
- Configuration is read only in `privileged.ts#loadCheckinAttestationConfig` (iOS: `GR_APPLE_TEAM_ID` + `GR_APPLE_BUNDLE_ID`; Android: the four `GR_PLAY_*`
  values; no DeviceCheck credential). An unset platform answers 503 to a request carrying that platform's attestation. See the edge-role-design environment table.
- The user id in the binding comes from the authenticated actor and is never used to address a row.

### Not verified, and a finding

- `[unverified]` everything the verifiers assume about Apple's assertion format and Google's verdict JSON (unchanged from `rewards-activate`); no device, Apple or Google
  route exists here. The tests prove self-consistency, not conformance.
- **Finding, since fixed (migration `0042`, next section):** `checkin-challenge` and `evidence` created unseen devices with `ensureOwn(deviceId, null)`, which stored
  `platform = 'ios'`, so an Android device first seen there was refused its Android activation (422 `platform_mismatch`).

### Related fixes in the same change

- `evidence-batch` per-item rate-limit errors carry `error.details.retryAfterSeconds` (the window of the bucket that refused), like the single endpoint's 429
  (`_shared/evidence/batch-item-result.ts`).
- The unit-test fake `consumeForFix` now clamps to the **challenge's** window like the real statement (it clamped to the token's): a fix captured hours before the redemption
  of a prefetched challenge is accepted, and the fake no longer passes a test for the wrong reason (`evidence-handler.test.ts` was updated to say so).

### Tests and verification (checkin-token attestation)

- **Unit** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): **47 files / 926 tests** (was 44 / 842): `checkin-token-attestation.test.ts` (51: shape, iOS with the real
  assertion verifier, Android with the real `buildAndroidPort` over a scripted `fetch`, vendor outages, configuration), `checkin-token-idempotency.test.ts` (18: repeat redemption, the no-attestation rule, the
  fake `consumeForFix` window), `evidence-batch-item-result.test.ts` (3), the binding vectors in `rewards-binding.test.ts`, the boundary in `rewards-isolation.test.ts`, and the activation capability-dodge cells.
- **Deno integration** (`checkin-attest.deno.test.ts`, 13 cells, real `withOwnership` / `Repo`): the atomic counter advance, the signal and its dedupe, purpose separation, another account's key, the lost advance race,
  the vendor outage that ROLLS BACK (the challenge is not consumed and redeems on retry), idempotent repeats, the no-attestation rule, and `consumeForFix` accepting a fix captured hours before a prefetched challenge's
  redemption. Whole suite **262** (was 248), both harness modes, with pgTAP `Files=24, Tests=2161` unchanged (no migration).
- `deno check --frozen` and `deno cache --frozen` over every entrypoint: exit 0, `deno.lock` unchanged (no new specifier). `service-role-lint` clean, `verify-function-inventory` OK, `check-migrations-immutable.sh --base origin/main` OK,
  `gitleaks dir .` clean. `pnpm -r typecheck` / `test`: every project passes except `tools/catalog` (`Cannot find module 'esbuild'`) and `apps/mobile` (its dependencies, e.g. `zod`, `expo-file-system`, are not installed in this
  sandbox); both fail identically without this change and neither is touched by it.

**Mutation proofs** (each applied to a `/tmp` copy, the unit suite run, success = a test that passes unmutated now fails; **36 of 36 caught**, copies deleted, no mutated text left in the tree): the purpose constant replaced by the
activation purpose; the purpose dropped from the iOS string / from the Android body; `userId` dropped from iOS; the nonce dropped from iOS and from Android; `deviceId` dropped from Android; the counter advance skipped; the verifier's
`<=` loosened to `<`; the key-id owner check removed; the iOS nonce bound as `""`; the account bound as `""`; each Android check removed alone (`requestHash`, package, certificate digest, `deviceIntegrity`); a vendor error mapped to
`failed` in the handler and, separately, in the port; the signal not raised; unknown keys accepted (attestation block and top level); idempotency: nonce check dropped, token expiry ignored, consumed token ignored, replay re-graded
upward, the used-challenge replay removed, the lost-race replay removed; the dodge: the claim always believed, the Android half dropped, the iOS half dropped, the same in activation, the claim ignored; `retryAfterSeconds`
dropped from the batch item; the fake's `consumeForFix` reverted to the token window; `production-ports` imported by the earning side; the not-configured pre-check removed.

## Device platform: unknown until the first platform-bearing use (2026-10-03, migration `0042_device_platform_unknown.sql`)

**The bug.** `app.device.platform` was `NOT NULL`, and `Repo#device.ensureOwn(id, null)` (called by `checkin-challenge` and `evidence`, whose requests carry no platform) stored
`platform ?? 'ios'`. An Android device first seen there was labelled iOS, and `rewards-activate` (which refuses a request whose platform differs from the row's, 422
`platform_mismatch`) then refused its Android activation.

**Call sites** (`ensureOwn`): `checkin-challenge` (null), `evidence` (null), `me-push-token` (the optional `platform` of its body), `rewards-activate` (the request's `platform`).

**The fix (option b).** `platform` is now nullable: NULL = unknown. It is set by the **first platform-bearing use**, and the first wins:

| Use | Sets the platform |
|---|---|
| `rewards-activate` | the request's `platform`, after every earlier refusal; a mismatch with a set platform stays 422 `platform_mismatch` |
| `devices-attest-key` | `ios`, **only after the attestation verified**; an Android device is still refused (422); a failed verification labels nothing |
| `checkin-token` | the attestation block's platform, **only when it graded `attested`**; a failed or absent block labels nothing, and nothing is refused here |
| `me-push-token` | its `platform`, when it names one |

The write is `private.claim_device_platform_for_actor(device, platform)` (SECURITY DEFINER, EXECUTE for `edge_actor` only, `kind='user'` bindings only): `UPDATE ... WHERE platform IS NULL`
(race-safe: the second writer re-evaluates the predicate), then it returns the platform on record, or **NULL** (it does not raise: an error would abort the request's transaction) for a device
that is not the actor's own. `edge_actor` gained **no** privilege on the column (no UPDATE; it keeps `INSERT (id, user_id, platform)`); `private_definer` gained `UPDATE (platform)`, row-scoped by
the existing `pd_edge_act_device_update` policy. No policy was added, `FORCE ROW LEVEL SECURITY` is untouched, the `ios`/`android` CHECK remains. Deploy order: apply `0042` before the Edge code that
inserts a NULL platform.

**Option (a) rejected:** adding `platform` to the challenge and evidence requests. The evidence body is strict and its input hash is the idempotency key of a replay, so a new field would turn a client's own
replays into 409 `evidence_conflict`; and an old client would keep the bug. **No wire change is needed from the mobile client.** (Sending `platform` to `me-push-token`, which already accepts it, now also labels the device.)

**Rows already mislabelled: no data migration.** A row labelled `ios` by the bug cannot be told from a real iOS device that has not registered an App Attest key yet (both: `ios`, no key), so
the only safe relabelling is to *unknown*, never to `android`. That would be harmless (the first platform-bearing use re-claims it) but this repository's databases are pre-launch, and an UPDATE inside
a migration is filtered by FORCE RLS for the table owner. Where such rows exist an operator can run, as `service_role`, `UPDATE app.device SET platform = NULL WHERE platform = 'ios' AND attest_key_id IS NULL;`
(a row with a registered key is certainly iOS and is excluded).

**Not closed at the database level:** `app.register_attest_key` (0034, unchanged) tests `platform <> 'ios'`, which is NULL (not true) for an unknown platform. The Edge handler claims `ios` first, so a key
is only ever registered on a device labelled iOS; a direct service_role call is trusted.

**Tests.** pgTAP `21_device_platform_claim.sql` (39 cells, as a real `edge_gateway` login: first wins, set platforms never change, the shape refusals, no direct UPDATE, another account's device, a system delegate
refused, a stale binding, and the posture: no edge_actor grant or policy added, FORCE RLS kept); whole matrix 25 files / **2200** tests (was 2161). Deno `device-platform.deno.test.ts` (6 cells; whole suite **268**, was 262):
an Android device first seen at `checkin-challenge` and then activated on Android is NOT refused, a device first seen as iOS and then activated as Android still is. Unit `device-platform.test.ts` (16): the same through
the handlers, plus attest-key, push-token and check-in token, and a source guard that `ensureOwn` never defaults to `'ios'`. **Mutants (11, all caught, copies deleted):** unit suite: activation's claim replaced by the
request's platform, the mismatch refusal removed, attest-key's claim removed, attest-key accepting Android, check-in token's claim removed, a failed block labelling, push-token's claim removed, `ensureOwn` defaulting
to `'ios'`; real database: the `platform IS NULL` guard removed (last wins), `UPDATE (platform)` also granted to `edge_actor` (the migration's own assertion aborts), the `kind = 'user'` check removed.

## Attestation follow-ups (2026-10-03): the PR #40 security-gate LOWs and NITs (migrations `0043_device_first_attested.sql` and `0044_export_first_attested.sql`)

Server-side only. Nothing on the wire changed: no request shape, no response body, no recorded mobile fixture (the edge-contract recorder was run in verify mode and is unchanged).

### LOW-1: out-of-order assertions of one key get their own reason

**The case.** The App Attest counter is shared by `checkin-token` and `rewards-activate` and is strictly monotonic. A client with two assertions of one key in flight can have them commit out of order
(counter 7 commits before 6). The lower one is refused, which is correct, and it grades `failed` and raises `fraud_signal(attestation_failed)`, which holds the account's activations (§7.5 row 2).
Before this change it carried `counter_not_monotonic` or `counter_replay`, the same words as a replay, so a reviewer could not tell an honest race from an attack.

**What changed: the reason only.** Strict monotonicity, the grade (`failed`), the signal kind, the held outcome and the counter (never lowered) are all unchanged. The reason is stored where the others are, in
`fraud_signal.detail.reasons`; no schema change. Three diagnostics for "the counter did not advance", all stored on the same signal:

| Reason | Where it is decided | Meaning |
|---|---|---|
| `counter_out_of_order` (new) | the verifier (`app-attest.ts`): presented counter **below** the stored one; and the lost-advance re-read (`rewards/attestation-evidence.ts#lostAdvanceReason`): the stored counter is now **above** the presented one | a later assertion of this key committed first: an honest client with more than one assertion in flight |
| `counter_not_monotonic` | the verifier: presented counter **equal** to the stored one | the same counter presented twice (a replay), seen before the advance |
| `counter_replay` | the lost-advance re-read: the stored counter is now **equal** to the presented one (or there is nothing to compare) | two identical assertions racing, seen at the advance |
| `key_replaced` (unchanged) | the lost-advance re-read: the key on the device is no longer the one verified | a registration replaced the key between the read and the write |

(The owner's note read "equal stays `counter_replay`". The equal case already had two names depending on where it was seen, `counter_not_monotonic` at the verifier and `counter_replay` at the advance; both are kept as they were
so no stored or documented reason changes meaning. Only "lower" is new.) The re-read behind `lostAdvanceReason` was already there for `key_replaced`; it runs only on this failure path, on the same transaction, and decides nothing. Both
handlers call the one function (each used to carry a copy).

**An out-of-order failure still holds the account's activations until a reviewer clears the signal.** That is deliberate (strictness stays), and it is why the client requirement below exists.

### LOW-1(b): MOBILE CLIENT REQUIREMENT (implemented by mobile P4.2b-2): one assertion in flight per key, across BOTH endpoints

The counter lives on the device row and both `POST /v1/checkin/token` (an iOS check-in attestation) and `POST /v1/rewards/{id}/activate` (an iOS activation assertion) advance it. Therefore:

1. **Serialise.** Per App Attest key, at most ONE assertion may be between "generate" (`generateAssertionAsync`) and "the server answered (or the request definitively failed)" at any time, **across both endpoints and across every code path** (foreground check-in, a prefetched-challenge redemption, an activation, a retry). One in-process queue/mutex keyed by key id is the intended shape.
2. **Generate late.** Generate the assertion immediately before sending the request that carries it, not when the challenge is prefetched or queued, and never generate two ahead and send them in parallel. An assertion whose request was never sent still consumed a counter value on the device: that is harmless (a gap is fine, the server only requires strictly greater) as long as the next one is generated after it.
3. **Do not retry an assertion in parallel; retry sequentially with a fresh one.** After a timeout or a lost response, wait for the first request to settle before generating the next assertion (an idempotent redemption of the same challenge returns the original token without re-verifying, so a repeat of the SAME check-in request is safe; a NEW assertion must come after).
4. **Order matters, gaps do not.** The server accepts any strictly increasing sequence per key. It refuses an assertion whose counter is not above the stored one, whatever the reason. A client that ever sends counter N after N+k has committed will be graded `failed` and will open the signal.
5. **A key replacement resets the counter** (a new key starts from 0); the old key's in-flight assertions are then `key_replaced` / `key_id_mismatch`. Do not register a new key while an assertion for the old one is in flight.

This is a client contract only; nothing server-side serialises the endpoints (a lock held across both would turn a client mistake into a latency problem for every other request of the account).

### LOW-2: the capability claim is NARROWED for honest clients, not closed

**Wording fixed** (code comments `checkin/token-handler.ts` header, `rewards/request-shape.ts`, the new `rewards/attestation-evidence.ts` header, and this document's "no-attestation rule" section, which used to say the dodge was closed). The evidence of capability is bound to a **device id the client chooses**
(up to `MAX_DEVICES_PER_USER` = 20 per account; a new id is a new device row). So a real device that has attested cannot later claim it cannot, but an attacker can claim "incapable" on a device id that has never attested and is believed.
What that buys the attacker is `unattestable` instead of `failed`: both are held in activation (§7.5 rows 2/3) and neither is a co-signal at check-in, so it avoids a *signal*, not a reward.

**The account-level rule, evaluated: NOT implemented. Open owner decision.** Candidate: "if any device on the account has ever attested, a no-attestation request on any device of that account grades `failed`."

| Variant | Effect | Verdict |
|---|---|---|
| A. account-level `failed` | closes the fresh-device-id claim; but an honest account with a second, genuinely incapable device (an old iPad below the App Attest OS floor, an Android without Play services or not Play-certified, a work phone, a device with attestation temporarily unsupported) would grade `failed`, open `attestation_failed`, and **hold every activation on the account**, a false fraud signal on a legitimate multi-device user, repeatedly (the signal re-opens after each clear) | **rejected** |
| B. account-level `unattestable` (never `failed`) | the owner's "safe variant" | **no behaviour change**: a no-attestation request that claims "incapable" on a device with no evidence already grades `unattestable`, so there is nothing for B to add |
| C. reviewer context only: when the account has an attested device and a no-attestation request arrives from another, record that on the held reward's hold detail / the signal | information for a human, no grade or hold change; costs one extra query on every no-attestation request, and needs a reviewer surface to read it | not implemented: it is a product decision about what reviewers see, and the dashboards that would show it are not in this repository |

**Recommendation: keep the per-device rule as it is (accept the residual), and do not implement A.** The residual is bounded: the attacker gains no reward (the request is held either way), needs only ONE device slot in total (a device id that has never attested can be reused for the dodge indefinitely, so the 20-device cap is no cost per attempt), and is already rate-limited (`checkin-token` 60/h per user; activation 10/h per user and 20/day per device). If the owner wants the signal, do C, not A. The stronger lever is on the client: register an App Attest key on **every capable iOS device early** (a registered key is permanent, unforgeable evidence on that row), and the dodge then requires a device id the account has never used.
**Decision needed from the owner:** (1) accept the residual as is (recommended), (2) ask for C, (3) ask for A and accept the false-positive cost for multi-device honest users.

### NIT-2: the no-attestation `failed` path is deduplicated

`checkin-token`'s no-attestation `failed` path inserted a `fraud_signal` on every request (`Repo#fraudSignal.insert`), so a client repeating it opened a signal per request. It now calls
`Repo#rewards.raiseAttestationFailedIfNone`, exactly as the presented-attestation path does (one OPEN signal per account, serialised by an advisory lock; clearing it lets the next failure open a new one). The detail is the activation vocabulary:
`{challengeId, deviceId, platform: null, reasons: ["no_attestation_token"] (+ "device_has_attested_before" when the evidence decided), source: "checkin-token"}` (it was `{challengeId, reason}` with two different `reason` words).
**The activation side already had the pattern** (`activate-handler.ts` step 7 raises through `raiseAttestationFailedIfNone` for every `failed` grade, `kind:"none"` included), so nothing changed there beyond the shared rule below.

### NIT-3: an Android ACTIVATION counts as evidence of capability (migration `0043`), and the rule is one function

Android had no device-level evidence except a check-in token graded `attested`, so an Android device that attested only at activation could still claim "I cannot attest". An activation records its verdict as `app.device.integrity_last = {grade, at}`, but that column is the **last** verdict: a later `failed` / `unattestable` verdict overwrites it
and would erase the evidence. So the evidence had to be sticky, which needs a schema change:

- `app.device.first_attested_at timestamptz` (NULL = never). **Stamped once by a `BEFORE INSERT OR UPDATE OF integrity_last, first_attested_at` trigger** (`app.device_first_attested_stamp`) when an `attested` verdict is written to `integrity_last` (on INSERT the value the statement assigned is discarded and the stamp is derived from the inserted verdict, so a `service_role` INSERT cannot plant a stamp that the UPDATE arm would then make permanent: the PR #41 gate's `'2001-01-01'` case); **never cleared or moved** (whatever an UPDATE assigns to it, the trigger restores the old value, by content and not by role).
- **No grant added or widened.** `edge_actor` holds no UPDATE and no INSERT on the column (only the trigger writes it; Postgres checks column privileges on the columns an UPDATE names, not on columns a BEFORE trigger changes); it reads it through its existing table-level SELECT and the existing own-row policy. No policy added, `FORCE ROW LEVEL SECURITY` untouched (asserted in the migration and in pgTAP). The trigger function is `SECURITY INVOKER`, empty `search_path`, EXECUTEd by no role, with its `private.function_inventory` row.
- **Edge read** (`Repo#rewards.hasAttestedVerdictOnDevice`): `first_attested_at IS NOT NULL OR integrity_last ->> 'grade' = 'attested'`, own device only. The second arm means a row written before `0043` (no stamp, no backfill: an UPDATE inside a migration is filtered by FORCE RLS for the owner, and the databases are pre-launch) still counts until its next verdict.
- **Exported** by `GET /v1/me/export` since migration `0044_export_first_attested.sql` (privacy default: include). It is a timestamp about the account's own device, the same kind of fact as `integrity_last`, `first_seen` and `last_seen`, which the export already carries, and the no-attestation rule acts on it. `0044` rebuilds `private.export_my_data` from `0028`'s final body with exactly one change: `first_attested_at` is added to the device block's explicit column list, after `integrity_last`. A timestamptz serialises like `first_seen` (an ISO-8601 string, or JSON `null` for a device that never attested; the key is always present). `0043` itself deliberately left it out; `0044` supersedes that.
- **Deploy order:** apply `0043` before the Edge code (an older schema answers 42703 to the read); `0044` follows it.

**One shared rule.** `rewards/attestation-evidence.ts` now holds `deviceHasShownAttestation` (registered key, `attested` check-in token, `attested` activation verdict), `gradeNoAttestation`, `noAttestationReasons` and `lostAdvanceReason`; `checkin/token-handler.ts` and `rewards/activate-handler.ts` call them (each carried a verbatim copy before). It is on the earning side's verification-only allow-list (it reads no persistent bit).

### NIT-4: the isolation test is now transitive

`rewards-isolation.test.ts` checked the **direct** imports of earning-side files only, so an allow-listed verification-only module that later imported `devicecheck-client.ts` would have reached the persistent-bit adapter with every assertion green.
`supabase/tests/unit/import-closure.ts` computes the **runtime import closure** (type-only imports ignored; comments, strings, templates with `${}` nesting and **regular-expression literals** tokenised, so none can hide an import, which a `/^\/*/` regex did to the first version of the scanner, a hidden `_shared/http.ts` import the PR #41 gate reproduced; string-named re-exports, non-ASCII identifiers and `new URL("./x", import.meta.url)` are edges; `import { type A }` conservatively counted, dynamic `import()` with a non-literal argument and unresolvable relative imports reported, never skipped) from `checkin-token/index.ts` and every earning-side entrypoint and file.
The test asserts that `devicecheck-client.ts`, `production-ports.ts`, `activate-handler.ts` and `rewards-activate/index.ts` are **unreachable** (the chain is printed if one is), that **no file in the closure names a persistent-bit call** (`rewards/types.ts`, which types the iOS port's methods, is the one exception), and that every `_shared/rewards/` file in the closure is verification-only or the one pure constant `privileged.ts` embeds
(`apple-app-attest-root.ts`). The walker has its own tests on synthetic graphs (`import-closure.test.ts`). **Why a tokenizer and not `deno info --json`:** `deno` is installed in the CI job that runs the unit suite, but the unit suite also runs wherever a developer has no Deno and no network, and `deno info` must fetch the remote modules (esm.sh, deno.land) to resolve the graph; a unit test that fails offline, or that needs a second toolchain, was not added. The tokenizer decides regex-versus-division by the usual previous-token heuristic; its one known limit is a regex literal right after `)` (`if (x) /re/.test(y)`), read as a division: if such a regex's body also contains `/*` or `//` it can still hide the text after it. Not covered; the walker's other safeguard is that every earning-side file is scanned by the by-name text checks too. **Proven by mutation** (below): an import added to an allow-listed module's own dependency, which the old direct-import checks cannot see, fails the new test.
Finding while writing it: `checkin-token/index.ts` reaches `privileged.ts`, which holds only `import type` of `production-ports.ts` (erased), so the earning side's closure is clean.

### Google's 403 on `decodeIntegrityToken` (the gate's unverified note): handled without changing grading `[unverified]`

`play-integrity-client.ts` mapped a 403 on the decode call to `VendorNotConfiguredError` ("Google rejected our credentials"), which is a 503 and a `console.error` line. **If Google answers 403 rather than 400 for a token minted for another app or project `[unverified: not checked here, no network]`,** any signed-in account can trigger that: a 503 for itself, a credentials-sounding error line in our log, and (the cache was dropped on every 401/403) one OAuth exchange per request.
Changes, all minimal, grading untouched:

- a decode 403 is now `VendorForbiddenError`, **a subclass of `VendorNotConfiguredError`**: the same 503 `attestation_not_configured`, the same non-grading, nothing consumed. Its message names both readings and does not say "credentials". A 403 on the OAuth exchange itself is still "our credentials". A 401 on the decode is unchanged.
- the handlers log it at **warn** level through `rewards/vendor-log.ts`, **at most one line per (endpoint, kind) per minute** per isolate, with the count suppressed; an attacker cannot flood the log or raise a false credentials alarm.
- the cached OAuth token is no longer discarded on a 403 (a fresh token would be refused the same way); it is still discarded on a 401.

**What is not known:** which status Google really answers for a foreign-app token (400 would be graded `failed`, as for an undecodable token; 403 is the 503 above), and whether a 403 can also mean our service account lost access to the app. The code treats both readings as possible and does not guess. If 403 is confirmed for foreign tokens, grading it `failed` would be a deliberate follow-up (an attacker could then open signals for themselves only: the signal is per account).

### Tests and verification (attestation follow-ups; final tree, nothing from before the last edit is counted)

- **Unit** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): **51 files / 1007 tests** (was 48 / 942). New files: `attestation-evidence.test.ts` (the shared rules' tables), `import-closure.test.ts` (the walker on synthetic graphs),
  `vendor-log.test.ts` (the rate-limited line and both handlers' 503); changed: `app-attest`, `checkin-token-attestation`, `checkin-token-idempotency`, `activate-handler`, `vendor-adapters`, `rewards-isolation` (now with the transitive closure), the fakes.
- **pgTAP** (`tools/db/test.sh`, both `HARNESS_MODE`s): **Files=27, Tests=2264, PASS** in both (was 25 / 2200). New: `22_device_first_attested.sql` (40: schema, stamping, stickiness, only a verdict can set it, posture, export) and `22_device_first_attested_edge.sql` (23: the real `recordDeviceVerdict` / `hasAttestedVerdictOnDevice` statements as an `edge_actor` login, no direct path, another account's device invisible). `0044` added 4 cells: 3 in `22_device_first_attested.sql` (the export carries the stamp, JSON `null` for a never-attested device, another account's export has none) and 1 in `14_me_export.sql` that pins the device block's exact column set.
- **Deno integration** (same script, both modes): **276 passed, 0 failed** (was 268; `me-handlers.deno.test.ts` +1 for the exported column): `checkin-attest.deno.test.ts` +4 (out-of-order on the real database, the equal-counter race, the deduplicated no-attestation signal, the Android activation evidence with a later `failed` verdict) and `rewards-activate.deno.test.ts` +3 (equal race, out-of-order, the Android dodge through activation); the unequal-race cells changed from `counter_replay` to `counter_out_of_order`.
- `verify-function-inventory` OK and `service-role-lint` clean (inside both `test.sh` runs and standalone); `tools/db/check-migrations-immutable.sh --base origin/main` OK (42 existing migrations byte-identical; `0043` is new); `deno check --frozen` and `deno cache --frozen` over every entrypoint exit 0 with `supabase/tests/deno.lock` unchanged;
  `gitleaks dir .` no leaks; `GOLFRAVEN_DEMO=1 pnpm -r test` exit 0 for every project (including `apps/mobile` 1191 tests and `tools/catalog`, which could not run in the previous round's sandbox).
- **The mobile edge-contract recorder, verify mode, passes with NO change to any recorded fixture** (no server answer on the wire changed: the new reasons live only in `fraud_signal.detail`).

**Mutation proofs** (each applied to a world-readable `/tmp` copy, the suite run, success = a test that passes unmutated now fails; **24 of 24 caught**, copies deleted, a search of the repository for the mutation marker prints nothing):
1a (7): the verifier's out-of-order reason collapsed into the replay reason; the verifier's equal-counter refusal removed (strictness loosened); the lost-advance reason `>` loosened to `>=`; `counter_out_of_order` never reported; `key_replaced` never reported; the activation handler and the check-in handler each bypassing the shared reason function with a constant.
3 (5): the no-attestation path inserting a signal per request again (the dedupe removed); the activation-verdict arm of the evidence dropped; the check-in-token arm dropped; the evidence ignored (claim always believed); the proven reason not told apart; plus, against a real database, **the trigger made non-sticky (killed by pgTAP, 8 cells)** and **`hasAttestedVerdictOnDevice` reading `integrity_last` only (killed by the two Android Deno cells)**.
4 (5): the walker not recursing; `import type` followed as a runtime import; comments not stripped; and the two **transitive** proofs: an `import "./devicecheck-client.ts"` added to the allow-listed `vendor-http.ts` (reachability, and the by-name check, fail with the chain printed; the old direct-import checks cannot see this hop), and a persistent-bit name added to `signin/bytes.ts`, a file reached only through `privileged.ts` and on no old list (only the new closure test fails).
5 (5): the decode 403 mapped back to the credentials error; the cached token discarded on 403 again; the logger's rate limit removed; each handler's 403 branch removed.
Control: a **type-only** `import type {} from "./devicecheck-client.ts"` in `vendor-http.ts` does **not** make the adapter reachable (the reachability test still passes); only the two by-name text checks, which also reject the adapter's NAME in a comment-free line, object to it.

**`0044` mutation proofs** (world-readable `/tmp` copies of the migration, `tools/db/test.sh`, copies deleted, no mutated text left in the tree; **2 of 2 caught, by pgTAP**): `first_attested_at` dropped from the export's device block (killed by the pinned column set in `14_me_export.sql` and two cells in `22_device_first_attested.sql`), and `first_attested_at` read from the wrong column (`first_seen AS first_attested_at`; killed by the never-attested-device-exports-JSON-null cell). The Deno cell covers the same path through the real handler. The mobile edge-contract recorder (whose `me-export` answer comes from the unit fake, which does not model SQL columns) is unchanged in verify mode and no fixture changed.

### PR #41 gate follow-ups (third commit; `0043` and `0044` were not on `main` yet, so `0043` was edited rather than superseded)

- **NIT-1, INSERT could set the stamp (`0043`).** The trigger was `BEFORE UPDATE` only, so a `service_role` INSERT could write any `first_attested_at` (the gate wrote `'2001-01-01'`) and the UPDATE arm then made it permanent. It is now `BEFORE INSERT OR UPDATE OF integrity_last, first_attested_at`, branching on `TG_OP`: on INSERT the assigned value is discarded and the stamp is derived from the inserted `integrity_last` (`now()` if `attested`, NULL otherwise; `OLD` is not read); the UPDATE arm is unchanged. The migration header and the function-inventory note say so. pgTAP: +6 cells in `22_device_first_attested.sql` (a bogus stamp with no verdict gives NULL and is not made permanent by a later verdict; an `attested` INSERT is stamped `now()`, not the assigned value; `unattestable` / `failed` / NULL verdicts give NULL; the trigger fires on INSERT and UPDATE). The "row written before `0043`" cells (`22_*` and `22_*_edge`) can no longer be produced through the trigger, so they switch it off for that one INSERT (as the table owner) and on again.
- **NIT-2.** The `0043` header no longer says the column is not exported (`0044` exports it) and its "nothing but a verdict write can set it" claim now reads "by any role, on INSERT or UPDATE".
- **NIT-3.** The residual cost of the capability claim is **one** device slot in total (a device id that never attests can be reused for the dodge indefinitely), not one per attempt.
- **LOW-1, the walker missed imports behind regex literals.** A regex such as `/^\/*/` was read as the start of a block comment, hiding everything up to the next `*` + `/`, a real import included (the gate hid one in `_shared/http.ts` and the tests still passed). `import-closure.ts` now tokenises strings, templates (with `${}` nesting) and regex literals (the previous-token heuristic) before stripping comments, and also follows string-named re-exports, non-ASCII identifiers and `new URL("./x", import.meta.url)`. Fixtures: `/^\/*/` then an import, `/[//]/` and `/[///]/` then an import, an escaped slash in a regex, a string with `/*` and with an escaped quote, a template with `//` including a nested `${ }` template, and the gate's `http.ts` reproduction end to end.
- **Mutation proofs:** INSERT arm removed from the trigger, INSERT arm keeping the assigned value, INSERT arm always stamping (all three caught by pgTAP, 3 of 3); the gate's `_shared/http.ts` reproduction applied to a copy (fails `rewards-isolation.test.ts`, with the chain printed), regex detection disabled, the character class ignored, template nesting not tracked, the unicode flag dropped, the `new URL` edge not recorded, string escapes ignored (all caught, 7 of 7).

## Stale App Attest key recovery: the `rekey` hint on `checkin-token` (2026-10-03)

**The problem.** `checkin-token` answered every refused iOS assertion with the same body, `{jti, expiresAt, attestationGrade: "failed"}`; the reason (`key_id_mismatch` and the rest) was written only to `fraud_signal.detail`. So the
mobile client could not tell "my local App Attest key is not the one the server has on record" from a replay or a wrong binding. If the two ever diverge (a database restore, an admin key reset, a lost registration write) an honest device was
graded `failed`, with a signal, on every check-in, forever, and nothing on the wire told it that registering a fresh key would end that. (The client-side cause, lock abandonment, was fixed in PR #42; this is the server half.)

**The change (server only, no migration, no grant, no new statement).** `IssuedToken` (`checkin/token-handler.ts`) gains one OPTIONAL member, `rekey?: true`. It is present, and always `true`, **only** when an iOS assertion was refused for a
KEY-IDENTITY reason, which is exactly two of the verifier's reasons (`attestation-evidence.ts#isKeyIdentityReason`, a two-element list pinned against the real verifier's output by a unit test):

| Verifier reason | Meaning | Grade (unchanged) | `rekey` |
|---|---|---|---|
| `key_id_mismatch` | the key id the client named is not the key registered for THIS user's device (another key of its own, a key of another account, a retired key) | `failed` | **`true`** |
| `key_not_registered` | an assertion was presented and the device has no registered key at all | `unattestable` | **`true`** |
| `counter_not_monotonic` / `counter_out_of_order` / `counter_replay` / `key_replaced` (a lost atomic advance) | about THIS assertion's counter or a replacement that raced it | `failed` | absent |
| `bad_signature_or_request_hash` (wrong purpose / nonce / challenge / device / user binding, or a signature by another key under the registered key id), `rp_id_mismatch`, `malformed_assertion`, `malformed_signature`, `bad_public_key` | about THIS assertion's content | `failed` | absent |
| a valid assertion | | `attested` | absent |
| no attestation at all (`failed` or `unattestable`), any Android answer | | unchanged | absent |

Wire examples: `{"data":{"jti":"...","expiresAt":"...","attestationGrade":"failed","rekey":true}}` and `{"data":{"jti":"...","expiresAt":"...","attestationGrade":"unattestable","rekey":true}}`; every other answer is byte-for-byte what it was (the
member is omitted, never `false`). The grade, the spent challenge (a failed attempt still spends it: there is no free second guess on one nonce) and the issued token are unchanged. Old clients ignore an unknown member (the mobile
`checkinTokenResultSchema` is a non-strict `z.object`); the mobile client consumes the hint since the follow-up change (`apps/mobile/src/attest/redeemer.ts`, rule 6; contract in `apps/mobile/README.md`, "Stale App Attest key recovery").

**Why `key_not_registered` (graded `unattestable`) carries it too.** The brief for this change named "no key is registered while an assertion was presented" as a rekey case, and it is the same family (the client holds a key the server does not):
a database restore or an admin reset that cleared the key lands here, not on `key_id_mismatch`. The mobile redeemer already reads `unattestable` after a presented assertion as "the server has no key" (`redeemer.ts`), so the hint adds no
information; it makes both cases one explicit field instead of a grade-reading convention. It is the only place the hint rides on a non-`failed` grade, and it raises no signal, as before.

### Why the hint leaks nothing useful

- **The caller already knows the one thing it says.** `key_id_mismatch` means "the key id you named is not the one on record". The caller chose that key id, so the negative statement is information it already has; the registered key id is **never**
  revealed (the answer carries no key id, the signal's `detail` carries none, and a test asserts neither the registered nor the presented id appears in the answer). `key_not_registered` was already readable from the grade.
- **It is not an oracle on other accounts.** Every row the verifier sees is the actor's own (`Repo` is actor-scoped; a foreign device is a 404 before any grading). Naming another account's key id is the same `key_id_mismatch` answer as naming a made-up one
  (tested), so the hint does not say whether a key id exists anywhere.
- **The residual: equality with the caller's own device's key, one bit per spent challenge.** Absence of the hint on a `failed` answer means the named key id equals the device's registered one (the failure was then something else). To use that, an attacker must
  guess a 256-bit key id (SHA-256 of the public key) for a device of their OWN account (or, with a stolen session, a victim's), paying one challenge and one `checkin-token` rate-limit slot (60/user/hour) per guess, with a `failed` token and an `attestation_failed`
  signal each time. A key id is not a secret in any case: it is sent in every request and returned by registration. Nothing is learnt that would let an assertion verify, which needs the private key.
- **It cannot be forced on an honest request.** The hint depends only on the key id the request itself named, never on the binding, the nonce or the counter (the key-id comparison runs before every other check in `verifyAppAttestAssertion`), so no other
  failure can be relabelled as a key problem and a replay stays indistinguishable from a wrong binding.

### The fraud signal: still raised

For `key_id_mismatch` the grade stays `failed` and `fraud_signal(attestation_failed)` is opened exactly as before (`raiseAttestationFailedIfNone`: one OPEN signal per account, serialised; `detail.reasons = ["key_id_mismatch"]`, no key material), so a reviewer still
sees every stale-key event, **with the reason recorded**. `key_not_registered` stays `unattestable` and raises nothing. Rejected alternative: **suppress the signal when the device then re-registers and attests within a window.** It needs a time window, a
read-after-write between two endpoints that share no transaction, and a rule for which earlier signal a later success clears, and it would make "a captured assertion followed by an honest re-registration" indistinguishable from recovery. The signal's job is to
make a human look; a human clearing it after a legitimate recovery (the reason names it) is the same act as today. **Consequence, stated plainly:** recovery restores the GRADE on the next check-in, not the account's standing: the open signal keeps holding the
account's activations (§7.5 row 2) until a reviewer clears it. That is the existing cost of any `failed`, unchanged.

### `rewards-activate`: no hint (it has no such answer)

The activation answer is `{id, kind, state, held, replay}`: it carries no grade and no reason ("the matched table row and its reasons are server-side diagnostics only and are never returned"), so there is no `failed` answer to extend. A key mismatch there grades
`failed`, the reward is `held_review`, and a repeat of the request is the idempotent "already held" short-circuit that verifies nothing, so a client that registered a fresh key could not release it by retrying either. Adding a field to that answer would be a new shape
for a case recovery cannot fix. The client learns the key is stale from its next check-in (`rekey: true`); the held reward waits for a human, as for any `failed`. **Not changed; no activation test changed.**

### The recovery path: `POST /v1/devices/attest-key` replaces a key on the caller's OWN device (verified, not changed)

Read and tested this session, nothing altered: the device must be the caller's own iOS (or not-yet-labelled) device; the key must be a **new** one (409 `key_already_registered` for the current key; 409 `key_previously_retired` for a key that was ever replaced on this device,
the newest 16 are remembered, so an old key can never return); a live challenge is consumed (120 s, bound to device and user); Apple's chain, the nonce, the key id, the app id, the counter and the environment are verified; `app.register_attest_key` then answers `registered`
(first key) or **`replaced`** (HTTP 200, `replaced: true`): the new key and public key are written, the **counter restarts at 0** (the old key's counter must not become the new key's floor), the old key's hash joins the retired list, and `device.attest_key_replaced` is audited with
hash prefixes only. Rate limits: 10/user/hour and 10/device/day, hit before the transaction; a failed registration returns 422 `attestation_rejected`, spends its challenge, and raises NO signal. Existing coverage: `attest-key-handler.test.ts` (reinstall: replaced, counter 0, old key retired) and
`attest-key.deno.test.ts` (replacement on the real SQL, counter restart, retired key cannot return, the lost-advance race with a mid-flight replacement). **New in this change** (`checkin-attest.deno.test.ts`, real database): register key A, present key B (`failed` + `rekey`, signal open with `key_id_mismatch`,
counter untouched), re-register B through the real handler (200, `replaced`, counter 0), and the very next check-in with B (counter 1) is `attested` with no hint, the signal still open; the retired key A is then `failed` + `rekey` and cannot be registered again (409).

**What the client must do with the hint (implemented in `apps/mobile`, with a per-device 1 h cooldown so it registers at most once an hour):** on `rekey: true`, generate a **fresh** App Attest key (Apple attests a key once, so the existing local key cannot simply be re-registered `[unverified — training knowledge of DCAppAttestService]`), register it through
`devices-attest-key` ONCE, then attest the next check-in with it; never loop (the budget is 10 registrations per device per day, and a refused registration is a 422 that spends a challenge). A 409 `key_previously_retired` means the key is already dead on this device: generate another.

### Limits, stated

- **A repeat redemption of the same challenge answers the ORIGINAL token WITHOUT the hint.** The hint is a property of the answer, not of the stored token (no schema change, hence no migration), and an idempotent repeat re-verifies nothing. A client whose response was lost
  therefore sees `failed` plain once; its next check-in (a new challenge) with the same stale key gets the hint. Persisting it would need a column (`0046`); not done, because the recovery does not depend on the lost answer.
- **A key replaced mid-flight (`key_replaced`) carries no hint:** the assertion verified against the key that was on record when it was read; the replacement that raced it is, in the usual case, the same device's own re-registration.
- **Honest limits of what is proved:** the verifier's wire format is still `[unverified]` against a real device (unchanged); the recovery was exercised end to end with synthetic attestations.

### Tests and verification (the `rekey` hint)

- **Unit** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): **54 files / 1107 tests** (was 1097; all in `checkin-token-attestation.test.ts`, 54 -> 64): `rekey: true` on a mismatched key id (the
  signal is raised with `["key_id_mismatch"]`, the challenge is spent, the counter untouched, the wire keys are exactly `jti, expiresAt, attestationGrade, rekey`), on another account's key (the same answer), and, as `unattestable`, when no key is registered; ABSENT on counter replay, counter
  out of order, a bad signature, a wrong binding / purpose / nonce, an rpId mismatch, a malformed signature and assertion, each lost-advance race (higher counter, equal counter, key replaced mid-flight), `attested`, the no-attestation `unattestable` / `failed`, and an Android `failed` (each with the strict
  key set); the registered key id with a signature by another key is `failed` WITHOUT the hint; the key-identity list pinned against the real verifier's output; repeated mismatches share ONE open signal; a repeat redemption answers the original token without the hint; the answer carries no key id.
- **Deno integration** (`checkin-attest.deno.test.ts`, real `withOwnership` / `Repo`, both harness modes): **293 passed, 0 failed** (was 290; +3): register key A through the real handler, present key B (`failed` + `rekey`, signal open, counter untouched), re-register B (`replaced`, counter 0), the
  next check-in `attested` with no hint and the signal still open, the retired key A `failed` + `rekey` and refused re-registration (409 `key_previously_retired`); no key + assertion (`unattestable` + `rekey`, then a first registration makes it `attested`); ABSENT on out-of-order, a signature by another key, a wrong
  purpose, a wrong rpId and a no-attestation `failed`. Two existing cells gained an assertion (a counter replay carries no hint; another account's key does). pgTAP `Files=30, Tests=2441` unchanged (no migration).
- **The mobile edge-contract recorder** (`apps/mobile/scripts/record-edge-contract.rec.ts`) was re-recorded (`RECORD_EDGE_CONTRACT=1`) and passes in verify mode. Its scripted iOS port now answers the verifier's own words for the two key-identity refusals (`key_not_registered` / `key_id_mismatch`)
  instead of one generic reason. **The fixture diff is three ADDED entries and nothing else** (39 added lines, 0 changed or removed; every existing recorded answer is byte-identical): `attestkey_201_registered_for_rekey`, `token_201_failed_rekey_ios` (`"attestationGrade":"failed","rekey":true`) and
  `token_201_unattestable_rekey_ios` (`"attestationGrade":"unattestable","rekey":true`). No other mobile source changed; `apps/mobile` passes (48 files / 1355 tests, 4 skipped).
- `deno check --frozen` (every entrypoint and the integration test) and `deno cache --frozen`: exit 0, `deno.lock` unchanged. `verify-function-inventory` OK and `service-role-lint` clean (inside both `test.sh` runs); `tools/db/check-migrations-immutable.sh --base origin/main` OK (45 migrations byte-identical, none added);
  `gitleaks dir .` no leaks; `GOLFRAVEN_DEMO=1 pnpm -r test` and `pnpm -r typecheck` exit 0.

**Mutation proofs** (each applied to a world-readable `/tmp` copy, the unit suite and the recorder run, success = a test that passes unmutated now fails; **14 of 14 caught by the unit suite**, the copy deleted, a search of the repository for the mutation marker prints nothing): the hint on ANY `failed` grade
(5 tests fail); the hint missing on a `key_id_mismatch` (6); missing when no key is registered (2); the hint on a counter replay / lost advance (1); on a key replaced mid-flight (1); on an rpId mismatch (2); on a bad signature (3); on a malformed assertion (2); on an `attested` answer (2); on an Android failure (1); on the
no-attestation `failed` path (1); the member always present as `false` (12); the hint persisted into the repeat redemption (2); and the fraud-signal behaviour changed (the signal not raised when the hint is set: 4).

## Offline TOTP seed provisioning (P4.2b-3a, 2026-10-03): `me-offline-seed`, the replay table and the verification core (migration `0045_offline_totp_seed.sql`)

Build plan §7.6 "Offline staff path (G-P1-07)", "Offline marker purchase (G2-03)" and "Offline offer redemption (A2-21)"; §4.5 `staff_presence` with and without a co-signal; the P4.2 line; P5 acceptance tests (12) and (13). **Server only.** The mobile client comes later; the staff verification endpoint belongs to the P5 portal and is **not** built here. What is built is the provisioning endpoint, the database half (a derived seed, a replay table, one staff-lane record function) and a pure, tested verification core P5 will call.

### What the spec asks for, and what each part is

A 6-digit TOTP (RFC 6238, 10-minute step) is computed **on the device** from a per-(account, device) seed. The server provisions the seed while the device is online and the device keeps it in its secure store. At a no-signal shop the staff member enters the player's **handle plus the code**; the server verifies it against that player's seed (+-1 step), records the used step so it cannot be replayed, and binds the evidence to the staff member's facility scope. Verification is limited to 5 failures per staff member per hour (critic SP13).

| Part | Where | Status |
|---|---|---|
| Seed derivation (K in Vault, HMAC in Postgres) | `private.offline_seed_derive` (0045) | built, tested against an outside reference |
| Seed version per device, rotation | `app.device.offline_seed_version`, `private.offline_seed_for_actor` | built |
| `POST /v1/me/offline-seed` | `supabase/functions/me-offline-seed`, `_shared/me/offline-seed-handler.ts` | built |
| Replay table, atomic record | `app.offline_code_step`, `private.offline_code_record_step_for_actor` (the `Repo#offlineCode.recordStep` wrapper was **removed by 0047 / X9**: the function is no longer EXECUTE-able by `edge_actor`; S3's partner definer calls it) | built |
| Pure verification core | `_shared/offline-code/{params,totp,verify}.ts` | built |
| Staff verification endpoint, staff-lane derivation by handle, the 5-failure counter, the evidence write | P5 | **not built** (checklist below) |
| Mobile client (secure store, code display) | P4.2 mobile lane | **not built** |

### The design, and the choices that were open

1. **No per-device seed is stored. The seed is derived:** `seed = HMAC-SHA256(K, 'golfraven/offline-seed/v1' || 0x00 || user_id || device_id || seed_version)`, where `user_id` and `device_id` are the 16 raw bytes of each uuid and `seed_version` is 4 bytes big-endian. Everything after the label is fixed length, so two different (user, device, version) triples can never produce the same message. A change to any of the three is a different seed (the pgTAP vectors and the Deno test prove it against a reference computed outside the database).
2. **Where K lives, and where the HMAC runs (chosen and documented):** K is the Vault secret `offline_seed_key` (at least 32 bytes, used as raw UTF-8 key bytes, the same convention as the pseudonym keys). It is read in **one** place, `private.offline_seed_derive`, a `SECURITY DEFINER` function owned by `private_definer` with `search_path = ''`, which **no role may EXECUTE** (the wrappers call it as the definer). **The HMAC is computed in Postgres and the derived seed is returned to the Edge function.** The alternative, the Edge runtime fetching K the way `get_signin_token_kek` hands out the sign-in KEK (0035) and deriving in TypeScript, would put the one key that mints **every** player's offline code in a process that serves public requests; here the runtime only ever holds a derived seed, for one device of the caller, after the database has checked the device is the caller's. pgTAP proves exactly one function in the database names the key, no role can read the Vault, and `edge_actor` cannot call the core; a unit test proves no production TypeScript holds the derivation label or the secret's name, and a Deno test proves it again as the real `edge_actor`.
3. **Algorithm: HMAC-SHA-256 (RFC 6238's SHA-256 mode), pinned.** Both ends are ours; the seed is already a 32-byte HMAC-SHA-256 output, which is exactly the key length RFC 6238 gives for SHA-256 (so no key-length special case); nothing is gained by carrying SHA-1 into a new design. The value is pinned in `params.ts` and echoed in the response (`algorithm`), so a client built against anything else fails loudly instead of computing wrong codes. RFC 6238's own SHA-256 test vectors (Appendix B, recomputed at the 600 s step) are a unit test.
4. **Seed encoding on the wire: RFC 4648 base32, upper case, no padding** (52 characters for 32 bytes), the encoding every TOTP library takes.
5. **Rotation = `POST` with `{"rotate": true}`**: one atomic `UPDATE app.device SET offline_seed_version = offline_seed_version + 1` under the row lock, then the derivation under the new version. Concurrent rotations get distinct, increasing versions (Deno test). The version never decreases (a trigger; a lower one would revive a rotated-out seed). Rotation invalidates every code the old seed could produce, because the old seed is no longer the verifier's seed, and the record function refuses a version that is not the device's current one.
6. **Replay table:** `app.offline_code_step`, primary key `(device_id, seed_version, step)`; `user_id` (FK to `auth.users`, the same shape as every personal table), `facility_id`, `used_at`. No seed, no code, no staff identity. The version is in the key so that after a rotation the same step number of the NEW seed (a different code) is not mistaken for a replay of the old one. `INSERT ... ON CONFLICT DO NOTHING` plus the row count is the atomic "was this new": two concurrent requests racing on one step get exactly one `recorded` (Deno test: 12 parallel requests, and 12 across two facilities).
7. **Staff-lane record function** (`private.offline_code_record_step_for_actor(device, seed_version, step, facility)`, edge_actor): the scope check comes first (no staff or manager scope at the facility: `42501`, the same answer for a real and a made-up device, so no existence oracle); the device's owner may not be the caller (`22023 self_attestation_refused`, A2-21, the database twin of the check P5 also makes at the Edge); the version must be current (`stale_seed_version`); the step must be within 2 of the database clock (`step_out_of_window`; deliberately **wider** than the core's +-1 so two clocks either side of a boundary never refuse a code the core accepted); then `recorded` or `replayed`. It also deletes that device's steps more than 3 behind the clock (they can never be accepted again), so the table holds a handful of rows per device, not a history.
8. **Provisioning never creates a device.** The device must already be the caller's (registered by `me-push-token`, the check-in challenge prefetch, etc.); another account's device and a device that does not exist are the **same** `404 not_found` (no oracle on device ids). The alternative, `ensureOwn` creating the row, would have answered `409 device_owned_by_other_user` for a foreign id (the existing convention elsewhere) and made a secret-revealing endpoint a device-creation path; the cost of the strict choice is an ordering rule for the mobile client: **register the device first** (the prefetch and push-token calls already do).

### The wire contract the mobile client must implement

`POST /v1/me/offline-seed` (JWT, as every `me-*` write). Body, **strict**: `{"deviceId": "<uuid>"}` or `{"deviceId": "<uuid>", "rotate": true}`; any other key is `400`, `rotate` must be a boolean. Response `200`, `cache-control: no-store`:

```json
{ "data": { "seed": "<52 chars, A-Z2-7>", "stepSeconds": 600, "digits": 6, "algorithm": "SHA256", "seedVersion": 1, "issuedAt": "2026-10-03T12:00:00.000Z" } }
```

- `seed`: base32 (RFC 4648, upper case, no padding) of **32 bytes**. Store the **bytes** in the secure store (Keychain / Keystore), never in logs, analytics or a backup that leaves the device.
- Code at unix time `t` (seconds): `counter = floor(t / 600)`; `h = HMAC-SHA256(seed bytes, counter as 8 bytes big-endian)`; `offset = h[31] & 0x0f`; `bin = ((h[offset] & 0x7f) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | h[offset+3]`; `code = (bin mod 10^6)` left-padded with zeros to **6 digits** (leading zeros are significant). This is RFC 4226 dynamic truncation over HMAC-SHA-256; the code is the same for the whole 10-minute step, and the staff member's server accepts the step before and after the server's own (so a device clock up to roughly 10 to 30 minutes off still works, depending on where in the step both clocks are).
- `seedVersion` and `issuedAt`: keep the version with the seed; `issuedAt - local clock` is an estimate of the device's clock offset (the app may show a warning when it is large).
- Re-calling returns the **same** seed (deterministic), so a reinstall that lost the secure store recovers by calling again. `rotate: true` returns a **new** seed and version and the old one stops working at once; rotate when the device is lost or the secure store may have been read. A `404` means the device is not registered to this account (register it first, then call again). `429` is the rate limit (below). `503 offline_seed_unavailable` means the server's key is not provisioned yet (retry later).
- Provision while online, **before** the player expects to be offline: the app should provision at first sign-in on a device and on every launch that finds no seed in the secure store, and re-provision on a `seedVersion` it does not hold.

### Threat model

| Threat | Control | Proof |
|---|---|---|
| A seed leaked from one device gives codes for another device or account | `user_id` and `device_id` are in the HMAC input; HMAC is a PRF, so a seed says nothing about K or any other seed | pgTAP vectors (another device, another user, another version: three different outside-computed values); Deno test |
| A code is accepted twice | `app.offline_code_step` unique `(device, version, step)`, atomic insert | pgTAP `recorded` / `replayed`; Deno: 12 concurrent requests, exactly one wins |
| A code from an old seed works after rotation | rotation changes the seed; the record refuses a stale version | unit (old code refused vs new seed), pgTAP (`stale_seed_version`), Deno (full chain) |
| K leaves Postgres | one definer reads it, no role may EXECUTE that definer, edge roles cannot read the Vault; no production TS names it | pgTAP (privilege matrix, one function names the key), unit source scan, Deno as the real `edge_actor` |
| Seed reveal abused (a stolen session harvesting) | `hitRateLimitForActor` before `withOwnership`: 20 reveals an hour, and 5 rotations an hour on top; per actor | Deno (21st refused, per actor), unit (the entrypoint orders the hits before `withOwnership`) |
| Provisioning another user's device | the definer returns zero rows unless the device is the bound actor's own; `404`, identical to a missing device; rotation likewise | pgTAP, Deno, unit |
| A staff member records a step for a facility they do not work at | `private.is_staff_or_manager_of_facility`: another facility's staff, a revoked member, an operator, a plain player are all refused | pgTAP section 6 |
| A staff member attests their own account | `22023 self_attestation_refused` in the database | pgTAP, Deno |
| A request with a client-chosen user, version or key | strict body: only `deviceId` and `rotate`; the actor comes from the verified token | unit |
| The seed in a log or an error | no `console.*` in the offline-code modules, the handler or the entrypoint; the 503 and 500 bodies carry no database text; `handleRequest` logs only the error object, and the database errors carry no seed | unit source scan; Deno (503 message names nothing) |
| A staff-lane runtime that holds a player's seed can mint that player's codes | **required P5 design (step 3): verification inside the database, no seed ever reaches the staff runtime**; until P5 exists the 0045 surface hands no account's seed to another account's session | design; pgTAP (no role can EXECUTE the derivation core) |

### Rotation of K (the fleet key), and of a device seed

- **A device seed** rotates with `POST ... {"rotate": true}` (above). **K** is not rotated routinely: changing the value of `offline_seed_key` changes every derived seed, so **every** player's offline code stops verifying until each device re-provisions (and the endpoint hands out the new seed under the *same* `seedVersion`, so the version number does not reveal it). It is an incident response (K suspected exposed). A cleaner fleet-wide invalidation, if ever needed, is to bump every device's `offline_seed_version` in one migration. Deploy runbook: `docs/security/edge-role-design.md` section 15 item 8.
- **Ops rule:** do not delete or overwrite `offline_seed_key` while players depend on offline codes; a missing key is `55000` and the endpoint answers `503 offline_seed_unavailable` (fail closed), a too-short key is the same.

### Deletion and export (decided)

- **Deletion.** `app.offline_code_step` carries `user_id` (FK to `auth.users` ON DELETE CASCADE) and is classified `delete_row` in `private.pii_retention_policy`, so `delete_my_data`'s registry-driven pass deletes it (with its `_r` visibility companion and its post-condition re-count), and the device FK cascades too. Nothing per-device needs wiping for the **seed**: it is derived, so deleting the device and the account leaves nothing that can recompute it except K plus ids that no longer exist. pgTAP and Deno both delete a real account and read the rows back as gone, with another account's row untouched.
- **Export.** `GET /v1/me/export` now includes (a) `offline_seed_version` on each device (a counter about the account's own device, the same kind of fact as `first_attested_at`), and (b) a new `offline_code_step` block (`user_id, device_id, seed_version, step, facility_id, used_at`): a presence-shaped record that a staff member accepted a code of the subject's own device at a facility at a time, like `purchase_evidence`. **The seed is never exported**: none is stored, and K is not the subject's data. The export function was rebuilt from 0044's final body with exactly those two changes; `14_me_export.sql` pins the new device column list and the rows file proves the block and that no seed hex or key appears.
- **Retention beyond the account.** The replay rows are pruned at write time (a device keeps only steps within the acceptable window). A TTL purge step in `retention-purge` for devices that are never verified again is a follow-up (a device keeps at most a few rows until then), not a claim.

### What P5 must do (the staff verification endpoint), in order

> **HARD RULE (gate LOW-1). RLS policies keyed on settable GUCs are NOT an ownership boundary against `edge_actor`; every `_for_actor` definer must filter explicitly by the bound uid.** A `private_definer` policy written `USING (col = nullif(current_setting('some.guc', true), ''))` is only a window the definer itself is meant to open, but `set_config` is open to **any** session, `edge_actor` included. The gate proved it on this very migration's neighbour: as a real `edge_gateway` / PA it planted `app.delete_my_data.target_user_id` (the policy `pd_delete_device_user_id_r`, 0016) and, with the explicit `d.user_id = v_uid` filter removed from `offline_seed_for_actor`, read PB's device row. Nothing leaks today only because the derivation uses the bound uid and the filter is explicit. So: (1) every `_for_actor` definer filters by the bound uid (or by an explicit scope check) in its own SQL, on every statement that reads or writes a caller-visible row; (2) a definer that derives or returns anything from another account's row must say, in its comment, which explicit check makes that safe; (3) do not add a policy that makes a definer's ownership depend on a GUC; key it on the actor binding (`private.actor_binding`, written only by `private.bind_actor`) as `pd_edge_act_*` and `pd_offline_code_device_select` are; (4) `app.offline_code_step`'s own GUC-keyed policies remain only because the one definer that touches the table sets the window itself and filters every statement explicitly, and nothing is returned from it for the caller. pgTAP now plants both GUC windows as PA and asks for PB's device (read and rotate): zero rows; the mutant that removes the explicit filter fails there.

1. Authenticate the staff member (passkey session scoped to the facility), take the player's **handle** and the 6 digits, resolve the player. **Refuse the staff member's own account** (422, A2-21), as the database also does.
2. **Count the attempt first**, and give it back on success: "5 failures per staff per hour" (SP13). `hit_actor_rate_limit` has no release, so it cannot express "failures" without also counting successes; use a reserve / release pair modelled on `private.reserve_signin_otp_attempt` / `release_signin_otp_attempt` (0035 section 3k), keyed on the **staff member** (the bound actor), not the player, so guessing across many players from one account hits one counter. Constants: `OFFLINE_CODE_STAFF_FAILURE_BUCKET`, `OFFLINE_CODE_STAFF_FAILURE_WINDOW_SECONDS` (3600), `OFFLINE_CODE_STAFF_MAX_FAILURES` (5) in `_shared/offline-code/params.ts`. Count every failed verification (`malformed_code`, `mismatch`, `replayed`, `stale_seed_version`, `no_such_device` for a handle with no device).
   - **Also count failures per TARGET player, not only per staff member (gate NIT-2).** One verification checks up to **20 devices x 3 steps = 60 candidate codes** per guess, so a single wrong guess is a 60 in 10^6 (6 x 10^-5) chance of being right against a player with 20 devices (the plan's device cap); the per-staff limit alone (5 an hour) bounds one account at about 3 x 10^-4 an hour per target, but a **second staff account** (a colluding or compromised one) starts a fresh counter, so many accounts attacking one player are bounded by nothing. Required numbers: **(a)** limit candidates to the player's **5 most recently seen devices** (`app.device.last_seen`, and only devices seen in the last 90 days): 5 x 3 = 15 candidates, a 1.5 x 10^-5 chance per guess; **(b)** count a failure against the target as well, a second counter keyed on the **player** (the definer builds the key in the database, e.g. `offline-code-fail:target:<user_id>`), **at most 10 failed verifications per target per hour and 30 per day across ALL staff**: at most 10 x 15 = 150 candidates an hour, about 1.5 x 10^-4 per hour and 4.5 x 10^-4 per day, from every account combined; **(c)** the per-staff cap of 5 an hour stays (so one account reaches at most 75 candidates, 7.5 x 10^-5, an hour). A target counter is also a lock-out lever (an attacker with any staff account can burn a player's offline path for an hour): count only failures by callers who hold a staff scope at a real facility (the definer's own check), alert on a target at its cap, and accept the cost, because the alternative is a brute-force surface of 60 codes a guess. A successful verification does not reset either counter.
3. **REQUIRED DESIGN: verify inside the database; seeds never reach the staff runtime.** (This was an option in the first write-up; the gate made it the requirement.) P5's migration adds ONE staff-lane definer, `verify-and-record` (name at P5's discretion), that takes the **handle, the typed 6 digits and the facility**, and does everything in Postgres: it checks the caller's staff scope at the facility and that the player is not the caller (`22023`, A2-21), resolves the handle, derives each candidate device's seed with `private.offline_seed_derive` (no EXECUTE for anyone: only a definer can), computes the HMAC-SHA-256 TOTP for the window steps in SQL (`public.hmac` on the 8-byte big-endian counter, RFC 4226 dynamic truncation, mod 10^6; proven against `_shared/offline-code/totp.ts` and the RFC 6238 vectors, which are already unit tests), compares in constant time, records the matched `(device, version, step)` with the same atomic `INSERT ... ON CONFLICT DO NOTHING`, and returns **only** `{ ok, device_id, step }` (or a bare refusal). No seed, no expected code, no per-candidate result ever leaves Postgres on the staff lane, so a compromised staff-lane runtime can no longer mint codes for any player (the limit the first design accepted and documented).
   - **The recorder must then require proof of the code, not trust Edge.** 0045's `private.offline_code_record_step_for_actor` takes `(device, version, step, facility)` and records whatever a caller claims verified; it exists as the atomic primitive and its Deno / pgTAP proofs, and it is a step-burning primitive for any staff caller who knows a device id (an id the staff lane never sees once the derivation moves into the database). P5's migration must **supersede it**: the verify-and-record definer above does the insert itself, and the migration `REVOKE EXECUTE ... FROM edge_actor` on `private.offline_code_record_step_for_actor` (and drops `Repo#offlineCode.recordStep`) so no Edge code can record a step without presenting the code the database checked. `_shared/offline-code/{totp,verify}.ts` then remain the reference implementation and the test oracle (RFC vectors, +-1 window, constant-time rule) the SQL is proven against; they are not a request-path dependency of the staff endpoint. **Update (0047, X9):** the recorder's `edge_actor` EXECUTE and its Edge wrapper are gone, so the "trust Edge" shape described here no longer exists on the user lane; the verify-and-record definer is S3's `_for_partner` function.
   - **If, against this requirement, a deviation is ever proposed** (a staff-lane definer returning seeds to the Edge runtime), it needs its own security review: the runtime then holds every player's seed for the request, and the only bound is that a code alone is `staff_presence` without a co-signal (0.80, badge-only, excluded from money, section 4.5), the hard class (0.95) needing the player's own challenge-bound fix within +-10 minutes of the code's step.
4. On `{ ok: true }` from the definer: only then write the evidence, bound to the staff member's facility scope. Refusals map as: a code whose step was already recorded is the `409` of P5 acceptance (13) ("a replayed code step returns 409"); a rotation that landed mid-request is "ask for a new code"; everything else is a failed verification and counts (step 2).
5. Evidence class: the code alone yields `staff_presence` **without** co-signal; it becomes **with** co-signal only when the player's app submits a fix against a prefetched challenge within +-10 minutes **of the code's step** (the step recorded here, not the upload time), the one §4.5 window (A2-20c). Marker purchase (`kind = marker_purchase`): the purchase row is `pending` until that co-signal arrives on reconnect (within 7 days). Offer redemption (A2-21): the offline code needs the staff step-up PIN and the in-app profile-card name check, is recorded `offline`, and raises a `fraud_signal` / `unconfirmed` settlement mark if no co-signal arrives within 24 hours.
6. A player may have several devices (up to 20), and "handle plus code" does not say which one produced the code: the definer tries the candidate devices (the 5 most recently seen, step 2) and takes the one that matches. A code matching two devices at once has probability about 10^-6 per extra candidate per step; if it happens the first match records (each device has its own `(device, version, step)` key).

### Residual risks and what is not known

- **A seed is valid until rotated.** There is no expiry: a device compromised later still holds a working seed until the player rotates (or the account is deleted). The mobile client should rotate on sign-out, on a reinstall that restored an old backup, and when the app detects a lost secure store.
- **Clock skew.** The acceptance window is +-1 step around the server's step, i.e. a device clock up to 10 to 30 minutes off works; a device clock further off fails closed (the player re-syncs the clock). `issuedAt` lets the app detect it while online.
- `[unverified]` on a real Supabase project: that Vault accepts `vault.create_secret(..., 'offline_seed_key')` as described, that `public.hmac` exists there (migration 0029 already assumes it), and the behaviour of Supavisor transaction mode for the two statements (they are ordinary single-statement function calls inside the existing `withOwnership` transaction).
- The unbounded-in-time validity of a seed is accepted for this stage (rotate on sign-out and on a suspected compromise). The staff-lane runtime holding a seed is **not** accepted: P5 must verify inside the database (step 3).

### Tests and verification (P4.2b-3a; the final tree, nothing counted from before the last edit)

- **Unit** (`pnpm --filter @golfraven/rules exec vitest run --config ../../supabase/tests/vitest.config.ts`): **54 files / 1096 tests** (was 51 / 1008). New: `offline-code-totp.test.ts` (the RFC 6238 Appendix B SHA-256 vectors at the 600 s step, plus 200 random seeds against an independent `node:crypto` reference, base32 against the RFC 4648 vectors), `offline-code-verify.test.ts` (+-1 accepted and +-2 refused at the step boundaries, malformed codes, replay, rotation, the constant-time source checks), `offline-seed-handler.test.ts` (strictness and unknown keys, the exact six-key response, ownership, rotation, the 503, the P5-shaped composition on a fake Repo, and the source guards: K never in production TypeScript, the entrypoint's ordering). Changed: `fake-repo.ts` (+ `fake-offline-code-repo.ts`, `offline-seed-reference.ts`, the independent derivation, under `tests/` only), `rewards-isolation.test.ts` (the new function and module are on the earning-side lists). `ci-function-lists.test.ts` needed no edit: it requires every `supabase/functions/*/index.ts` in all three CI deno lists, and the new entrypoint is in each (a mutant that drops it from one list fails that test).
- **pgTAP** (`tools/db/test.sh`, both `HARNESS_MODE`s): **Files=30, Tests=2441, PASS** in both (was 27 / 2264). New: `23_offline_totp_seed.sql` (63: structure, the privilege matrix, K readable by nobody, the derivation against vectors computed outside the database, a missing or short key, the monotonic trigger, the registries), `23_offline_totp_seed_edge.sql` (91: as a real `edge_gateway` login: provisioning, rotation, another account's device, the replay record, scope, self-attestation, delegates, stale bindings, an admin naming an unknown facility), `23_offline_totp_seed_rows.sql` (23: the committed rows read back as `service_role`, the prune, export, deletion, cleanup). Changed: `14_me_export.sql` (the device block's column list).
- **Deno integration** (same script, both modes): **290 passed, 0 failed** (was 276): `offline-code.deno.test.ts`, 14 tests, on the real database and the real `privileged.ts`: the seed equals the independent reference; deterministic, and different per device, user and version; another account's device is a 404 and cannot be rotated; no device is created; **as the real `edge_actor`, the Vault, the derivation core, the replay table and the version column are all refused**; **12 parallel record requests for one step give exactly one `recorded`**, and 12 across two facilities too; statuses, scope, an admin's unknown facility (422) and self-attestation; the whole chain (provision, the device computes the code, staff verifies, record, replay refused, rotation invalidates); 6 parallel rotations give 6 distinct versions; the 21st reveal in the hour is refused; a missing key is a 503 that names nothing and service resumes when it returns; the export and deletion of real rows.
- `verify-function-inventory` OK and `service-role-lint` clean (inside both `test.sh` runs and standalone); `tools/db/check-migrations-immutable.sh --base origin/main` OK (44 existing migrations byte-identical, `0045` added); `deno check --frozen` and `deno cache --frozen` over every entrypoint including `me-offline-seed` exit 0 and **`supabase/tests/deno.lock` is unchanged** (no new dependency: WebCrypto only); `gitleaks dir .` no leaks; `GOLFRAVEN_DEMO=1 pnpm -r test` exit 0 for every project (after `pnpm install --frozen-lockfile` and `pnpm -r build`, as CI does).
- **The mobile edge-contract recorder, verify mode, passes with NO change to any recorded fixture** (no existing wire shape changed; the mobile client for this endpoint comes later).

**Mutation proofs** (each applied to a world-readable `/tmp/totp-mut-N` copy, never the tree; the suites run; success = a test that passes unmutated now fails; the unmutated copy was run as a control for each layer and passed; **38 of 38 distinct mutants caught (the one "equivalent" mutant of the first write-up was a real gap, see the gate follow-up below)**; copies deleted, and a repository-wide search for the mutation marker prints nothing):

| Threat | Mutants (all caught) | Caught by |
|---|---|---|
| user or device dropped from the derivation | `user_id` removed; `device_id` removed | pgTAP vectors (23, 23 edge) |
| version ignored | the derivation uses a constant version; the record no longer refuses a stale version; the rotation flag ignored; the handler always rotates | pgTAP vectors / `stale_seed_version` / rotation cells; unit |
| step window widened | the TypeScript window `1 -> 2`; the database bound `2 -> 200` | unit; pgTAP (`step_out_of_window`) |
| replay check removed | the record always answers `recorded`; the primary key and arbiter removed; the prune threshold moved so fresh rows are deleted; **the insert made check-then-act (non-atomic)**; the verifier's used-step pre-check removed | pgTAP (`replayed`); the **Deno 12-way race** (the check-then-act mutant passes every single-session cell and fails only there); unit |
| K exposed to `edge_actor` | EXECUTE on the derivation core granted, with the migration's own proof neutralised; the same grant with the proof intact | pgTAP 23 and 10; the migration itself refuses to apply |
| non-constant-time compare | `expected === code` | unit (the source check) |
| ownership / scope checks removed | the provisioning ownership removed at **both** layers (the function's filter and a permissive `private_definer` policy); the staff scope check removed; the self-attestation check removed; the delegate refusal removed; the handler ignoring the ownership answer (404) | pgTAP (23 edge); unit |
| registries and export | the retention classification row renamed away; the export forgetting the `offline_code_step` block; the export adding a derived seed to the device block; the key-length floor removed | pgTAP 09, 14, 23 rows, 23 |
| wire contract | digits 6 -> 8, algorithm echoed as SHA1, step 600 -> 300, base32 lower case, the dynamic-truncation mask wrong, unknown keys accepted, `no-store` dropped, the rate limits after `withOwnership`, the entrypoint dropped from a CI list, the label or the derivation call in production TypeScript | unit |

- **Correction (gate LOW-1): there is NO equivalent mutant here, and the first write-up's claim that ownership was "enforced twice" was wrong.** It said removing the `d.user_id = v_uid` filter from `offline_seed_for_actor` changes no answer because RLS hides another account's device from `private_definer`. That holds only while no `private_definer` SELECT policy on `app.device` is keyed on a GUC the session can set. Two were: this migration's own `pd_offline_code_device_select` (`app.offline_code.target_device_id`) and 0016's `pd_delete_device_user_id_r` (`app.delete_my_data.target_user_id`). With the filter removed and either GUC planted, PB's device was visible and the whole suite still passed. Fixed: `pd_offline_code_device_select` is now keyed on the actor binding (`private.offline_code_bound_staff()`), the explicit filter is the ownership boundary (and the doc's hard rule says so), 0016's policy (immutable) is documented as a window, and the new pgTAP cells plant both GUCs as PA and require zero rows for PB's device on the read and the rotate path. The mutant is now caught (see the follow-up block below).
- **A test weakness the mutation run found and fixed:** the first version of the "K never in production TypeScript" scan stripped comments with a regex that can pair a stray `/*` with a later `*/` and delete real code; a mutant placing the derivation call on a code line survived it. The scan is now a line filter (comment-only lines dropped, nothing else), and the mutant is caught.
- Not caught, and not claimed: nothing about the P5 staff endpoint (not built); the unit tests of the entrypoint are source-order checks, because `index.ts` calls `serve` on import and a real HTTP round trip needs a deployed gateway.

### PR #43 gate follow-up (second commit): LOW-1, NIT-1, NIT-2, NIT-3 (0045 edited, not superseded: it is not on `main` yet)

- **LOW-1 (c): the GUC-keyed device policy is gone.** `pd_offline_code_device_select` was `USING (id::text = nullif(current_setting('app.offline_code.target_device_id', true), ''))`. It is now `USING (private.offline_code_bound_staff())`: true only when THIS transaction has a `kind = 'user'` actor bound (`private.actor_binding`) who holds a staff / manager scope somewhere, or is an admin. A player cannot make it true (their binding is their own uid), and no session GUC can. It is deliberately **not** a per-device or per-facility boundary: `offline_code_record_step_for_actor` still checks the facility scope explicitly first and then reads `d.id = p_device_id`. The function has no EXECUTE for any role (`private_definer`, the only role the policy applies to, owns it). The three `app.offline_code_step` policies stay GUC-keyed, with the reasons written at the policy (one definer touches the table, sets the window itself from its own argument after the scope check, and filters every statement explicitly; nothing is returned from the table for the caller).
- **LOW-1 (b): pgTAP.** `23_offline_totp_seed_edge.sql` section 3b: as a real `edge_gateway`, PA bound, plants the offline-code device window and the `delete_my_data` user window (each alone and both) at PB's device or user, then calls `offline_seed_for_actor` for PB's device with `rotate = false` and `rotate = true`: zero rows each (so a 404), PA's own seed unchanged, and a non-staff PA planting the windows still cannot record a step (`42501`).
- **NIT-1.** `private.validate_and_register_pseudonym_hmac_id` (0018) accepted any Vault secret of at least 32 bytes by id, with no check of its name, so a writer allowed to set a pseudonym key id could have registered `offline_seed_key`'s id as a pseudonym key. 0045 now replaces it with the same body plus `AND name LIKE 'pseudonym_hmac%'` (the predicate `account_pseudonyms` already uses). Verified by a live body diff (a cluster at 0044 against a cluster at 0045): `prosrc` differs in exactly that one line; owner (`private_definer`), ACL (`private_definer`, `service_role`, `edge_actor`), `search_path = ''`, SECURITY DEFINER and volatility are identical. pgTAP: registering `offline_seed_key`'s id is refused (`23514`); a real `pseudonym_hmac_v1` id still registers; the posture cell.
- **NIT-3.** The staff-lane design that keeps seeds in Postgres is now the REQUIRED P5 design (step 3 above), and the recorder must be superseded by a verify-and-record definer that takes proof of the code. **NIT-2.** Brute-force guidance with numbers is in step 2 above (60 candidates a guess; 5 most recent devices; per-target cap of 10 an hour and 30 a day across all staff).
- **Mutation proofs for this commit** (one world-readable `/tmp` copy, the migration edited in turn, the 23 matrix files run on a fresh cluster each time, an unmutated control passing; **2 of 2 caught**): the explicit `d.user_id = v_uid` filters removed from `offline_seed_for_actor` (caught by the `delete_my_data`-window cells, tests 37 and 42: 0016's policy still leaks it, exactly as the gate found; the offline-code window no longer leaks because that policy is gone); the validator's name check dropped (caught by the refusal cell and the posture cell). The copy was deleted and a search of the repository for the mutation marker prints nothing.

## Marker purchase by course QR: the player lane (P5.1a S2a, 2026-10-04; migration `0046_course_qr_marker_scan.sql`)

The prose of what was built and the wire contract is `docs/security/partner-auth-design.md`, "As built: S2a". This section is what the money path needs from it: which rows a scan writes and in which states, the new definers and their trust argument, the seam S3 must use, and what is and is not proven.

### What a scan writes (purchase evidence and the credit)

`private.marker_scan_for_actor` (the bound actor is the buyer; no user argument) writes, per **eligible trail** of the facility (an accepted `any_purchase` programme row whose `qr_mode` allows the variant), one `app.purchase_evidence` row (`method = 'course_qr'`, `qr_variant`, `ref_id`, `local_date` in the facility's tz) and one `app.marker_credit` row:

| Co-signal | `purchase_evidence.status` | `marker_credit.status` | `cosignal` |
|---|---|---|---|
| attested fix | `valid` | `credited` | `{fixId, grade, capturedAt, evidenceId}` |
| unattestable fix | `held_review` | `held_review` | the same |
| none | `pending` | `pending` | `{awaiting: {from, to, until}}` |

A marker purchase **alone never creates or raises a play** (AT(4)): the scan writes no `app.play` row, and its one evidence row is the fix's facility-level `foreground_checkin`. **`credited` needs an attested co-signal** (AT(3)): the Edge cannot assert one the database does not receive with a fix id and an evidence row id, and the Edge only passes a grade for a fix it consumed a check-in token for. `ref_id` is the nonce hash (Q1) or `pin:<facility>:<local date>` (Q2; no epoch, so a rotation cannot allow a second same-day purchase); a unique partial index `(user_id, trail_id, ref_id) WHERE method = 'course_qr'` makes a replayed printed-QR scan a duplicate even under a race. The credit rule is unchanged: one credited marker per player per shop (a credit that cannot be `credited` because the player already holds one is voided by the intake).

### The definers (all `_for_actor`: SECURITY DEFINER, owner `private_definer`, `search_path = ''`, EXECUTE for `edge_actor` only)

| Definer | Returns | Trust argument |
|---|---|---|
| `course_qr_public_key_for_actor(kid, purpose)` | the public key and its revoked flag | public data; requires a bound actor so it cannot be called outside a request |
| `course_pin_attempt_for_actor(facility, pin, at)` | `ok / wrong / locked / no_facility / no_programme` | never raises (a refusal must commit so the counter counts); counters are sums over `private.rate_limit_bucket` under transaction advisory locks (50 parallel guesses: exactly five `wrong`); returns no PIN; judges the PIN under the date, epoch (`app.course_pin_epoch_log`) and pepper in effect at `at`, so a rotation never turns a queued honest scan into a counted failure (review M1); a right PIN writes `private.course_pin_proof` (with its instant); the proof is deleted by the scan that uses it **and by a deferred constraint trigger at COMMIT**, so the table is empty at rest and holds nothing for `DELETE /v1/me` to purge (round-2 medium) |
| `marker_scan_for_actor(...)` | a status, and the purchase and credit rows of the **bound** actor | every refusal is a returned status written before any write; every statement on a caller-visible row filters `user_id = <bound uid>`; the token's `used_by_user` is never returned (only that it was used); a printed-QR scan **raises `42501` unless the PIN gate passed in this transaction, for the same instant** (the proof row; chosen over repeating the counters, review L5), and **consumes** that proof when it accepts the scan; a `p_at` more than 5 minutes from now with no co-signal raises `22023` (L1); the token row's `kid` must equal the verified `kid`; the co-signal is read back (below) |
| `marker_cosignal_attach_for_actor(...)` | `attached / no_pending_purchase / cosignal_invalid / cosignal_used` and the caller's own rows | filters by the bound uid, takes the row lock; method-agnostic; reads the co-signal back first |
| `marker_cosignal_check(uid, facility, date, at, grade, fix id, evidence id)` | `ok / cosignal_invalid / cosignal_used` | **no EXECUTE for anyone**; the review-M2 read-back: the evidence row must be the **bound user's**, `foreground_checkin`, `source_ref = 'fix:' + fix id`, at this facility (no course), accepted, with the claimed grade, the scan's local date and captured time (within 1 s), used by no other scan (unique index on `(trail_id, cosignal->>'evidenceId')`), **and its derived fix must QUALIFY** (from the app, not simulated, foreground, a live or prefetched challenge, accuracy 0 to 50 m, polygon geometry, play-verified tier, inside the buffer, a token present with the claimed grade; round-2 low 1: an evidence-endpoint-shaped row is no co-signal) |
| `course_pin_derive(facility, date, epoch)` | the PIN | **EXECUTE for nobody**; the only reader of the Vault secret `course_pin_pepper`; called by exactly the two definers above |

New policies (22, `pd_marker_scan_*`) are keyed on the actor binding, never a settable GUC (the HARD RULE above): the wide visibility the token, QR and programme READ policies give the definer is not an ownership boundary, the definers' own predicates are. Column grants are narrow (`UPDATE (pin_epoch)` on `facility_programme`, `UPDATE (used_by_user, used_at)` on `course_qr_token`, `SELECT (id, tz)` on `catalog_facility`, ...). No existing grant or policy is broadened, FORCE ROW LEVEL SECURITY is kept on every table touched, and `edge_actor` has **no** privilege on `course_qr_key`, `course_pin_alarm`, `course_qr_token`, `facility_qr`, `purchase_evidence` or `marker_credit` (a pgTAP cell and the Deno suite both prove it as the real role).

### Threat table

| Threat | Control | Proven by |
|---|---|---|
| Replay of a rotating token | single-use `UPDATE ... WHERE used_at IS NULL` plus a write-once trigger | pgTAP; Deno: 6 parallel scans of one token give exactly one purchase |
| Token scanned long after issue | 120 s judged against the **fix** time, both directions; a fix older than 7 days is refused | pgTAP, unit, Deno |
| Forged or foreign QR | Ed25519 verification against a registered, unrevoked `kid` before anything is consumed; the facility id is bound into the printed-QR signature; a forgery commits a `fraud_signal` | unit, Deno |
| PIN guessing | 5 wrong per user per facility per local date (the 6th is `locked` even if right); 30 per facility per date rotates the PIN and alarms | pgTAP, Deno (parallel guesses; the 30-failure rotation) |
| PIN read by an Edge compromise | the pepper is read in one function nobody can EXECUTE; the player lane returns no PIN | pgTAP (one function names the pepper; no role may execute it), Deno (as `edge_actor`) |
| A purchase credited with no presence | `credited` only with an attested, challenge-bound fix inside a `play-verified` polygon plus 50 m | unit (drift test against the scorer's own predicate), Deno (a far fix, a simulated fix) |
| A claimed co-signal that is not the bound user's, not this fix, not this facility, a different grade or date, or already used | the database reads the evidence row back (`marker_cosignal_check`) and refuses: `invalid_cosignal` / `fix_already_used` | pgTAP, one must-fail cell per check against real evidence rows; Deno |
| A PIN rotation turning queued honest scans into wrong guesses | the PIN is judged at the fix's instant: its date, the epoch live then (`course_pin_epoch_log`), the pepper then (`course_pin_pepper_previous`, effective time from the operator-written `app.course_pin_pepper_epoch`, never Vault timestamps); a valid-for-its-instant PIN is never counted | pgTAP (scan dated yesterday + rotation today + upload = ok, nothing counted; two rotations in a day; a rotated-out PIN tried for a later instant IS counted; a previous pepper without an epoch row is never used), Deno |
| A leaked PIN or pepper after an alarm or compromise rotation | **residual, not closed**: back-dating a fix inside the check-in challenge's window (a prefetched challenge lives 24 h) keeps the OLD epoch's PIN, and while a previous pepper exists the previous pepper, verifying for up to about 24 h after the rotation; an instant after the rotation is judged under the new epoch. **A compromise rotation keeps no previous pepper and writes no epoch row** | pgTAP (an old epoch's PIN at a later instant is wrong) |
| A photographed rotating token burned days later, or a client choosing the PIN date | the instant is the fix's only for a **qualifying** fix, else now; the database refuses a `p_at` far from now without a co-signal | unit, pgTAP, Deno |
| `marker_scan_for_actor` used as an uncounted PIN oracle | it refuses (`42501`) a printed-QR scan without the same-transaction PIN-gate proof **for the same instant**, and consumes the proof | pgTAP (no gate, other facility, other date, other instant, other actor, ended transaction, a replaced proof, a second scan on one gate), Deno |
| The PIN proof outliving its transaction (an actor id at rest on a pooled backend) | deleted by the scan and by a deferred constraint trigger at COMMIT; the table is empty at rest | pgTAP C0 (a real-commit read as the owner with a positive control), Deno (committed gate with no scan, committed scan, refused scan) |
| A real evidence row that is no co-signal (the evidence endpoint's check-in) credited | the read-back checks the derived fix's qualification | pgTAP (one must-fail cell per field, plus the qualifying controls) |
| Another account's pending purchase completed | the intake filters by the bound uid | pgTAP (PA's fix joins nothing of PB's) |
| A refused scan spending a check-in token | refusals after the token's consumption are thrown (rolled back) | Deno (the second token is unspent) |

### What S3 and S2b must do

S3 (offline-code staff scan) writes its purchase as `pending` with `cosignal.awaiting` exactly as the design doc's seam paragraph states; the player's reconnect completes it through the existing intake with no change here. S3's verify-and-record definer still supersedes 0045's recorder (section "Offline TOTP seed provisioning", "What P5 must do"). S2b's PIN display must call `private.course_pin_derive` through a wrapper that checks the staff scope for the facility (the money doc's rule: no wrapper derives for an unchecked facility), with today's date and the facility's **current** epoch, and S2b writes `course_qr_token` / `facility_qr` rows and the public keys. S2b's "Rotate PIN" only has to raise `facility_programme.pin_epoch` (a trigger logs it); it must **not** write `app.course_pin_epoch_log` itself. Any pepper-rotation tooling must follow the procedure in the design doc's M1 section: a **non-compromise** rotation copies the old pepper to `course_pin_pepper_previous` and inserts into `app.course_pin_pepper_epoch` in the same transaction (delete the previous pepper after 7 days); a **compromise** rotation copies nothing and writes no epoch row.

**The plan §8.3 cap: 25 static-PIN course-QR credits per facility per day (L4).** This is a **signal and an alert, not a block**: a facility's 26th printed-QR credit of a local date still credits; what changes is that an operator is told. It is **not built in S2a**. It belongs to S2b (which owns the operator surface that reads the PIN alarm) and hooks in at one place: after `Repo#markerScan.record` returns an accepted `static_pin` scan in `handleMarkerScan` (`supabase/functions/_shared/course-qr/scan-handler.ts`), count the facility's credited rows for the local date (`app.marker_credit` joined to `app.purchase_evidence` on `method = 'course_qr' AND qr_variant = 'static_pin'`, `facility_id`, `local_date`, `status` in `credited`), and at 25 write one `fraud_signal` row (and push the same operator alert the PIN alarm uses) without changing the response. It reads the count through a new `_for_actor` read, not the Edge's own table access. S2a already bounds the inputs: 20 scans a user a day, 5 wrong PINs a user and 30 a facility a date, one credit per player per shop.

### Not verified (`[unverified]`)

Vault accepting `course_pin_pepper` / `course_pin_pepper_previous`, and `public.hmac`; the hosted Edge runtime's Ed25519 WebCrypto; the retention of `course_qr_token`, `course_pin_alarm` and abandoned `pending` rows (no purge yet).

### Tests and verification

Nothing from before the last edit is counted; each line is a command run on the final tree (the S2a re-gate fixes included).

- **pgTAP, both harness modes, one at a time** (`HARNESS_MODE=restricted tools/db/test.sh`, then `HARNESS_MODE=superuser tools/db/test.sh`, each a full initdb, migrate, seed, pgTAP, teardown): `Files=33, Tests=3005, Result: PASS` in both (S2a's three files are `24_course_qr_marker_scan.sql` 126 cells, `..._edge.sql` 348, `..._rows.sql` 90). The same runs: the Deno integration suite `314 passed | 0 failed` (21 of them `marker-scan.deno.test.ts`), `verify-function-inventory` OK, `service-role-lint` clean.
- `supabase/tests` vitest: 59 files, 1197 tests passed (S2a: 82 tests in the five marker / course-qr files). `packages/rules` vitest: 24 files, 443 passed (`marker-scan-presence.test.ts`: 5, the scorer fixture for the purchase-fix presence rule). `apps/mobile` vitest: 65 files, 1967 passed, 6 skipped. The recorder verify run passes; the fixture diff is additions only (21 `markerscan_*` responses).
- `pnpm -r typecheck` exit 0; `deno check --frozen` and `deno cache --frozen` over every Edge entrypoint exit 0 and `supabase/tests/deno.lock` unchanged; `tools/db/check-migrations-immutable.sh --base origin/main`: all 45 existing migrations byte-identical, `0046` added.
- **Mutation proofs** (world-readable `/tmp` copies, deleted afterwards; an unmutated control passing; a search of the repository for the mutation marker prints nothing): database 40 mutants of 0046, **40 of 40 killed**; Edge, mobile and recorder 55 mutants, **55 of 55 killed**; round 2 (proof lifecycle, qualification read-back, future bound, pepper epoch) 29 more database mutants, **28 killed, 1 equivalent**. Detail in `docs/security/partner-auth-design.md`, "As built: S2a".
- The harness-owner defects found on the way (and the restricted-mode `CREATE TRIGGER` EXECUTE grant) are written up in `docs/security/partner-auth-design.md`, "As built: S2a".
