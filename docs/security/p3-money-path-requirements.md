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
