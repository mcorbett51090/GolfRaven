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
- **Catalog skew (AT 8/15, G3-10) — implemented, with one honest deferral.** Version-window
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
- **Signed payload.** The manifest signature is verified over a domain-tagged payload
  (`golfraven-catalog-manifest-v1:${version}:${manifestSha256}`), binding both the version and the
  manifest's own claimed content hash.
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
