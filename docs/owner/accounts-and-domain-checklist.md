# Accounts and domain checklist

Covers the "External prerequisites moved into P0" non-gating items (plan §10 P0, G-P0-02, G-P0-07, FM-27) and
the P0 acceptance test: "The GolfRaven domain resolves, SMTP passes a DMARC check, and the organisation store
accounts exist in the operating entity's name (or their pending status is dated)."

Each item below: what it is, **done when**, and the P0 acceptance test it satisfies.

## 1. Domain — golfraven.com / .golf / .ca

**What:** Register the primary domain for GolfRaven (O1 DECIDED 2026-09-23). Check availability/price for
`golfraven.com`, `golfraven.golf`, and `golfraven.ca`; register the primary (`.com` preferred) and hold the
others where cheap `[unverified — availability and price; A82]`.

**Done when:** `golfraven.com` (or the next-preferred available option) resolves, and any additional TLDs held
are recorded with their registrar/renewal date.

**P0 acceptance test satisfied:** "The GolfRaven domain resolves" (plan §10 P0 AT(5)).

**Note:** WHOIS/RDAP lookups against `rdap.verisign.com` were proxy-blocked in this session (see
`docs/owner/network-unblock.md`) — availability has not been checked from this environment.

## 2. D-U-N-S number

**What:** A D-U-N-S number is applied for now if the operating entity does not already hold one (O20
DECIDED: Matt's existing operating entity is the applicant and merchant of record for US + CA).

**Done when:** Either an existing D-U-N-S number is confirmed on file for the entity, or an application has
been submitted with a dated receipt.

**P0 acceptance test satisfied:** "the organisation store accounts exist in the operating entity's name (or
their pending status is dated)" (plan §10 P0 AT(5)) — Apple's and Google's organisation developer accounts
both require a D-U-N-S number as part of verification.

## 3. Apple Developer organisation account

**What:** Open an **organisation** Apple Developer account in the name of the P0 legal entity (O20).

**Done when:** The account is approved and active under the entity's name.

**P0 acceptance test satisfied:** AT(5) (organisation store accounts in the entity's name, or dated pending).

## 4. Google Play organisation developer account

**What:** Open an **organisation** Google Play developer account in the name of the P0 legal entity (O20). If
only a personal account is available by P4, the plan budgets 3 weeks for a closed test with ≥ 12 testers drawn
from K2 signups as a fallback `[unverified — training knowledge on the current rule]` — that fallback is a P4
concern, not a P0 blocker.

**Done when:** The account is approved and active under the entity's name.

**P0 acceptance test satisfied:** AT(5).

## 5. Sign in with Apple service id + key

**What:** Under the organisation Apple Developer account, create the Sign in with Apple service identifier and
its signing key (O12 DECIDED: email OTP + Sign in with Apple + Google at launch; Apple 4.8 makes Sign in with
Apple mandatory once Google sign-in ships).

**Done when:** The service id and key exist and are stored securely (they are P4 build-time inputs, not
committed to the repo).

**P0 acceptance test satisfied:** AT(5) explicitly names this: "…incl. the Sign in with Apple key and Google
OAuth client" (P0 DoD, plan §15).

## 6. Google OAuth client

**What:** Under the organisation Google account, create the Google OAuth client used for Google sign-in
(O12).

**Done when:** The OAuth client id/secret exist and are stored securely.

**P0 acceptance test satisfied:** AT(5) (same DoD line as above).

## 7. Custom SMTP with SPF/DKIM/DMARC

**What:** Verify the P0 domain with **Resend** (the provider the K2 signup worker already uses, as in
raven-site-kit's secure-upload), with SPF, DKIM and DMARC records published. For Supabase Auth's email later,
point it at Resend's SMTP relay on the same verified domain `[unverified — training knowledge: Resend SMTP
availability; confirm on Resend's dashboard]`, and raise Supabase Auth's per-hour email limits to match — the built-in SMTP is
development-only `[unverified — training knowledge]` (plan §7.7, FM-27, G-P1-17, FM-26).

**Done when:** All three DNS records (SPF, DKIM, DMARC) are published for the domain, and a test send through
the provider passes DMARC alignment.

**How to verify DMARC passes:**
1. Send a test email through the configured SMTP provider to an address on a mail service that publishes
   DMARC results in headers (e.g. a Gmail address), or use a DMARC-testing service
   (e.g. `mail-tester.com`, or the provider's own DMARC test tool).
2. Inspect the received message's `Authentication-Results` header: it should show `dmarc=pass` (and, feeding
   into that, `spf=pass` and `dkim=pass` for the sending domain).
3. Separately confirm the DNS records themselves resolve as expected: `dig TXT golfraven.<tld>` should show
   the SPF record (`v=spf1 ...`), `dig TXT _dmarc.golfraven.<tld>` should show the DMARC policy
   (`v=DMARC1; p=...`), and the provider-specific DKIM selector TXT record should resolve
   (`dig TXT <selector>._domainkey.golfraven.<tld>`).

**P0 acceptance test satisfied:** "SMTP passes a DMARC check" (plan §10 P0 AT(5)).

## 8. Bundle-ID reservation

**What:** Reserve the iOS and Android bundle/application IDs for `apps/mobile` under the organisation store
accounts.

**Done when:** Both identifiers are reserved (even before the app is built) so they cannot be squatted.

**P0 acceptance test satisfied:** Not separately numbered in §10 P0 AT(1)–(6), but listed as a P0 non-gating
deliverable ("Bundle IDs reserved," plan §10 P0).

## 9. Supabase project (region per the plan)

**What:** Create the Supabase project(s) referenced in §3.7: `gr-staging` and eventually `gr-prod`. The plan
lists prod as **"NA region `[unverified — training knowledge]`"** — it does not commit to a specific
sub-region (e.g. `us-east-1` vs a Canada-adjacent region); that choice is made at project-creation time and is
not pre-decided in the plan. Given Law 25 (Québec) data-residency sensitivity noted elsewhere in the plan
(§7.8), weigh a Canada-adjacent region if one is offered, but this is **not** a plan-mandated choice — record
whichever is picked and why.

**Done when:** The project exists, PostGIS can be enabled on it (feeds X7 directly), and its region is
recorded.

**P0 acceptance test satisfied:** Feeds X7 (`docs/p0/X7.md`); the region/DPA review itself is a **P3
pre-build gate** item ("Supabase region + DPA reviewed," plan §10 — reviewed again before P3, since money
and personal data go live only after P3), but the project itself is created in P0/P1.

**Note:** `supabase.com` returned a proxy 403 in this session — project creation may need the network-unblock
step (`docs/owner/network-unblock.md`) if attempted from this environment.

## 10. Cloudflare account

**What:** A Cloudflare account for Cloudflare Pages hosting (the site's chosen host per §3.4/§3.7; SWC itself
is on GitHub Pages currently, per X3 — GolfRaven's own site moves to Cloudflare Pages).

**Done when:** The account exists and a Pages project is ready to receive the P2 site build (not itself a P0
blocker — the landing page for K2 needs *somewhere* to be hosted, which may be this account or a simpler
interim host).

**P0 acceptance test satisfied:** Supports AT(5) indirectly (the domain needs to resolve to something) and
the §5.2 build-budget gates checked at X5 (Cloudflare Pages file/`_redirects`/file-size limits).

**Note:** `developers.cloudflare.com` returned a proxy 403 in this session (relevant if consulting Cloudflare
Pages docs from this environment) — see `docs/owner/network-unblock.md`.
