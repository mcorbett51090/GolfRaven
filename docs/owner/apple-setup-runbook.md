# Apple setup runbook

Owner-facing, ordered. It turns every Apple-dependent item this repository expects into steps you can do on the
organisation Apple Developer account. It does **not** mark anything done: the status of each item stays in
`docs/owner/accounts-and-domain-checklist.md` (§3, §5, §8 point here).

**How to read it.**

- Every statement about this repository cites `file:line`. Every statement about Apple's portal, App Store Connect
  or EAS that was **not** checked in this repo is tagged `[unverified — training knowledge]`. Apple's screens
  change often, so this runbook gives the _intent_ and the _item name_ rather than click paths. If a name has
  moved, find the nearest equivalent and keep the intent.
- "Plan" means `docs/golf-trails/02-build-plan.md` in the RavenGolf repo (the same convention as the root
  `README.md:8-10`); `02-build-plan.md:NNN` cites a line in it. It is a different repository from this one.
- Placeholders: `<TEAM_ID>`, `<KEY_ID>`, `<SIWA_KEY_ID>`, `<DEVICECHECK_KEY_ID>`, `<PROJECT_REF>`. The real values
  never appear in this repository (it is public).
- Numbered steps are in dependency order: nothing waits on a step that comes later, except where a step says
  "blocked on" and names what.

## Secrets: where they live, and where they never go

| Secret                                               | Lives in                                                                                                                            | Never in                                                                               |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Sign in with Apple `.p8` key                         | A password manager or vault you control (the file), and the Supabase Edge Function secret `GR_APPLE_SIWA_PRIVATE_KEY`              | The repo, CI logs, any `EXPO_PUBLIC_*` variable, EAS build env, chat, tickets          |
| DeviceCheck `.p8` key                                | The same kind of vault, and the Supabase Edge Function secret `GR_APPLE_DEVICECHECK_PRIVATE_KEY`                                    | Same list                                                                              |
| Supabase Auth Apple client-secret JWT (≤ 6 months)   | Pasted into the Supabase Auth Apple provider settings only; keep a copy in the vault until it is re-minted                           | Same list                                                                              |
| App Store Connect API key / distribution certificate | EAS credential storage or your vault (Step 5)                                                                                       | Same list, and not a committed `credentials.json`                                      |
| Team ID, Key IDs                                     | Not secret in Apple's model, but this repo is public: they go in the Supabase secrets below and in your own notes, **not** in git  | The repo (this runbook uses placeholders on purpose)                                   |
| Bundle ID `com.golfraven.app`                        | Public: it is already in the repo (`apps/mobile/app.json:25`) and in the store listing                                              | n/a (nothing to protect)                                                               |

Why this holds in code, not just in prose:

- The server reads Apple configuration only from the Edge Function environment, in one file
  (`supabase/functions/_shared/privileged.ts:2814`, `:2849`, `:2962`, `:2997`). Its own header says the DeviceCheck
  and Google keys "live ONLY in the environment; nothing in this repository carries one"
  (`supabase/functions/_shared/privileged.ts:2807-2808`).
- The mobile app refuses secret-shaped `EXPO_PUBLIC_*` values (`apps/mobile/README.md:160-162`); the same guard is
  EAS Build's pre-install hook (`apps/mobile/package.json:14`). That guard catches Supabase-style keys. It does not
  know what an Apple `.p8` is, so **do not put an Apple key in any `EXPO_PUBLIC_*` or EAS env variable at all**:
  the app has no use for one.
- `.gitignore` now lists `*.p8`, `AuthKey_*.p8`, `*.p12`, `*.mobileprovision`, `*.cer`, `*.pem`, `*.jks`, `*.keystore` and
  `credentials.json`
  (it covered only `.env*` before; "Repo inconsistencies" item 8, fixed). gitleaks' default `private-key` rule
  (`.gitleaks.toml` adds no allowlist for PEM blocks) is the backstop: it flagged a runtime-generated key in four forms
  (a `.p8` file, plain text, and a one-line literal-`\n` key in `.env` and in JSON) when checked.
- The `.p8` download is offered **once** by Apple `[unverified — training knowledge]`. Save it to the vault before
  closing the page, then **delete the downloaded copy** (the Downloads folder, and empty the trash) and make sure it
  is not in a cloud-synced or backed-up folder. Keep working copies only in the vault.

### Handing a key to Supabase or to the mint tool without it touching a command line

A key (or the JWT minted from it) on a command line is visible to every user on the machine through `ps` and
`/proc/*/cmdline`, and lands in shell history. So **nowhere in this runbook does a key appear in a command's
arguments**, and you should not improvise one (for example substituting the key file's contents into a `supabase secrets set`
command with `$(...)` puts the whole key on that process's argv; do not do that). Use one of these, in this order of preference:

1. **The Supabase dashboard secret field** (Edge Functions, secrets): paste the key's contents. No command line is
   involved. `[unverified — training knowledge on the current dashboard layout]`.
2. **A secrets file read by the CLI**, written with mode 0600 in a throwaway directory **outside the checkout**, then
   deleted. The `--env-file` flag of `supabase secrets set` is `[unverified — training knowledge]`; confirm it with
   `supabase secrets set --help` first. The key is written as one line with a literal `\n` for each line break, which
   both shared parsers accept (`_shared/pem.ts`):

   ```sh
   (   # a subshell: the umask does not leak into your shell, and the trap cleans up even if a command fails
     umask 077
     ENVDIR="$(mktemp -d)"           # mode 0700, outside the checkout
     trap 'rm -rf "$ENVDIR"' EXIT    # delete the directory and file when this subshell ends, success or not
     printf 'GR_APPLE_SIWA_PRIVATE_KEY="%s"\n' "$(awk 'NF{printf "%s\\n",$0}' <path-to-the-AuthKey-p8-in-your-vault>)" > "$ENVDIR/secrets.env"
     supabase secrets set --env-file "$ENVDIR/secrets.env" --project-ref <PROJECT_REF>   # flag name [unverified]
   )
   ```

   `printf` is a shell builtin, so the key is not in any child process's arguments (the only argument `awk` sees is the
   file path); that holds for bash and zsh `[unverified for other shells; use the dashboard if unsure]`. Whether the
   CLI expands the `\n` inside the quotes or passes it through literally does not matter to this server: both forms
   parse. Secure deletion of a file on a modern disk is best-effort; the directory is 0700 and short-lived, which is
   the real protection.
3. **For the mint tool (Step 2.4):** pipe the key from your password manager's command-line tool into the tool's
   stdin (`--key-file -`), or give it a 0600 file outside the checkout. Never a path inside the checkout, and never
   the Downloads folder.

## Value map (read this first)

Every Apple-dependent value, what it is called in this repo, where it is stored, and who reads it. "Supabase secret"
means a Supabase Edge Function secret for the project (staging and production are separate projects and take
separate values; plan §3.7, `02-build-plan.md:450-457`).

| Value                                       | Created in (Apple/other)                          | Name it goes into                                          | Stored where                                       | Read by                                                                                                          | If unset or wrong                                                                                                                                  |
| ------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Team ID                                     | Developer portal, membership details              | `GR_APPLE_TEAM_ID`                                         | Supabase secret                                    | `privileged.ts:2818`, `:2850`, `:2963`, `:2998`                                                                   | All Apple paths unconfigured (rows below)                                                                                                          |
| Bundle ID `com.golfraven.app`               | Developer portal, Identifiers                     | `GR_APPLE_BUNDLE_ID`                                       | Supabase secret                                    | `privileged.ts:2819`, `:2851`, `:2964`                                                                            | Same. Whitespace in team or bundle id also counts as unconfigured (`privileged.ts:2852`, `:2966`)                                                   |
| (same bundle ID, app side)                  | already in the repo                               | `ios.bundleIdentifier` in `apps/mobile/app.json:25`        | git (it is public)                                 | Expo prebuild                                                                                                     | A different value on either side breaks App Attest (`rpIdHash`, `app-attest-registration` step 5, `p3-money-path-requirements.md:2671`)            |
| SIWA client id (native flow)                | = the bundle ID                                   | `GR_APPLE_SIWA_CLIENT_ID`                                  | Supabase secret                                    | `privileged.ts:2999`                                                                                              | `me-signin-methods`, `me-delete`, `signin-revocation-drain`: Apple unconfigured (see below)                                                         |
| SIWA key ID                                 | Developer portal, Keys                            | `GR_APPLE_SIWA_KEY_ID`                                     | Supabase secret                                    | `privileged.ts:3000`                                                                                              | Same                                                                                                                                               |
| SIWA private key (`.p8` contents)           | Developer portal, Keys (one-time download)        | `GR_APPLE_SIWA_PRIVATE_KEY`                                | Supabase secret (plus your vault)                  | `privileged.ts:3001` then `_shared/pem.ts:21-37`                                                          | Blank: unconfigured. Not a valid PKCS#8 PEM or not a P-256 key: fails on first use (`apple-client-secret.ts:56-63`)                                |
| App Attest environment (server)             | Your decision (Step 3.1)                          | `GR_APPLE_APPATTEST_ENV` = `production` or `development`  | Supabase secret                                    | `privileged.ts:2965`                                                                                              | Any other value or unset: `devices-attest-key` answers 503 `attestation_not_configured` (`privileged.ts:2967`, `devices-attest-key/index.ts:39`) |
| App Attest environment (build)              | Your decision (Step 3.1)                          | `GOLFRAVEN_APP_ATTEST_ENV` = `development` or `production` | EAS build profile env or the shell running prebuild | `modules/golfraven-attest/app.plugin.js:17-21`                                                                    | Unset: `production`. Any other value: the prebuild throws                                                                                          |
| DeviceCheck key ID                          | Developer portal, Keys                            | `GR_APPLE_DEVICECHECK_KEY_ID`                              | Supabase secret                                    | `privileged.ts:2820`                                                                                              | `rewards-activate` on iOS: 503 `attestation_not_configured` (`activate-handler.ts:201`)                                                            |
| DeviceCheck private key (`.p8` contents)    | Developer portal, Keys (one-time download)        | `GR_APPLE_DEVICECHECK_PRIVATE_KEY`                         | Supabase secret (plus your vault)                  | `privileged.ts:2821` then `_shared/pem.ts:21-37`                                                                  | Same. Real line breaks or one line with a literal `\n` per break are both accepted (one shared parser, Repo inconsistencies item 3, fixed)                                                       |
| DeviceCheck environment                     | Your decision D1 (Step 3.1)                         | `GR_APPLE_DEVICECHECK_ENV` = `production` or `development` | Supabase secret                                    | `privileged.ts:2822`, host chosen at `devicecheck-client.ts:63-66`                                                | Anything else: unconfigured                                                                                                                        |
| Supabase Auth Apple provider fields         | Supabase dashboard                                | client id(s), team id, key id, client-secret JWT           | Supabase Auth settings (dashboard), not git        | GoTrue inside Supabase, see `p3-money-path-requirements.md:2988-2990`                                             | Native Apple sign-in does not work                                                                                                                 |
| Client-secret JWT (≤ 6 months)              | You mint it locally from the SIWA `.p8` (Step 2.4) | (pasted into the dashboard field above)                    | Dashboard, plus vault copy                         | Monthly check `tools/apple/check-siwa-secret-expiry.mjs:1-12`                                                    | After expiry Auth's Apple sign-in fails; the server's own 10-minute secrets are unaffected (`apple-client-secret.ts:13-14`)                        |
| Apple App Attestation Root CA               | Not configuration: **pinned in code**             | none (there is no variable)                                | git: `_shared/rewards/apple-app-attest-root.ts:27-41` | `privileged.ts:2967`                                                                                              | n/a. Step 3.2 is the human check that the pinned bytes are really Apple's                                                                          |

Two names you may have been given do **not** exist as variables: `GR_APPLE_APPATTEST_ROOT` and
`GR_APPLE_TRUST_ANCHOR`. The only mentions anywhere in the repo are a test that sets them to prove they are
**ignored** (`supabase/tests/integration/attest-key.deno.test.ts:398-403`). The trust anchor is "not configuration:
it is Apple's root, pinned in code" (`privileged.ts:2960-2961`). Do not create these as Supabase secrets.

### What each Edge Function needs

Copied from the repo's own table (`docs/security/edge-role-design.md:869-874`) and re-checked against the loaders:

| Function                  | Apple values it reads                                                                                                                               | Loader                                |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `devices-attest-key`      | `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID`, `GR_APPLE_APPATTEST_ENV`                                                                                  | `privileged.ts:2962-2968`             |
| `checkin-token`           | `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID` only (verification, no DeviceCheck credential)                                                             | `privileged.ts:2849-2853`             |
| `rewards-activate`        | `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID`, `GR_APPLE_DEVICECHECK_KEY_ID`, `GR_APPLE_DEVICECHECK_PRIVATE_KEY`, `GR_APPLE_DEVICECHECK_ENV`             | `privileged.ts:2814-2829`             |
| `me-signin-methods`       | the four: `GR_APPLE_TEAM_ID`, `GR_APPLE_SIWA_CLIENT_ID`, `GR_APPLE_SIWA_KEY_ID`, `GR_APPLE_SIWA_PRIVATE_KEY`                                        | `privileged.ts:2997-3004`             |
| `me-delete`               | the same four SIWA values (unset: grants stay queued for the 72 h retry, `me-delete/index.ts:29`)                                                    | `me-delete/index.ts:30`               |
| `signin-revocation-drain` | the same four SIWA values                                                                                                                           | `signin-revocation-drain/index.ts:18` |

Each function builds its configuration **once per cold start** (`devices-attest-key/index.ts:28-29`,
`me-signin-methods/index.ts:22`, `signin-revocation-drain/index.ts:18`). After you change a secret, whether a
running instance picks it up without a redeploy is `[unverified — training knowledge]`; redeploy the function if a
probe in Step 6 still shows the old behaviour.

A half-set Apple configuration is "not configured", never a default: every variable of a path must be present and
non-empty (`privileged.ts:2802-2805`).

---

## Step 1. Team and identifiers

### 1.1 Confirm the organisation enrolment and record the Team ID

- **Where:** Apple Developer portal, account/membership details `[unverified — training knowledge]`.
- **What:** Confirm the enrolment is approved and active under the operating entity's name. That is checklist §3
  (`docs/owner/accounts-and-domain-checklist.md:35-41`). It needed a D-U-N-S number (checklist §2, `:23-33`). Note
  the 10-character **Team ID**.
- **Goes into:** the Supabase secret `GR_APPLE_TEAM_ID` (Step 3.4) and your own vault note. Not git.
- **Verify:** the portal shows the account as active and the entity name matches the legal entity (plan P0 AT(5),
  checklist `:41`).

### 1.2 Register the App ID `com.golfraven.app`

- **Where:** Developer portal, Certificates, Identifiers & Profiles, Identifiers `[unverified — training knowledge]`.
- **What:** Register an **explicit** App ID (not a wildcard) with bundle identifier `com.golfraven.app`. This is the
  value in `apps/mobile/app.json:25` (iOS) and `:11` (Android package, same string). The URL scheme is `golfraven`
  (`apps/mobile/app.json:5`); it needs nothing from Apple.
- **Capabilities to enable on the App ID:**

  | Capability              | Needed because                                                                                                                                                                                                                       |
  | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
  | Sign in with Apple      | The app's generated entitlements include `com.apple.developer.applesignin` = `Default` (`apps/mobile/test/support/policy-scan.ts:65`; the plugin is `expo-apple-authentication`, `apps/mobile/app.json:48`, `apps/mobile/README.md:145-146`) |
  | App Attest              | The local config plugin writes `com.apple.developer.devicecheck.appattest-environment` (`apps/mobile/modules/golfraven-attest/app.plugin.js:14`, `policy-scan.ts:66`). Whether the portal also needs an explicit App Attest capability toggle on the App ID is `[unverified — training knowledge]`; if the build or the review complains about a missing capability, enable it here |
  | DeviceCheck             | **No capability.** DeviceCheck needs only a key (Step 3.3) `[unverified — training knowledge]`                                                                                                                                       |

- **Capabilities to leave OFF:** HealthKit, Push Notifications, Associated Domains. The policy test allow-lists only
  the two entitlements above (`policy-scan.ts:62-67`) and says a new entitlement "is added here on purpose, in
  review". Push is not built: `expo-notifications` is not installed
  (`apps/mobile/src/push/index.ts:4-8`, `apps/mobile/README.md:122-123`), so **no APNs key is needed yet**. HealthKit
  is not used on iOS (Android Health Connect only, `apps/mobile/app.json:12`); counsel L7 must sign before the first
  HealthKit read ships (plan `02-build-plan.md:2790`).
- **Goes into:** `GR_APPLE_BUNDLE_ID=com.golfraven.app` (Step 3.4). If EAS manages signing, it can also create and
  sync the App ID itself `[unverified — training knowledge]`; if you register it by hand, keep the capabilities
  identical to the table.
- **Verify:** the Identifiers list shows `com.golfraven.app` with exactly the capabilities above.

### 1.3 Bundle-ID reservation (checklist §8, Apple half)

- **What:** checklist §8 wants both the iOS and Android IDs reserved "even before the app is built" so they cannot be
  squatted (`docs/owner/accounts-and-domain-checklist.md:103-113`).
- **Apple half:** registering the App ID (1.2) and creating the App Store Connect record (Step 4.1) is what holds the
  identifier and name `[unverified — training knowledge: that an App ID alone, without an app record, reserves the
  name]`.
- **Android half:** the same string `com.golfraven.app` (`apps/mobile/app.json:11`) is reserved in Google Play
  Console. **Blocked on** the Google Play organisation account (checklist §4, `:45-54`). This runbook does not cover
  it.
- **Verify:** both stores list the identifier under the organisation account.

---

## Step 2. Sign in with Apple

Why it exists: Google sign-in ships at launch, which makes Sign in with Apple mandatory in every build that offers
Google (Apple 4.8; plan `02-build-plan.md:397`, `:1870`; AT 17 at `:2789`). The app uses the **native** flow on iOS:
`signInAsync` with the email scope only and a hashed nonce (`apps/mobile/src/signin/apple-expo.ts:20`), then Supabase
`signInWithIdToken` (`apps/mobile/src/signin/flow.ts:90`) and a `link` call to hand the server the authorization code
(`apps/mobile/src/signin/flow.ts:96`) so the grant can be revoked on deletion.

### 2.1 App ID capability

Done in Step 1.2. Nothing more to create for the native iOS flow.

### 2.2 Create the Sign in with Apple key and record its ID

- **Where:** Developer portal, Keys `[unverified — training knowledge]`.
- **What:** Create a key, tick **Sign in with Apple**, and choose `com.golfraven.app` as the primary App ID
  `[unverified — training knowledge]`. Download the `.p8` once, store it in the vault, delete the downloaded copy (see
  "Handing a key to Supabase or to the mint tool" above). Record the **Key ID**.
- **Use a separate key from DeviceCheck (Step 3.3).** The repo reads two independent variable sets for them
  (`GR_APPLE_SIWA_*` and `GR_APPLE_DEVICECHECK_*`, `privileged.ts:2998-3001` vs `:2765-2769`), so separate keys keep
  a leak or a revocation of one from touching the other. Whether Apple allows one key to carry both services, and
  how many keys an account may hold, is `[unverified — training knowledge]`.
- **Goes into:**

  | Value                 | Variable                      | Format the code expects                                                                                                                                                                                                                                                                                  |
  | --------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | Key ID                | `GR_APPLE_SIWA_KEY_ID`        | Plain string, trimmed (`privileged.ts:3000`)                                                                                                                                                                                                                                                             |
  | `.p8` contents        | `GR_APPLE_SIWA_PRIVATE_KEY`   | The whole file: one PKCS#8 `PRIVATE KEY` block (`BEGIN PRIVATE KEY` ... `END PRIVATE KEY`). Real line breaks or one line with literal `\n` are both accepted (`apple-client-secret.ts:31`, `_shared/pem.ts:21-37`). It must be an **EC P-256** key (`apple-client-secret.ts:60`)                                                              |
  | Team ID               | `GR_APPLE_TEAM_ID`            | Plain string, trimmed (`privileged.ts:2998`)                                                                                                                                                                                                                                                             |
  | Client ID (native)    | `GR_APPLE_SIWA_CLIENT_ID`     | `com.golfraven.app`. It is the identity token's audience for the native flow (`privileged.ts:2992`, `p3-money-path-requirements.md:2981`)                                                                                                                                                                |

- **How the server uses it:** it mints a 10-minute ES256 client-secret JWT itself from the key (header `kid` = key
  ID; `iss` = team ID; `sub` = client ID; `aud` = `https://appleid.apple.com`), caches it, and re-mints when under 2
  minutes remain (`apple-client-secret.ts:54-73`, `:39-40`, `:76-96`). That is why the key never has to be
  rotated into a long-lived secret on the server side. The JWT claim set is itself `[unverified — training
  knowledge]` until a real key is used (`apple-client-secret.ts:6-8`).
- **Verify:** the key is listed with Sign in with Apple enabled; the `.p8` is in the vault and the downloaded copy is deleted; nothing is in git.

### 2.3 Set the four Supabase secrets

- **Where:** Supabase dashboard, project settings, Edge Functions secrets `[unverified — training knowledge on the current
  UI]`. For the non-secret values (team ID, key ID, client ID) the CLI form `supabase secrets set NAME=value
  --project-ref <PROJECT_REF>` is fine. **For the key, use the dashboard field or the 0600 env-file route** in "Handing a
  key to Supabase or to the mint tool without it touching a command line" (Secrets section above), never a command
  line argument.
- **What:** `GR_APPLE_TEAM_ID`, `GR_APPLE_SIWA_CLIENT_ID`, `GR_APPLE_SIWA_KEY_ID`, `GR_APPLE_SIWA_PRIVATE_KEY`
  (`p3-money-path-requirements.md:2978-2983`, deploy step 2 at `:2995`).
- **The key never goes on a command line or into shell history or a CI log** (see the Secrets section).
- **Order matters for deletion:** an account deleted while Apple is unconfigured queues its Apple grant as
  `not_configured_apple` and the queue gives up after **72 hours** (`me-delete/index.ts:29`,
  `signin-revocation-drain/index.ts:3`, `p3-money-path-requirements.md:2945`). Set these before the first real
  Apple-signed-in account can exist in that project.
- **Verify:** Step 6, probes P2 and P3.

### 2.4 Configure Supabase Auth's own Apple provider, and mint its client secret

This is a **dashboard step, documented but not built** (`privileged.ts:2994-2996`,
`p3-money-path-requirements.md:2988-2990`).

- **Where:** Supabase dashboard, Authentication, Providers, Apple `[unverified — training knowledge]`.
- **What:**
  1. Enable the Apple provider.
  2. Client id: `com.golfraven.app` (the bundle ID for the native flow). Put the **same** client id in
     `GR_APPLE_SIWA_CLIENT_ID` (`p3-money-path-requirements.md:2989-2990`).
  3. Team ID, Key ID and a pre-generated client-secret JWT valid for at most six months (the repo's wording;
     Apple's exact maximum is `[unverified — training knowledge]`).
- **Confirm you need this secret before minting it.** For a **native-only** Sign in with Apple flow (iOS
  `signInWithIdToken`, which is all this app does today, `apps/mobile/src/signin/flow.ts:90`; Android and web SIWA are
  not built, Step 2.5), Supabase Auth may not need a client secret at all: the secret is used when Auth itself talks to
  Apple's token endpoint for the browser/OAuth flow, and a native id-token sign-in only verifies the token's audience
  `[unverified — training knowledge]`. Settle this in the P4 library spike (plan `02-build-plan.md:397`, A77) **before**
  minting a long-lived credential for nothing. If the spike shows the provider accepts the native flow without a
  secret, skip this whole step and the monthly check, and note that in your records. The server's own secret
  (`GR_APPLE_SIWA_*`) is independent and still needed for the token exchange and revocation (Step 2.3).
- **Minting the JWT.** Use the repo's operator tool `tools/apple/mint-siwa-client-secret.mjs` (sibling of the expiry
  checker; Node 24 or newer, because it imports the server's own TypeScript signer so the claims cannot drift):

  ```sh
  node tools/apple/mint-siwa-client-secret.mjs --team-id <TEAM_ID> --key-id <SIWA_KEY_ID> \
    --client-id com.golfraven.app --lifetime-days 150 --key-file <path-to-a-0600-copy-OUTSIDE-the-checkout>
  # or, from the password manager (no key file on disk, nothing on argv except a path or a pipe):
  #      <your password manager's CLI: print the key> | node tools/apple/mint-siwa-client-secret.mjs ... --key-file -
  ```

  What it guarantees (each is pinned by `supabase/tests/unit/mint-siwa-client-secret.test.ts`): the key is read only
  from a file path or stdin, never from the command line (an argument that looks like a key is refused); it writes
  nothing to disk and prints no key material; only the JWT goes to stdout (messages go to stderr; Node may print a
  harmless "module type" warning there); the lifetime is capped at **180 days** and a larger value is refused rather
  than clamped (default 150; Apple's exact maximum is `[unverified — training knowledge]`, 180 days sits under any
  reading of "six months"). Exit codes: 0 minted, 1 the key is not a PKCS#8 P-256 key, 2 bad usage.
  The output **is a secret**: paste it straight into the dashboard field, keep one copy in the vault, clear the
  terminal scrollback, and do not redirect it into a file inside the checkout.
- **Calendar the re-mint** (at most every six months, in practice every ~5), if you minted one. Run the repo's check
  monthly, giving it the JWT on **stdin** so the secret never appears in your shell history or `ps` (the checker reads
  stdin, `tools/apple/check-siwa-secret-expiry.mjs:11`):

  ```sh
  <your password manager's CLI: print the stored JWT> | node tools/apple/check-siwa-secret-expiry.mjs [--warn-days 30]
  ```

  Do **not** use the script's `APPLE_SIWA_CLIENT_SECRET_JWT=<jwt> node ...` env-var form: the secret would be
  in the shell history. Exit 0 means more than 30 days remain; exit 1 means expired, expiring, malformed or no `exp`;
  exit 2 means no input (`tools/apple/check-siwa-secret-expiry.mjs:1-12`, `p3-money-path-requirements.md:3004-3010`). It is **not
  scheduled** anywhere (`p3-money-path-requirements.md:3009-3010`); a calendar reminder is the owner's half.
- **Decide before launch (not an Apple step):** GoTrue links same-verified-email identities by default
  `[unverified — training knowledge]`, which would defeat plan rule (2) at the sign-in moment. The P4 spike must turn
  automatic linking off or route the first social sign-in through a pre-check
  (`p3-money-path-requirements.md:3033-3040`).
- **Verify:** Step 6, probe P5 (a real Apple sign-in on a TestFlight build), and the monthly check exits 0.

### 2.5 Services ID (Android and web): **not needed by today's code**

- **Repo position:** Sign in with Apple on Android "needs a web flow and a Services ID (server O3)"; the Apple button
  is shown on Android only when Google is offered and then reports "not available on this device"
  (`apps/mobile/README.md:120-121`). Server: "`GR_APPLE_SIWA_CLIENT_ID` is one value today"; a Services ID is "a
  different `aud`" and needs a second audience and a secret whose `sub` is that id
  (`p3-money-path-requirements.md:3019`, `:3054`).
- **So:** there is nothing in the repo to put a Services ID _into_ until that server and client work is built.
  Creating the identifier now is harmless but pointless. Checklist §5 lists it as a P0 deliverable
  (`docs/owner/accounts-and-domain-checklist.md:56-68`); if you want that box ticked for AT(5), create it, record
  its identifier in your vault, and leave it unused.
- **Blocked on the domain (owner question Q1):** a Services ID takes return URLs and a verified domain
  `[unverified — training knowledge]`. The domain is not decided: Q1 is "the partners domain. Confirm the exact
  host" with placeholder `partners.golfraven.<tld>` (`docs/security/partner-auth-design.md:791`), and the primary
  domain is checklist §1 (`:9-21`). Until the host is known, **do not** register return URLs.
- **When unblocked:** the Services ID's identifier needs a second accepted audience in
  `apple-id-token.ts` and a second client id in `GR_APPLE_SIWA_*` handling; that is engineering work, not an owner
  step.

### 2.6 Private-relay email: register the sending domain

- **Why:** with Hide My Email, Apple gives the app an `@privaterelay.appleid.com` address. Mail to it is delivered
  only from a sender domain registered with Apple's relay (plan assumption A78, `02-build-plan.md:3279`, and `:1870`,
  `:2785`: "the private-relay SMTP registration" is in P4.2 scope). The server already treats a relay address as its
  own email (`supabase/functions/_shared/signin/apple-id-token.ts:222`, plan rule (3) at `02-build-plan.md:397`).
- **Where:** Developer portal, the Sign in with Apple "email communication" configuration (Apple's name for it is
  along the lines of "Configure Sign in with Apple for Email Communication") `[unverified — training knowledge]`.
- **What to register:** the domain (or addresses) that Supabase Auth sends OTP mail from. Checklist §7 settles the
  provider as **Resend** on the P0 domain with SPF, DKIM and DMARC published
  (`docs/owner/accounts-and-domain-checklist.md:79-101`). Apple may also require SPF/DKIM alignment before accepting
  the domain `[unverified — training knowledge]`.
- **Goes into:** nothing in the repo or in a secret. It is Apple-side configuration. Record the registered
  domain(s) and the date in the checklist, not in the runbook.
- **Blocked on:** (a) the domain exists (checklist §1), (b) Resend is verified on it with DNS records live (checklist
  §7), and (c) Supabase Auth's custom SMTP points at it. The mail-provider question for _staff security notices_ is
  Q7 (`partner-auth-design.md:797`); it is a separate sender use but the same domain and provider decision, so settle
  them together.
- **Verify:** a test Apple ID using Hide My Email signs in, and the OTP email sent for that account arrives at the
  relay address (AT 17/18 with a relay account; plan `A78` row: "P4 AT(17) with a relay account").

---

## Step 3. App Attest and DeviceCheck

### 3.1 Match the environments: build side and server side

The App Attest entitlement carries either `development` or `production`. The attestation's `aaguid` names the
environment, and the server accepts **exactly one** per deployment (`p3-money-path-requirements.md:2673`).

| Build kind                                     | `GOLFRAVEN_APP_ATTEST_ENV` at prebuild/EAS build | The server project it talks to must have `GR_APPLE_APPATTEST_ENV` |
| ---------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------- |
| App Store build                                | unset or `production`                            | `production`                                                      |
| TestFlight build                               | unset or `production` (README: "App Store / TestFlight") | `production`                                              |
| A development build that must attest (Xcode run or EAS development profile) | `development` | `development`                            |

Sources: `apps/mobile/README.md:90`, `:281`; `modules/golfraven-attest/app.plugin.js:3-9`, `:17-21`;
`privileged.ts:2955-2960`.

- A mismatch is **not** silent: registration is refused with 422 `attestation_rejected` (server-side reason
  `aaguid_mismatch`, logged, `p3-money-path-requirements.md:2810-2817`), then the app backs off registering for 1 hour
  (`apps/mobile/README.md:281`, `:400`), and the device stays `unattestable`.
- **Consequence for staging:** one Supabase project has one `GR_APPLE_APPATTEST_ENV`. Plan §3.7 puts TestFlight
  against `gr-staging` (`02-build-plan.md:456`), and a TestFlight build is `production`. So `gr-staging` should carry
  `production`, and a development-signed build can only attest against a deployment set to `development`. Do not flip
  the staging value to try a development build while testers are on TestFlight.
- `GR_APPLE_DEVICECHECK_ENV` is a **separate** variable on purpose: it names the DeviceCheck API host, not the build
  entitlement (`privileged.ts:2956-2959`: "its own variable ... a property of the app BUILD's entitlement, DeviceCheck's
  is a property of the API host"). "In a normal deployment the two agree" is true for **production**; it is **not** a
  rule for staging. See decision D1 below before you set it. There is no mismatch canary today
  (`p3-money-path-requirements.md:2810-2817`, follow-up F16).

**Decision D1 (owner): which DeviceCheck environment does `gr-staging` use?** Do not default it to the same word as
App Attest. DeviceCheck's two bits are **persistent at Apple, per device**: bit0 means "an account that received a
monetary reward has used this device", set when a reward is activated (plan `02-build-plan.md:1693`;
`rewards/decision-table.ts:15`). If staging talks to Apple's **production** DeviceCheck host, every test activation on a
tester's phone sets bit0 at Apple, a database reset on staging cannot clear it, and when that phone is later used with
a real production account the activation is held for review (`multi_account_device`, `decision-table.ts:120`).
Choose one and write the choice in your notes:

| Option | `gr-staging` `GR_APPLE_DEVICECHECK_ENV` | App Attest for the same project | What it costs |
| --- | --- | --- | --- |
| **A. Recommended default** | `development` | `GR_APPLE_APPATTEST_ENV=production` (TestFlight builds are `production`, `apps/mobile/README.md:90`) | Whether a TestFlight build's DeviceCheck token is accepted by Apple's **development** host is `[unverified — training knowledge]`; a 400 that names the device token becomes a **failed grade, an open `attestation_failed` signal and a held activation** (`devicecheck-client.ts:138`, `activate-handler.ts:347-362`), which looks like a normal "held for review" in the app; a 401, a 403 or any other 400 becomes 503 `attestation_not_configured` (`:137-141`). Test it with probe P8 on one TestFlight device, **including its database check**. If it is rejected, use B or C |
| B. Dedicated test devices | `production` | `production` | Keep a written list of devices that are **used only against staging and never with a production account** (their bit0 will be set). Cheap, but a discipline problem: one slip burns a real tester's phone |
| C. No DeviceCheck on staging | leave the three `GR_APPLE_DEVICECHECK_*` secrets **unset** | `production` | `rewards-activate` on iOS answers 503 `attestation_not_configured` (`activate-handler.ts:201`), so iOS reward activation cannot be exercised on staging. Test it only on option-B devices |

Production (`gr-prod`) always uses `production` for both variables. Keep `GR_APPLE_APPATTEST_ENV=production` on staging in
every option, because that follows the TestFlight build, not DeviceCheck.

### 3.2 App Attest root fingerprint check (follow-up K2 of the App Attest work)

**Naming warning: this is not the K2 landing-page experiment.** In the build plan "K2" is the player-signal landing-page kill experiment
(`02-build-plan.md:2641`). The check here is the **"follow-up K2" of the App Attest work**, defined at
`docs/security/p3-money-path-requirements.md:2693-2702` and `supabase/functions/_shared/rewards/apple-app-attest-root.ts:13-16`.
It is unrelated to the landing page.

**What it is.** Attestation verification trusts one root, pinned in code as base64 DER
(`apple-app-attest-root.ts:29-41`) with its SHA-256 pinned beside it (`:27`). The bytes were fetched on 2026-10-02
from `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem` by an agent behind a
TLS-terminating egress proxy, so they are "what the proxy served for Apple's URL", not an independently authenticated
copy (`apple-app-attest-root.ts:10-16`). A unit test pins the bytes to the constant, so it catches accidental edits
but "cannot tell you the constant was right to begin with" (`:15-16`). **A human must compare the fingerprint with
Apple's before this ships.** The URL above is the repo's own cited source (`apple-app-attest-root.ts:11`).

**Procedure (from a clean personal machine, not through a corporate TLS-inspecting proxy):**

1. Download Apple's root from the repo's cited URL (above) on a clean personal machine. Save it as
   `Apple_App_Attestation_Root_CA.pem`. Note that Apple's "Apple PKI" page, `https://www.apple.com/certificateauthority/private/`
   `[unverified — training knowledge]`, only links the same file from the same origin, so it is the **same source**, not a
   second one.
2. Print its identity and fingerprint:

   ```sh
   openssl x509 -in Apple_App_Attestation_Root_CA.pem -noout -subject -issuer -dates -fingerprint -sha256
   ```

3. Compare with what the repo pins (`apple-app-attest-root.ts:18-22`):

   | Field                  | Pinned value                                                                          |
   | ---------------------- | ------------------------------------------------------------------------------------- |
   | Subject and issuer     | `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California` (self-signed)         |
   | Validity               | 2020-03-18 18:32:53 UTC to 2045-03-15 00:00:00 UTC                                    |
   | SHA-256 of the DER     | `1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32` |

   `openssl ... -fingerprint -sha256` prints colon-separated uppercase hex of the DER, the same form. The repo's
   constant at `apple-app-attest-root.ts:27` is the same value in lowercase without colons.
4. **Pass:** all three match exactly **and** an independent second source agrees. Genuinely independent sources are:
   (a) the same URL fetched from a **different network and device** (for example a phone on mobile data, not the
   machine and network of step 1), so that a single compromised network path or proxy cannot serve both copies; and/or
   (b) the root certificate embedded in a well-known, independently maintained open-source App Attest verifier library,
   at a pinned release, compared by fingerprint `[unverified — training knowledge: that such libraries embed Apple's
   App Attestation root; this runbook does not name one]`. Apple publishing a fingerprint on a documentation page would
   also count `[unverified — training knowledge: whether it does]`. Write down which sources you used.
5. **Fail:** any difference means the pinned root is wrong. Stop. Do not deploy App Attest to production. Open an
   issue; the fix is to replace the bytes and the constant in `apple-app-attest-root.ts` and
   `p3-money-path-requirements.md:2693-2702` together ("there is deliberately no way to do so at run time",
   `apple-app-attest-root.ts:24-25`).
6. Record the result (date, the fingerprint you saw, the sources and networks you used) in your own notes and, if you want it in the
   public repo, as a one-line "verified on <date>" in the runbook's status table below. Do **not** record anything
   else about your machine.

**Optional self-check of the repo itself** (proves the repo's bytes match the repo's constant; it does **not**
prove either is Apple's). Reconstruct the PEM from the embedded base64 lines and fingerprint it. Observed when
writing this runbook: the repo's embedded certificate reproduces exactly the pinned subject, validity, serial and
SHA-256 above.

```sh
CHECKDIR="$(mktemp -d)"   # a temp dir OUTSIDE the checkout (and *.pem is gitignored anyway)
{ echo "-----BEGIN CERTIFICATE-----"
  sed -n '30,41p' supabase/functions/_shared/rewards/apple-app-attest-root.ts | sed -E 's/^ *"//; s/" *\+? *;? *$//'
  echo "-----END CERTIFICATE-----"; } > "$CHECKDIR/repo-root.pem"
openssl x509 -in "$CHECKDIR/repo-root.pem" -noout -subject -issuer -serial -dates -fingerprint -sha256
rm -rf "$CHECKDIR"
```

The unit test `supabase/tests/unit/app-attest-registration.test.ts:373` does the same comparison in CI.

| Check                                   | Result | Date | Who |
| --------------------------------------- | ------ | ---- | --- |
| Pinned Apple App Attestation root verified against Apple | not done | | |

### 3.3 Create the DeviceCheck key

- **Why:** reward activation on iOS reads and sets two persistent bits at Apple's DeviceCheck service, so a
  second-hand or multi-account device reaches a human (plan `02-build-plan.md:1689`, `:1722`;
  `supabase/functions/_shared/rewards/devicecheck-client.ts:3-6`).
- **Where:** Developer portal, Keys, a key with **DeviceCheck** enabled `[unverified — training knowledge]`. Download the
  `.p8` once, store it in the vault and delete the downloaded copy; record the Key ID.
- **Goes into:**

  | Value                | Variable                           | Format the code expects                                                                                                                                                                                                                                                  |
  | -------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
  | Key ID               | `GR_APPLE_DEVICECHECK_KEY_ID`      | Plain string (the JWT header `kid`, `devicecheck-client.ts:114`), trimmed by its loader                                                                                                                                                         |
  | `.p8` contents       | `GR_APPLE_DEVICECHECK_PRIVATE_KEY` | One PKCS#8 `PRIVATE KEY` PEM block, with real line breaks or one line with a literal `\n` per break: the same shared parser as the SIWA key (`_shared/pem.ts`). A non-PEM value makes every call throw not-configured (`devicecheck-client.ts:110-111`). Must be EC P-256 (`devicecheck-client.ts:114-116`) |
  | Environment          | `GR_APPLE_DEVICECHECK_ENV`         | Exactly `production` or `development` after trimming (`privileged.ts:2822`); see decision D1 for which one a project should use. It picks the host: `https://api.devicecheck.apple.com` or `https://api.development.devicecheck.apple.com` (`devicecheck-client.ts:63-66`)                                  |

- **Operational caveats from the code.** A 400 whose body **does** blame the device token makes the activation `failed` (an
  `attestation_failed` signal and a hold, `devicecheck-client.ts:138`); a 400 whose body does not blame it, a 401 or a 403 are all
  turned into 503 `attestation_not_configured` (`devicecheck-client.ts:137-141`), with the server log line
  "attestation vendor is not configured" (`activate-handler.ts:123`). So after you configure DeviceCheck, **a 503 from
  `rewards-activate` on iOS means the key, key ID, team ID or environment is wrong**, not that the player did
  something. Apple's wire contract here is entirely `[unverified — training knowledge]` until a real key is used
  (`devicecheck-client.ts:7-21`).
- **Egress guard.** The DeviceCheck client now refuses any URL that is not `https` on exactly
  `api.devicecheck.apple.com` or `api.development.devicecheck.apple.com` (parsed; no userinfo, no port), refuses to
  follow a redirect (`redirect: "error"`), and keeps its per-call timeout, the same protections the Sign in with Apple
  client gets from `signin/safe-fetch.ts` (`devicecheck-client.ts:68-83`, `:104-136`;
  `supabase/tests/unit/devicecheck-egress.test.ts`). A refusal is a retryable 503-class error. Nothing to configure.
- **Verify:** Step 6, probe P8.

### 3.4 Set the App Attest and DeviceCheck secrets

Set in the same place as Step 2.3 (per project). The key goes in through the dashboard field or the 0600 env-file route
(Secrets section), never a command line:

| Secret                              | Value                                                                  |
| ----------------------------------- | ---------------------------------------------------------------------- |
| `GR_APPLE_TEAM_ID`                  | your Team ID (no whitespace; `privileged.ts:2852`)                     |
| `GR_APPLE_BUNDLE_ID`                | `com.golfraven.app`                                                    |
| `GR_APPLE_APPATTEST_ENV`            | per Step 3.1: `production` or `development`                            |
| `GR_APPLE_DEVICECHECK_KEY_ID`       | `<DEVICECHECK_KEY_ID>`                                                 |
| `GR_APPLE_DEVICECHECK_PRIVATE_KEY`  | the DeviceCheck `.p8` (real line breaks or `\n`-escaped one line)      |
| `GR_APPLE_DEVICECHECK_ENV`          | per decision D1 (Step 3.1): production project `production`; staging `development` by default, **not** automatically the same word as App Attest |

Do not add `GR_APPLE_APPATTEST_ROOT` or `GR_APPLE_TRUST_ANCHOR` (they do nothing; see the value map).

The Android half of the same 503 (`GR_PLAY_*`) is outside this runbook (`apps/mobile/README.md:281`,
`edge-role-design.md:869`, `:871`).

**Verify:** Step 6, probes P1, P7 and P8.

---

## Step 4. App Store Connect

Blocked on Step 1 (the App ID must exist to select it).

### 4.1 Create the app record

- **Where:** App Store Connect, My Apps, new app `[unverified — training knowledge]`.
- **What:**

  | Field                | Value                                                                                                                                                                                                  |
  | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
  | Name                 | The app's name in the repo is `GolfRaven` (`apps/mobile/app.json:3`). Availability of the name is `[unverified — training knowledge]`                                                                  |
  | Bundle ID            | `com.golfraven.app` (pick from the list created in 1.2)                                                                                                                                                 |
  | SKU                  | Your own internal identifier; any unique string `[unverified — training knowledge]`. Not referenced anywhere in the repo, so invent one and keep it in your notes                                       |
  | Primary language     | English; the app also ships French Canadian (`apps/mobile/app.json:32`, `:62-64`). Which is the store's primary is your decision                                                                    |
- **Goes into:** nothing in the repo. The numeric Apple ID the record gets is needed only if you later configure EAS
  Submit `[unverified — training knowledge]`; store it in your notes.
- **Verify:** the record appears under the organisation team with bundle ID `com.golfraven.app`.

### 4.2 TestFlight internal testing

- **Where:** App Store Connect, the app, TestFlight `[unverified — training knowledge]`.
- **What:** Add yourself and other App Store Connect users as **internal testers**; internal groups can receive
  builds without beta review `[unverified — training knowledge]`. External testers need beta review and are not
  needed for the field test.
- **Depends on:** a processed build (Step 5.5).
- **Verify:** the build shows "Ready to test" and installs from the TestFlight app on a physical iPhone. App Attest
  does not work on a simulator (`apps/mobile/README.md:407-408`), so the field test needs a real device
  (`apps/mobile/README.md:293`, `:282`).

### 4.3 The review account (plan AT 14)

- **Requirement:** "The review account can sign in and cannot receive a reward" (AT 14, plan
  `02-build-plan.md:2789`). Apple 2.1: "one `app-review` account whose OTP is delivered to a monitored reviewer inbox.
  It has no partner scope, can receive no offer or special marker, audits every sign-in, and is disabled outside
  submission windows" (plan `02-build-plan.md:1871`).
- **What the repo has:** the table `app.app_review_demo_account (user_id)` (`supabase/migrations/0007_private_helpers.sql:23-25`);
  `private.is_demo_account` (`:42-47`); the reward activation refusal, 403 `forbidden`, before any reward is read
  (`supabase/functions/_shared/rewards/activate-handler.ts:271`; proved at
  `supabase/tests/integration/rewards-activate.deno.test.ts:239-251`); the partner-route refusal
  (`docs/security/partner-auth-design.md:211`); and an own-row read for the actor
  (`supabase/migrations/0031_edge_role_policies.sql:468`).
- **What the repo does not have:** a provisioning script or procedure for creating the demo row; any mechanism that
  "audits every sign-in" or "disables outside submission windows". A search of `supabase/functions`,
  `apps/mobile/src` and `docs` found only the table, the refusals and tests. Those two plan behaviours are
  **unbuilt** and are tracked as a P4.2 pre-submission item (Repo inconsistencies, item 6;
  `docs/security/p3-money-path-requirements.md`, the "Tracked gap" note under the activation handler).
- **Which project:** the real reviewer account lives in the **production** project (Apple reviews the store build, which
  points at production). A TestFlight build points at **staging** (plan `02-build-plan.md:456`), so it cannot see a
  production-only demo row. Do the steps below **twice**: first against `gr-staging` with a staging-only reviewer address
  for a dry run on TestFlight, then against production for the real one.
- **Owner steps, when the staging project and mail provider exist** (do not do these in the repo; run steps 2 and 3 once
  per project as described above):
  1. Choose a dedicated, monitored mailbox for the reviewer account. Keep the address out of the repo.
  2. Sign that address in once through the app's email-OTP flow (`apps/mobile/src/auth/supabase-auth.ts:210-213`)
     against the project in question (staging for the dry run, production for the real account) so an Auth user exists.
  3. As a service-role/admin database role, insert that user's id into `app.app_review_demo_account`
     (`0007_private_helpers.sql:23-25`; `service_role` holds INSERT on it, `supabase/migrations/0009_grants_revokes.sql:56`). The row is what makes the account a demo account.
  4. In App Store Connect, App Review Information, give the reviewer the sign-in instructions and a note that the
     code goes to the monitored inbox, and that guest browse works with no account (plan `02-build-plan.md:1872`)
     `[unverified — training knowledge: the exact field names]`.
  5. After the review window, remove the row or disable the Auth user, since "disabled outside submission windows"
     is not automated.
- **Blocked on:** Supabase production project, custom SMTP (checklist §7), and a submitted build.
- **Verify:** sign in as the staging reviewer on a TestFlight build (staging); Wallet activation, if flagged on, answers
  403 `forbidden` (`activate-handler.ts:271`). Repeat on a production-pointed build for the real reviewer account
  before submission.

### 4.4 Privacy ("nutrition") label inputs

The repo cannot say what Apple will accept, and the README says to "decide the exact data types with the privacy
owner" (`apps/mobile/README.md:278`, `:296`). This table lists **what the code collects or sends**, not the label
answers. Mapping each row to Apple's categories, "linked to identity", "used for tracking" and purposes is a decision
for the owner and counsel; do not copy a mapping from here.

| Data the code handles                                                                  | Where in the code                                                                                                                                                                               | Status today                                                                                                                  |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Email address (email OTP; Apple email scope)                                           | `apps/mobile/src/auth/supabase-auth.ts:210-213`; `apps/mobile/src/signin/apple-expo.ts:20` (EMAIL scope only, no name); server `signin/apple-id-token.ts:222`                                      | In the build                                                                                                                  |
| Apple account identifier (`sub`) and an encrypted Apple refresh token (for revocation) | `supabase/functions/_shared/signin/apple-client.ts:54-76`; envelope encryption at `p3-money-path-requirements.md:2926`                                                                       | In the build, server side                                                                                                     |
| Precise location, foreground only (lat, lng, accuracy, time)                           | `apps/mobile/src/evidence/payload.ts:39-48`; `apps/mobile/src/checkin/expo-location.ts:4-7`, `:57`; usage string at `apps/mobile/app.json:38`                                                    | Behind `CHECKIN_UI_ENABLED = false` (`apps/mobile/src/features.ts:13`)                                                        |
| Device identifiers for fraud prevention: the DeviceCheck token, the App Attest key id  | `apps/mobile/README.md:278`, `:340`; server stores a hash (`privileged.ts:2673`)                                                                                                                  | Behind the check-in and Wallet flags (`features.ts:13`, `:29`)                                                                |
| A random device id (UUID) for the install                                              | `apps/mobile/src/evidence/payload.ts:113`                                                                                                                                                         | In the build                                                                                                                  |
| Birth year                                                                             | **Not stored or sent**: only a device-local "not eligible" flag (`apps/mobile/src/age/gate.ts:8`, `:18`)                                                                                          | In the build                                                                                                                  |
| Push token                                                                             | `apps/mobile/src/api/http-client.ts:350-352`                                                                                                                                                      | **Not collected**: `expo-notifications` is not installed (`apps/mobile/src/push/index.ts:4-8`)                                |
| Health data                                                                            | Android Health Connect `ExerciseSession` read for the X1 check (`apps/mobile/app.json:12`); **no iOS HealthKit** (`policy-scan.ts:62-67`)                                                          | Developer-tools panel only, output rendered on screen (`apps/mobile/README.md:467-470`, `docs/p0/gate-review.md:54`)         |
| Ads, analytics SDKs                                                                    | None; AT(7) "No ads or analytics SDK in the lockfile" (plan `02-build-plan.md:2789`)                                                                                                              | n/a                                                                                                                           |

Cross-reference to the README's "Before flipping the flags" list (`apps/mobile/README.md:271-282`): the label item
there is "update it to match what the build collects once attestation is reachable" (`:278`) and the location one is
"Precise Location: collected, linked to the user's identity ... used for App Functionality and Other purposes: fraud
prevention, not used for tracking" (`:296`). Treat those wordings as the repo's **proposal**, to be confirmed. The
server-side reference for what is stored is `docs/security/p3-money-path-requirements.md`.

Store-side items the plan puts in P4.2 that are **not** Apple label answers but need an owner: privacy policy and
terms in English and French (plan `02-build-plan.md:2785`, `:2788`; blocked on the domain and on counsel), the export
compliance question about encryption `[unverified — training knowledge; the app ships its own crypto via
@noble/curves and @noble/hashes, apps/mobile/package.json:21-22]`, and the age-rating questionnaire
`[unverified — training knowledge]`. The in-app deletion Apple 5.1.1(v) asks for exists (plan `02-build-plan.md:1875`, AT(6)/(19) at `:2789`).

---

## Step 5. Builds

### 5.1 Facts about this repo

- **There is no `eas.json`** anywhere in the repo (checked in this worktree: no `eas.json` at the root or in
  `apps/mobile/`). `apps/mobile/README.md:458-461` says the same: it "needs an Expo account and `eas.json`, neither of
  which exist in this skeleton yet — `eas build:configure` sets that up". `apps/mobile/package.json:8` says "no EAS
  build or expo export in CI yet (real store builds are P4.2)", and `apps/mobile/README.md:159` repeats it.
- `apps/mobile/app.json` has no EAS project ID, no `ios.buildNumber`, and `"version": "0.0.0"` (`app.json:6`). The
  store needs a real marketing version and an incrementing build number `[unverified — training knowledge: EAS can
  auto-increment]`.
- **There must be no `app.config.*`**: a policy test forbids a dynamic config so a scan of `app.json` sees everything
  (`apps/mobile/README.md:78`; `app.plugin.js:11-13`). Per-profile values therefore come from `eas.json` /
  EAS environment variables, not from a config file.

### 5.2 What `eas.json` needs (no values invented)

Create it with `eas build:configure` from `apps/mobile/` after you have an Expo account and have linked the project
`[unverified — training knowledge on current EAS CLI behaviour]`. The repo tells you which settings must differ per
profile; it does not tell you any values:

| Profile (name is yours)               | `GOLFRAVEN_APP_ATTEST_ENV`                | Distribution                                  | Public `EXPO_PUBLIC_*` values it needs                                                                                           | Points at server project |
| ------------------------------------- | ----------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| development (device, dev client)      | `development`                             | internal / ad hoc                             | the staging project's, `apps/mobile/README.md:84-90`                                                                              | a project whose `GR_APPLE_APPATTEST_ENV` is `development` |
| staging (TestFlight)                  | unset or `production`                     | store (TestFlight)                            | the staging project's                                                                                                              | `gr-staging` with `production` |
| production (App Store)                | unset or `production`                     | store                                         | the production project's                                                                                                           | `gr-prod` with `production` |

- `GOLFRAVEN_APP_ATTEST_ENV` is **build time only**, not `EXPO_PUBLIC_*`, and never in the bundle
  (`apps/mobile/README.md:90`). Set it in the profile's `env` block `[unverified — training knowledge: that the
  profile's env block is passed to the build's process environment, which expo prebuild and the plugin read]`.
  If you instead leave it unset the plugin defaults to `production` (`app.plugin.js:18-19`), which is correct for
  both store profiles; set it explicitly anyway so the profile documents itself.
- `EXPO_PUBLIC_*` values are **public by design** (`apps/mobile/README.md:92`); only the anon/publishable Supabase key
  is allowed, and a `service_role` or `sb_secret_` key is refused at parse time and by the pre-install guard
  (`apps/mobile/README.md:88`, `:160-162`).
- **Do not put any `GR_*` variable, any `.p8` or any JWT in `eas.json` or EAS environment variables.** They belong to
  Supabase only. The mobile app reads none of them.

### 5.3 Where Apple signing credentials live

- **Where:** EAS credential management or your vault `[unverified — training knowledge]`. EAS can create and store the
  distribution certificate and provisioning profile for you, and an App Store Connect API key for submission
  `[unverified — training knowledge]`. Choose one and record the choice in your notes.
- **Never in git.** `.gitignore` now excludes `*.p8`, `AuthKey_*.p8`, `*.p12`, `*.mobileprovision`, `*.cer`, `*.pem`,
  `*.jks`, `*.keystore` and `credentials.json` (Repo inconsistencies, item 8). The repo runs gitleaks in CI (`.github/workflows/ci.yml:665`)
  but gitleaks is a backstop, not a reason to be careless.
- **Verify:** `git status` shows none of those file types after a build; the EAS dashboard lists the credentials.

### 5.4 Flags: what a first build can and cannot test

`CHECKIN_UI_ENABLED`, `MARKER_COSIGNAL_UI_ENABLED`, `OFFLINE_CODE_UI_ENABLED` and `WALLET_ACTIVATION_UI_ENABLED` are
all `false` (`apps/mobile/src/features.ts:13`, `:21`, `:29`, `:38`) and the README says not to flip one in a release
build until its items are done (`apps/mobile/README.md:273`). Consequences:

- A build from today's code **can** test: install via TestFlight, the age screen, **Sign in with Apple**, email OTP,
  `link` capture, Me, deletion and revocation (Step 6 probes P3, P5, P6).
- It **cannot** reach App Attest registration or DeviceCheck: those run only behind the check-in and Wallet flags.
  Exercising Step 3 end to end needs a **test build with the relevant flag flipped**, which is a code change
  someone has to make and review (`apps/mobile/src/features.ts`), not an owner click. Until then Step 3's
  server configuration can be proven only with the config probes P1, P7 (400 vs 503).

### 5.5 The first TestFlight build (the real-device field test)

1. Steps 1, 2.2, 4.1 and 5.1-5.3 done; staging Supabase project exists (checklist §9); its secrets from Steps 2.3 and
   3.4 are set; Supabase Auth's Apple provider is configured (2.4).
2. From `apps/mobile/`, run the build for the staging profile, for example
   `eas build --platform ios --profile <staging-profile>`, then submit it to App Store Connect (EAS Submit, or upload
   with Apple's own tooling) `[unverified — training knowledge on current EAS CLI syntax]`. The pre-install guard runs
   first and fails the build on a secret-shaped public variable (`apps/mobile/package.json:14`).
3. Wait for App Store Connect to finish processing, answer any export-compliance prompt (see 4.4), then add the
   build to the internal group (4.2).
4. Install on a physical iPhone and run the checklist in `apps/mobile/README.md:293`: for the iOS side that is "iOS
   with a Distribution-signed or TestFlight build for App Attest", the permission prompt only after the tap, an
   in-course fix matching its circle, airplane-mode check-in, and "Precise location off" messaging.
   Several of these need the check-in flag (5.4).
5. Android is a separate account and pipeline (Google Play); out of scope here.

---

## Step 6. Verification table

Run each probe against the **project you configured**. Substitute your own values; never paste them into the repo or a
shared log. `$ANON_KEY` is the public anon key (it is already in every app bundle, so it may sit on a command line);
`$API` is `https://<PROJECT_REF>.supabase.co/functions/v1`. **Bearer tokens are different**: the signed-in test user's
session token is a credential, and the **service-role key** (P4) bypasses row-level security entirely. Neither may appear
in a command's arguments (`ps`, `/proc/*/cmdline`, shell history), so every probe sends them through curl's config-on-stdin
(`-K -`) with a shell function. `printf` is a builtin, so the secret never reaches any process's argv; the only argument
the password manager's CLI sees is the item's name (bash or zsh; `[unverified for other shells]`):

```sh
# print-secret = your password manager's CLI command that prints one item's value (replace it).
secret_curl() {   # secret_curl <password-manager item holding a bearer token> <curl args...>
  local item="$1"; shift
  printf 'header = "authorization: Bearer %s"\n' "$(print-secret "$item")" | curl -s -K - "$@"
}
```

Never add `-v` (it prints the request headers, including the token) and do not save the output of a run that used the
service-role key anywhere in the checkout. `$USER_TOKEN_ITEM` and `$SERVICE_ROLE_ITEM` below are the names of those two
password-manager items, not the values. The expected results below were **read from the code, not run** against a deployed project, and the Supabase
gateway behaviour is `[unverified — training knowledge]`. If a probe disagrees with this table, believe the probe
and fix the table.

| ID  | What it proves                                    | How                                                                                                                                                                                                                                                                  | Pass                                                                                                                          | Fail means                                                                                                                                                                                                      |
| --- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1  | `devices-attest-key` is configured                | `secret_curl "$USER_TOKEN_ITEM" -o /dev/null -w '%{http_code}\n' -X POST "$API/devices-attest-key" -H "apikey: $ANON_KEY" -H 'content-type: application/json' -d '{}'`                                                                              | **400** (the body fails validation, which happens after the config check: `devices-attest-key/index.ts:36-42`)                  | **503** `attestation_not_configured`: team, bundle or `GR_APPLE_APPATTEST_ENV` missing, whitespace in an id, or env not exactly `production`/`development` (`privileged.ts:2966`). 401: bad token                    |
| P2  | SIWA server values are all set                    | `secret_curl "$USER_TOKEN_ITEM" -X POST "$API/me-signin-methods" -H "apikey: $ANON_KEY" -H 'content-type: application/json' -d '<body>'` with a well-shaped body `{"action":"link","provider":"apple","identityToken":"x.y.z","authorizationCode":"x","nonce":"<16+ chars>"}` (`signin/request-shape.ts:6`; the raw nonce is 16-256 characters, `apps/mobile/src/signin/nonce.ts:4`). It costs one of the 10 link attempts per user per hour (`me-signin-methods/index.ts`) | **422** `invalid_identity_token` (Apple is configured and rejected the dummy token, `methods-handler.ts:88`)                    | **503** `provider_not_configured`: one of the four values is missing or blank (`methods-handler.ts:84`, `:102`). This probe does **not** prove the private key is valid, because the key is first used when a code is exchanged (`apple-client-secret.ts:81`) |
| P3  | The `.p8`, key ID, team ID and client ID are right | After a real Apple sign-in on a TestFlight build, the app's `link` call succeeds (`apps/mobile/src/signin/flow.ts:96`); then call `secret_curl "$USER_TOKEN_ITEM" "$API/me-signin-methods" -H "apikey: $ANON_KEY"` (a GET) and see an `apple` method                                                                                                      | `link` returns `created: false` or `true`, no 5xx; the Apple method is listed                                                  | 503 `provider_not_configured`: P2's cause. A `token_invalid_client` style failure means the key, key ID, team ID or client ID do not match each other (`apple-client.ts:61-66`: `invalid_client` is treated as our configuration being wrong) |
| P4  | The revocation drain works                        | In staging: delete a throwaway Apple-signed-in account with Apple unconfigured (grant queued as `not_configured_apple`, `revocation.ts:73`), then configure Step 2.3 and run `secret_curl "$SERVICE_ROLE_ITEM" -X POST "$API/signin-revocation-drain"` from a trusted shell (the service-role key is read from the password manager into curl's stdin, never an argument) | JSON `{"attempted":1,"revoked":1,...}` (`signin-revocation-drain/index.ts:26-37`)                                              | `queuedForRetry` stays 1: read `outcome`/`error` in the function logs (`revocation.ts:109`); `invalid_client` means the SIWA values are inconsistent. 401: the bearer is not the service-role key (`privileged.ts:3009-3015`) |
| P5  | Native Apple sign-in end to end                   | TestFlight build on a real iPhone, tap Sign in with Apple, finish the age screen first                                                                                                                                                                                | A session is created (`flow.ts:90`) and the account appears in Supabase Auth with an Apple identity                            | Supabase Auth rejects the id token: the Auth Apple provider's client id does not equal the bundle ID, or (only if the provider turns out to require one for the native flow, Step 2.4 `[unverified — training knowledge]`) its secret JWT is expired or wrong. Failing before the sheet opens: the Sign in with Apple capability is missing from the signed build `[unverified — training knowledge]` |
| P6  | `DELETE /v1/me` revokes the Apple grant           | Delete the P5 account in the app (AT 19). Read the `me-delete` response                                                                                                                                                                                               | `signinProvidersRevoked: [{provider:"apple", status:"revoked"}]` (`p3-money-path-requirements.md:2952`)                          | `queued_for_retry`: see P4. Apple unconfigured shows `not_configured_apple` in the queue                                                                                                                        |
| P7  | App Attest end to end                             | Needs the check-in flag (5.4). On a physical iPhone, run a check-in; read the `devices-attest-key` response                                                                                                                                                         | 200/201 with `{deviceId, keyId, replaced}` (`attest-key-handler.ts:70`); then `checkin-token` grades `attested`               | 422 `attestation_rejected` with server reason `aaguid_mismatch`: environment mismatch (Step 3.1). Other reasons are in the verifier table at `p3-money-path-requirements.md:2664-2675`; all are `[unverified]` against a real device |
| P8  | DeviceCheck credentials are accepted | Needs the Wallet flag (5.4). Activate an earned reward on an iPhone, then check **both** the app's outcome **and** the database (admin SQL editor; the query holds no secret): `select created_at, detail->'reasons' as reasons from app.fraud_signal where user_id = '<test-user-uuid>' and kind = 'attestation_failed' and cleared_at is null order by created_at desc;` | Not 503, **and** no open `attestation_failed` row for the test user whose `reasons` contains `devicecheck_token_rejected`. An outcome "held" for some **other** reason (bits already set on this device, an unattestable grade) is normal | **FAIL** if either: (a) 503 `attestation_not_configured` with the log line "attestation vendor is not configured": key, key ID, team ID or environment wrong, or a malformed PEM (`devicecheck-client.ts:110-111`, `:137-141`; a one-line `\n`-escaped key is valid); or (b) an open `attestation_failed` signal with reason `devicecheck_token_rejected`, **even though the app shows a normal "held for review"**: a 400 from Apple that names the device token becomes `VendorRejectedError` (`devicecheck-client.ts:138`), and the handler grades the activation `failed`, opens the signal and holds it (`activate-handler.ts:347-362`). Under decision D1 **option A** (`development` host on staging) this is exactly what a TestFlight token rejected by that host looks like (whether and how Apple rejects it, and with which body, is `[unverified — training knowledge]`): treat it as "option A does not work", clear the test account's signal (it is cleared only by a human act, and while open it holds that account's next activations, `decision-table.ts:13`), and fall back to option B or C |
| P9  | Pinned Apple root is really Apple's               | Step 3.2                                                                                                                                                                                                                                                              | Fingerprint equals `1C:B9:...:C9:32` from a clean machine and a second source                                                  | Stop; do not ship App Attest to production                                                                                                                                                                      |
| P10 | Auth client-secret JWT is not about to expire     | `<password manager CLI: print the JWT> | node tools/apple/check-siwa-secret-expiry.mjs` (stdin form; never put the JWT in an env-var prefix or argument)                                                                                                                                                                                | Exit 0, "more than 30 days"                                                                                                   | Exit 1: re-mint (Step 2.4); exit 2: you gave it no input                                                                                                                                                         |
| P11 | Private relay mail is delivered                   | A test Apple ID with Hide My Email signs in; an OTP email is sent to that account                                                                                                                                                                                      | The mail arrives at the `@privaterelay.appleid.com` address                                                                    | Sender domain not registered with Apple, or SPF/DKIM not aligned `[unverified — training knowledge]`                                                                                                              |
| P12 | App Store Connect and TestFlight are wired        | Build processes; install from TestFlight on a physical iPhone                                                                                                                                                                                                         | "Ready to test"; the app launches                                                                                              | Processing errors are reported in App Store Connect; a missing entitlement points back to Step 1.2 `[unverified — training knowledge]`                                                                                                              |
| P13 | Review account cannot receive a reward            | Sign in as the reviewer **on the project the build points at** (a TestFlight build points at staging, so do the dry run with a staging reviewer account created the same way, Step 4.3 steps 2-3 against `gr-staging`; the real reviewer account is checked on a build pointed at production); attempt a Wallet activation (flag on)                                                                                                                                                                                                         | 403 `forbidden` (`activate-handler.ts:271`)                                                                                    | The `app.app_review_demo_account` row is missing **in that project** (4.3)                                                                                                                                                           |

---

## Step 7. What stays blocked, and on what

| Blocked item                                                                  | Blocked on                                                                                                                                                                             | Source                                                                                                  |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Services ID return URLs / domain verification (Android + web SIWA)            | **Q1**: the domain (partners host and primary player domain, checklist §1). Also needs server work for a second audience, so the Services ID has no consumer yet                       | `partner-auth-design.md:791`; `apps/mobile/README.md:120`; `p3-money-path-requirements.md:3019`, `:3054` |
| Private-relay sender-domain registration                                      | **Q7 / checklist §7**: mail provider and sender domain chosen and verified (Resend, SPF/DKIM/DMARC), custom SMTP in Supabase Auth. Also needs the domain (§1)                           | `partner-auth-design.md:797`; checklist `:79-101`; plan `02-build-plan.md:1870`, `:3279`                  |
| Staging/production secrets (Steps 2.3, 3.4), Auth Apple provider (2.4), probes | **Supabase project creation** (checklist §9: `gr-staging`, then `gr-prod`)                                                                                                             | checklist `:115-132`                                                                                    |
| Review account, privacy policy URL, French legal text                          | Supabase production project, custom SMTP, domain, counsel (privacy policy / terms in EN and FR)                                                                                          | plan `02-build-plan.md:1871`, `:2788`                                                                    |
| Android: bundle reservation, Play Integrity, Data Safety form                  | **Google Play organisation account** (checklist §4) and Google Cloud project                                                                                                           | checklist `:45-54`; `apps/mobile/README.md:277`, `:281`                                                  |
| App Attest and DeviceCheck verified on a device                               | Check-in and Wallet flags flipped in a test build (engineering), a physical iPhone, Steps 3.2-3.4 done. The native module has never been compiled or run                                | `apps/mobile/README.md:282`, `:426-431`                                                                  |
| App Attest root accepted for production                                       | The Step 3.2 human fingerprint comparison                                                                                                                                              | `apple-app-attest-root.ts:13-16`                                                                         |
| EAS builds                                                                    | An Expo account and an `eas.json` (does not exist), a real version and build number                                                                                                    | `apps/mobile/README.md:458-461`                                                                          |
| Push notifications (APNs key)                                                 | `expo-notifications` is not installed; an owner decision on push credentials                                                                                                           | `apps/mobile/src/push/index.ts:4-8`                                                                      |
| HealthKit / Health declarations on iOS                                        | Counsel L7 sign-off before the first HealthKit read; nothing HealthKit-related is built                                                                                                | plan `02-build-plan.md:2790`; `policy-scan.ts:62-67`                                                     |
| Native Apple sign-in not auto-linking by email                                | The P4 spike decision on GoTrue linking (not an Apple task)                                                                                                                            | `p3-money-path-requirements.md:3033-3040`                                                                |
| Google sign-in                                                                | No native Google SDK or OAuth client; server link is 501                                                                                                                              | `apps/mobile/README.md:117-119`; `methods-handler.ts:96-100`                                            |

---

## Repo inconsistencies found while writing this, and what became of each

Written first against the code as it was at `cbd9c2b`; the "Status" column records the follow-up commits.

| #  | Finding                                                                                                                                                                                                                                                                                                                                   | Status                                                                                                                                                                                                                                                         |
| -- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | `GR_APPLE_APPATTEST_ROOT` and `GR_APPLE_TRUST_ANCHOR` are **not variables**. A test sets them only to prove they are ignored (`supabase/tests/integration/attest-key.deno.test.ts:398-403`); the anchor is pinned bytes (`apple-app-attest-root.ts`)                                                                                         | **Documented**: stated plainly in `docs/security/edge-role-design.md` (after the section-6 table) and in `p3-money-path-requirements.md` "Trust anchor". Do not create them as secrets                                                                          |
| 2  | `apps/mobile/README.md` "Release attestation configuration" under-listed the server values: no `GR_APPLE_APPATTEST_ENV` for `devices-attest-key`, no `GR_APPLE_DEVICECHECK_*` for `rewards-activate`                                                                                                                                       | **Fixed**: the README item now lists, per function, every Apple and Play server value                                                                                                                                                                          |
| 3  | The SIWA and DeviceCheck/Play PEM parsers disagreed on a one-line literal-`\n` key                                                                                                                                                                                                                                                        | **Fixed**: one shared parser, `supabase/functions/_shared/pem.ts`, used by SIWA, DeviceCheck and Play Integrity; tests `pem-shared.test.ts`, `devicecheck-egress.test.ts`, `apple-config.deno.test.ts`                                                          |
| 4  | `loadRewardsAttestationConfig` did not trim (a trailing newline on `GR_APPLE_DEVICECHECK_ENV` silently meant "unconfigured")                                                                                                                                                                                                              | **Fixed**: trims like the other loaders, refuses whitespace inside the team/bundle id, requires a non-blank PEM; `apple-config.deno.test.ts`                                                                                                                    |
| 5  | "K2" is overloaded: the plan's landing-page experiment vs the App Attest root fingerprint check                                                                                                                                                                                                                                           | **Renamed** everywhere it is the root check: "App Attest root fingerprint check (follow-up K2 of the App Attest work)"                                                                                                                                          |
| 6  | Two plan behaviours for the review account are unbuilt: "audits every sign-in" and "disabled outside submission windows" (plan `02-build-plan.md:1871`); also no provisioning procedure                                                                                                                                                  | **Tracked, deliberately not built**: a "Tracked gap, P4.2 pre-submission item" note in `p3-money-path-requirements.md` and Step 4.3 above. Until built, remove the demo row or disable its Auth user by hand after each review window                            |
| 7  | The DeviceCheck client used the bare platform `fetch`: no host allow-list, no `redirect: "error"` (the SIWA path has both via `signin/safe-fetch.ts`). `appleid.apple.com` is the only Apple host on any in-code allow-list; no Supabase-side outbound allow-list exists in the repo (`supabase/config.toml` has none); `docs/owner/network-unblock.md` is about the development container's proxy and lists no Apple host | **Fixed for DeviceCheck**: exact-host allow-list (`api.devicecheck.apple.com`, `api.development.devicecheck.apple.com`), `redirect: "error"`, refused redirects, existing per-call timeout; `devicecheck-egress.test.ts`. The Play Integrity adapter still uses the bare `fetch`: tracked as follow-up K11 in `p3-money-path-requirements.md`, not built |
| 8  | `.gitignore` did not exclude Apple credential file types                                                                                                                                                                                                                                                                                  | **Fixed**: `*.p8`, `AuthKey_*.p8`, `*.p12`, `*.mobileprovision`, `*.cer`, `credentials.json`. gitleaks' default private-key rule confirmed to flag a committed key block in four forms; nothing loosened                                                        |
| 9  | No operator script minted the six-month client-secret JWT, only the expiry checker existed                                                                                                                                                                                                                                                | **Fixed**: `tools/apple/mint-siwa-client-secret.mjs` (Step 2.4); `mint-siwa-client-secret.test.ts`                                                                                                                                                              |
| 10 | `apps/mobile/app.json` has no EAS project ID, no iOS build number, and version `0.0.0`; there is no `eas.json`                                                                                                                                                                                                                            | **Open** (Step 5.1): an owner/engineering step when EAS is set up                                                                                                                                                                                              |

## Everything in this runbook that is `[unverified — training knowledge]`

Grouped so a reviewer can check them in one pass. None of these was verified against Apple, Expo or Supabase in this
repo.

- **Apple portal and App Store Connect:** the names and places of Identifiers, Keys and the Sign in with Apple "email
  communication" configuration; that SIWA key setup asks for a primary App ID; that App Attest may need an explicit
  App ID capability toggle and DeviceCheck needs none; that an App ID alone reserves the name; the `.p8` is
  downloadable once; whether one key can carry several services and how many keys an account may hold; that Apple
  requires SPF/DKIM alignment for the relay domain; the SIWA client-secret claim set and its six-month maximum;
  Services ID return URLs and domain verification; app-record field names (name availability, SKU, primary language);
  internal TestFlight groups need no beta review; export-compliance and age-rating prompts; the App Review
  Information field names.
- **Apple PKI:** that `https://www.apple.com/certificateauthority/private/` lists the App Attestation root and is a
  valid second source; which Apple page publishes a fingerprint, if any. (The direct PEM URL is cited by the repo at
  `apple-app-attest-root.ts:11`, itself marked "unverified against a second source".)
- **Supabase:** the dashboard path to Edge Function secrets and the Apple provider; CLI flags for `supabase secrets
  set`; whether a running function instance picks up changed secrets without a redeploy; gateway behaviour for the
  probes; GoTrue's default linking of same-email identities.
- **EAS / Expo:** `eas build:configure` behaviour; that `eas.json` `env` reaches `expo prebuild`; EAS-managed
  credentials; EAS Submit and build-number auto-increment; exact CLI syntax in 5.5.
- **Apple DeviceCheck and SIWA wire contracts** (also flagged in the repo itself): the hosts, paths, bodies and error
  conventions (`devicecheck-client.ts:7-21`, `apple-client.ts:5-10`, `p3-money-path-requirements.md:3021-3029`).
- **Real-device behaviour:** everything about App Attest, DeviceCheck and SIWA on a physical iPhone. No Swift or
  Kotlin line has been compiled or run (`apps/mobile/README.md:282`, `:426-431`).
