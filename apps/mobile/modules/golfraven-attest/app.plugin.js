// Config plugin of the local module `golfraven-attest` (P4.2b-2). It does ONE thing: sets the App Attest entitlement on iOS,
//   com.apple.developer.devicecheck.appattest-environment = "development" | "production",
// which `DCAppAttestService` needs (without it `isSupported` is false on a real device and `generateKey` fails). It adds NO Android permission and NO Info.plist key.
//
// The value is chosen at prebuild time by the build-time variable GOLFRAVEN_APP_ATTEST_ENV (NOT an EXPO_PUBLIC_* variable: it is not inlined into the bundle and is not read by
// the app). Unset it is "production", the value for App Store / TestFlight builds; a development build that must attest sets GOLFRAVEN_APP_ATTEST_ENV=development. A key attested in
// one environment does not verify as the other at the server (the attestation's aaguid names the environment), so a development build against a production deployment registers
// nothing (`attestation_rejected`) and the device stays `unattestable`: use a matching pair. Any other value fails the prebuild rather than guessing.
//
// There is deliberately no `app.config.*` (a dynamic config could hide things from the policy scan of `app.json`): this plugin is listed in `app.json`, is on the policy
// allow-list (`test/support/policy-scan.ts`), and the entitlement it writes is checked in the GENERATED entitlements file (`test/policy.test.ts`).
const { withEntitlementsPlist } = require("expo/config-plugins");

const KEY = "com.apple.developer.devicecheck.appattest-environment";
const VALUES = ["development", "production"];

function environmentFrom(env) {
  const v = env.GOLFRAVEN_APP_ATTEST_ENV;
  if (v === undefined || v === "") return "production";
  if (!VALUES.includes(v)) throw new Error(`GOLFRAVEN_APP_ATTEST_ENV must be "development" or "production" (got ${JSON.stringify(v)}).`);
  return v;
}

const withAppAttest = (config) =>
  withEntitlementsPlist(config, (c) => {
    c.modResults[KEY] = environmentFrom(process.env);
    return c;
  });

module.exports = withAppAttest;
module.exports.environmentFrom = environmentFrom;
module.exports.ENTITLEMENT_KEY = KEY;
