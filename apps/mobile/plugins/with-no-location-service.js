// Config plugin (P4.2c-1): removes `expo-location`'s `LocationTaskService` from the MERGED Android manifest.
//
// The library's own manifest declares
//   <service android:name=".services.LocationTaskService" android:foregroundServiceType="location" />
// (its namespace is `expo.modules.location`). That service exists only for background location updates, which this app never uses (foreground only, build plan §7.1, P4 AT 5), and a
// `foregroundServiceType="location"` service in the merged manifest invites a Play foreground-service declaration for a capability the app does not have. `FOREGROUND_SERVICE_LOCATION` is
// already blocked in `app.json`; this entry removes the service itself with `tools:node="remove"`, written under its fully-qualified name (a relative `.services...` in the APP's manifest
// would resolve against the app's package, not the library's, and match nothing).
//
// `[unverified]`: the generated app manifest is checked (`test/policy.test.ts`), but the REMOVAL happens in the Gradle manifest merger, which has not been run here against a real build.
// It is on the policy allow-list with that reason (`test/support/policy-scan.ts`).
const { withAndroidManifest, AndroidConfig } = require("expo/config-plugins");

const SERVICE = "expo.modules.location.services.LocationTaskService";
const TOOLS_NS = "http://schemas.android.com/tools";

/** Pure: adds the removal entry to a parsed manifest (`xml2js` shape, as `withAndroidManifest` gives it). Idempotent. */
function applyToManifest(manifestFile) {
  const manifest = manifestFile.manifest;
  manifest.$ = manifest.$ || {};
  manifest.$["xmlns:tools"] = manifest.$["xmlns:tools"] || TOOLS_NS;
  const app = AndroidConfig.Manifest.getMainApplicationOrThrow(manifestFile);
  app.service = app.service || [];
  const existing = app.service.find((s) => s.$ && s.$["android:name"] === SERVICE);
  if (existing) existing.$["tools:node"] = "remove";
  else app.service.push({ $: { "android:name": SERVICE, "tools:node": "remove" } });
  return manifestFile;
}

const withNoLocationService = (config) =>
  withAndroidManifest(config, (c) => {
    c.modResults = applyToManifest(c.modResults);
    return c;
  });

module.exports = withNoLocationService;
module.exports.applyToManifest = applyToManifest;
module.exports.SERVICE = SERVICE;
