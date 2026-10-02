/**
 * Scanners behind the two store-policy gates (build plan §10 P4 acceptance
 * tests 5 and 7). Pure functions over text, so each rule is proved against
 * a failing fixture as well as against the real files.
 *
 * AT 5: "No `Always` / background-location permission in either build
 * (manifest + `Info.plist` scan)." Foreground location is allowed in the MVP
 * (§7.1); only background / `Always` is forbidden.
 * AT 7: "No ads or analytics SDK in the lockfile."
 */

export const FORBIDDEN_ANDROID_PERMISSIONS = [
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.FOREGROUND_SERVICE_LOCATION",
] as const;

export const FORBIDDEN_IOS_INFOPLIST_KEYS = [
  "NSLocationAlwaysAndWhenInUseUsageDescription",
  "NSLocationAlwaysUsageDescription",
] as const;

/** Config-plugin props that turn background location on. */
const BACKGROUND_PLUGIN_PROPS = new Set([
  "isAndroidBackgroundLocationEnabled",
  "isIosBackgroundLocationEnabled",
  "isAndroidForegroundServiceEnabled",
  "locationAlwaysAndWhenInUsePermission",
  "locationAlwaysPermission",
]);

/** Plugins whose purpose is background work/location; none is in the MVP. */
const FORBIDDEN_PLUGINS = new Set(["expo-task-manager", "expo-background-fetch", "expo-background-task"]);

export interface Violation {
  rule: string;
  detail: string;
}

type ExpoConfig = {
  expo?: {
    android?: { permissions?: string[]; blockedPermissions?: string[] };
    ios?: { infoPlist?: Record<string, unknown>; entitlements?: Record<string, unknown> };
    plugins?: (string | [string, Record<string, unknown>?])[];
  };
};

/** Static scan of `app.json`. */
export function scanAppConfig(config: ExpoConfig): Violation[] {
  const out: Violation[] = [];
  const expo = config.expo ?? {};
  const permissions = expo.android?.permissions ?? [];
  const blocked = new Set(expo.android?.blockedPermissions ?? []);
  for (const p of FORBIDDEN_ANDROID_PERMISSIONS) {
    if (permissions.includes(p)) out.push({ rule: "android-permission", detail: `app.json requests ${p}` });
    // Defence against a library adding it through its own manifest: the app must
    // explicitly block it so the manifest merger removes it.
    if (!blocked.has(p)) out.push({ rule: "android-blocked-permission-missing", detail: `app.json must list ${p} in android.blockedPermissions` });
  }
  const infoPlist = expo.ios?.infoPlist ?? {};
  for (const k of FORBIDDEN_IOS_INFOPLIST_KEYS) {
    if (k in infoPlist) out.push({ rule: "ios-infoplist", detail: `app.json sets ${k}` });
  }
  const modes = infoPlist["UIBackgroundModes"];
  if (Array.isArray(modes) && modes.includes("location")) out.push({ rule: "ios-background-modes", detail: "app.json sets UIBackgroundModes: location" });
  for (const entry of expo.plugins ?? []) {
    const [name, props] = Array.isArray(entry) ? entry : [entry, undefined];
    if (FORBIDDEN_PLUGINS.has(name)) out.push({ rule: "plugin", detail: `plugin ${name} is background-only and not allowed in the MVP` });
    for (const [prop, value] of Object.entries(props ?? {})) {
      if (BACKGROUND_PLUGIN_PROPS.has(prop) && value !== false) out.push({ rule: "plugin-prop", detail: `plugin ${name} sets ${prop}` });
    }
  }
  return out;
}

/** Scan of a generated `AndroidManifest.xml` (after `expo prebuild`). A
 * permission removed with `tools:node="remove"` does not count as granted. */
export function scanAndroidManifest(xml: string): Violation[] {
  const out: Violation[] = [];
  for (const m of xml.matchAll(/<uses-permission\b([^>]*)>/g)) {
    const attrs = m[1] ?? "";
    const name = /android:name="([^"]+)"/.exec(attrs)?.[1];
    if (!name || /tools:node="remove"/.test(attrs)) continue;
    if ((FORBIDDEN_ANDROID_PERMISSIONS as readonly string[]).includes(name)) out.push({ rule: "android-manifest", detail: `manifest grants ${name}` });
  }
  return out;
}

/** Scan of a generated `Info.plist` (XML plist, after `expo prebuild`). */
export function scanInfoPlist(plist: string): Violation[] {
  const out: Violation[] = [];
  const keys = [...plist.matchAll(/<key>([^<]+)<\/key>/g)].map((m) => m[1]!);
  for (const k of FORBIDDEN_IOS_INFOPLIST_KEYS) if (keys.includes(k)) out.push({ rule: "ios-infoplist", detail: `Info.plist has ${k}` });
  const modes = /<key>UIBackgroundModes<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist)?.[1] ?? "";
  if (/<string>location<\/string>/.test(modes)) out.push({ rule: "ios-background-modes", detail: "Info.plist UIBackgroundModes contains location" });
  return out;
}

/* ------------------------------------------------------------------ */

interface Denied {
  /** Exact package name, or a scope/prefix ending in `/` or `*`. */
  pattern: string;
  why: string;
  /** `owner` = not an ad/analytics SDK by name, but needs an explicit owner
   * decision before it can ship under "no third-party ad or analytics SDK". */
  kind: "ads" | "analytics" | "owner";
}

export const DENIED_SDKS: readonly Denied[] = [
  // advertising
  { pattern: "react-native-google-mobile-ads", why: "Google Mobile Ads", kind: "ads" },
  { pattern: "expo-ads-admob", why: "AdMob", kind: "ads" },
  { pattern: "expo-ads-facebook", why: "Facebook Audience Network", kind: "ads" },
  { pattern: "react-native-admob", why: "AdMob", kind: "ads" },
  { pattern: "@react-native-admob/", why: "AdMob", kind: "ads" },
  { pattern: "react-native-fbads", why: "Facebook Audience Network", kind: "ads" },
  { pattern: "react-native-applovin-max", why: "AppLovin MAX", kind: "ads" },
  { pattern: "react-native-appodeal", why: "Appodeal", kind: "ads" },
  { pattern: "react-native-unity-ads", why: "Unity Ads", kind: "ads" },
  { pattern: "react-native-ironsource", why: "ironSource", kind: "ads" },
  // analytics / attribution / tracking
  { pattern: "@react-native-firebase/analytics", why: "Firebase Analytics", kind: "analytics" },
  { pattern: "@react-native-firebase/perf", why: "Firebase Performance", kind: "analytics" },
  { pattern: "expo-firebase-analytics", why: "Firebase Analytics", kind: "analytics" },
  { pattern: "expo-firebase-core", why: "Firebase core (Analytics)", kind: "analytics" },
  { pattern: "@amplitude/", why: "Amplitude", kind: "analytics" },
  { pattern: "amplitude-js", why: "Amplitude", kind: "analytics" },
  { pattern: "expo-analytics-amplitude", why: "Amplitude", kind: "analytics" },
  { pattern: "mixpanel-react-native", why: "Mixpanel", kind: "analytics" },
  { pattern: "mixpanel-browser", why: "Mixpanel", kind: "analytics" },
  { pattern: "@segment/", why: "Segment", kind: "analytics" },
  { pattern: "react-native-segment", why: "Segment", kind: "analytics" },
  { pattern: "posthog-react-native", why: "PostHog", kind: "analytics" },
  { pattern: "posthog-js", why: "PostHog", kind: "analytics" },
  { pattern: "@datadog/mobile-react-native", why: "Datadog RUM", kind: "analytics" },
  { pattern: "react-native-appsflyer", why: "AppsFlyer attribution", kind: "analytics" },
  { pattern: "react-native-adjust", why: "Adjust attribution", kind: "analytics" },
  { pattern: "react-native-branch", why: "Branch attribution", kind: "analytics" },
  { pattern: "react-native-fbsdk-next", why: "Facebook SDK", kind: "analytics" },
  { pattern: "react-native-fbsdk", why: "Facebook SDK", kind: "analytics" },
  { pattern: "expo-facebook", why: "Facebook SDK", kind: "analytics" },
  { pattern: "expo-insights", why: "EAS Insights telemetry", kind: "analytics" },
  { pattern: "expo-observe", why: "EAS Observe telemetry", kind: "analytics" },
  { pattern: "expo-app-metrics", why: "app metrics telemetry", kind: "analytics" },
  { pattern: "expo-tracking-transparency", why: "App Tracking Transparency (implies tracking)", kind: "analytics" },
  // crash reporting: not an ads/analytics SDK by name, but it collects
  // diagnostics that must be declared in the privacy label / Data Safety, so
  // adding one is an owner decision that edits this list on purpose.
  { pattern: "@sentry/", why: "Sentry (diagnostics: declare it, then decide)", kind: "owner" },
  { pattern: "sentry-expo", why: "Sentry (diagnostics: declare it, then decide)", kind: "owner" },
  { pattern: "@bugsnag/", why: "Bugsnag (diagnostics: declare it, then decide)", kind: "owner" },
  { pattern: "@react-native-firebase/crashlytics", why: "Crashlytics (diagnostics: declare it, then decide)", kind: "owner" },
];

function matches(name: string, pattern: string): boolean {
  return pattern.endsWith("/") ? name.startsWith(pattern) : name === pattern;
}

/** Package names listed under a pnpm lockfile's `packages:` section
 * (`  name@version:` / `  '@scope/name@version':`), de-duplicated. */
export function lockfilePackageNames(lockText: string): string[] {
  const start = lockText.indexOf("\npackages:\n");
  if (start === -1) return [];
  const end = lockText.indexOf("\nsnapshots:\n", start);
  const section = lockText.slice(start, end === -1 ? undefined : end);
  const names = new Set<string>();
  for (const line of section.split("\n")) {
    const m = /^ {2}'?((?:@[^/@\s]+\/)?[^@\s'][^@\s']*)@[^\s']+'?:\s*$/.exec(line);
    if (m) names.add(m[1]!);
  }
  return [...names].sort();
}

export function findDeniedSdks(lockText: string): { name: string; why: string; kind: Denied["kind"] }[] {
  const out: { name: string; why: string; kind: Denied["kind"] }[] = [];
  for (const name of lockfilePackageNames(lockText)) {
    const hit = DENIED_SDKS.find((d) => matches(name, d.pattern));
    if (hit) out.push({ name, why: hit.why, kind: hit.kind });
  }
  return out;
}
