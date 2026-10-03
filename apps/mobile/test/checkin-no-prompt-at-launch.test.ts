/**
 * P4.2c source scans (like `push.test.ts` for the notification prompt):
 *  - the location permission prompt has ONE caller chain and it starts at a button's `onPress`: never at launch, never in an effect, never in the composition root;
 *  - FOREGROUND ONLY: no background / Always / geofencing API of `expo-location` (or a task manager) appears anywhere in the app, and the one adapter file that imports the module calls
 *    only the four foreground functions (P4 AT 5, source half; the manifest / Info.plist half is `policy.test.ts`).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : /\.tsx?$/.test(n) ? [join(dir, n)] : []));
const all = [...files(join(root, "src")), ...files(join(root, "app"))];
const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
const read = (f: string): string => strip(readFileSync(join(root, f), "utf8"));
const where = (needle: RegExp): string[] => all.filter((f) => needle.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f)).sort();

/** The text between the parentheses opened right after `open` (balanced), for every occurrence of `open`. */
function callBodies(text: string, open: string): string[] {
  const out: string[] = [];
  let from = 0;
  for (;;) {
    const i = text.indexOf(open, from);
    if (i < 0) return out;
    let depth = 1;
    let j = i + open.length;
    while (j < text.length && depth > 0) {
      const c = text[j];
      if (c === "(") depth += 1;
      else if (c === ")") depth -= 1;
      j += 1;
    }
    out.push(text.slice(i + open.length, j - 1));
    from = j;
  }
}

describe("the location prompt is shown only from a button", () => {
  it("`requestForegroundPermissionsAsync` appears only in the expo-location adapter, inside `requestPermission`", () => {
    expect(where(/requestForegroundPermissionsAsync/)).toEqual(["src/checkin/expo-location.ts"]);
    const adapter = read("src/checkin/expo-location.ts");
    const body = /async requestPermission\(\) \{([\s\S]*?)\n    \},/.exec(adapter)?.[1] ?? "";
    expect(body).toMatch(/requestForegroundPermissionsAsync/);
    expect(adapter.match(/requestForegroundPermissionsAsync/g)).toHaveLength(1);
  });

  it("`.requestPermission(` is CALLED in exactly one place, `ensureForegroundLocation`, which only the two button flows call", () => {
    expect(where(/\.requestPermission\(/)).toEqual(["src/checkin/permission.ts"]);
    expect(where(/\bensureForegroundLocation\b/)).toEqual(["src/checkin/flow.ts", "src/checkin/permission.ts", "src/marker/capture.ts"]);
    expect(where(/\brunCheckIn\b/)).toEqual(["src/checkin/flow.ts", "src/runtime/services.ts"]);
    expect(where(/\bcaptureMarkerCoSignal\b/)).toEqual(["src/marker/capture.ts", "src/runtime/services.ts"]);
  });

  it("the screens call the services from the button handler only: `onCheckInPress` / `onMarkerPress` appear only as the button's `onPress`", () => {
    expect(where(/services\.checkin\(/)).toEqual(["src/screens/CheckInCard.tsx"]);
    expect(where(/services\.markerCosignal\(/)).toEqual(["src/screens/MarkerCard.tsx"]);
    const card = read("src/screens/CheckInCard.tsx");
    expect(card.match(/onCheckInPress/g)).toHaveLength(2); // the definition and the one onPress
    expect(card).toMatch(/onPress=\{\(\) => void onCheckInPress\(\)\}/);
    const marker = read("src/screens/MarkerCard.tsx");
    expect(marker.match(/onMarkerPress/g)).toHaveLength(2);
    expect(marker).toMatch(/onPress=\{\(\) => void onMarkerPress\(\)\}/);
  });

  it("no effect (useEffect / useLayoutEffect / useFocusEffect / useCallback-in-effect) anywhere in the app mentions the check-in, the marker capture or the permission", () => {
    const bad = /checkin\(|markerCosignal\(|runCheckIn|captureMarkerCoSignal|requestPermission|ensureForegroundLocation|CheckInCard|MarkerCard/;
    for (const f of all) {
      const text = strip(readFileSync(f, "utf8"));
      for (const hook of ["useEffect(", "useLayoutEffect(", "useFocusEffect("]) {
        for (const body of callBodies(text, hook)) expect(body, `${relative(root, f)} ${hook}`).not.toMatch(bad);
      }
    }
  });

  it("the composition root and the provider only CONSTRUCT the port: nothing there reads the permission, asks for it or takes a fix", () => {
    const services = read("src/runtime/services.ts");
    expect(services).toMatch(/createExpoLocationPort\(Platform\.OS\)/);
    expect(services).not.toMatch(/location\.(permission|requestPermission|servicesEnabled|currentFix)/);
    const provider = read("src/runtime/AppProvider.tsx");
    expect(provider).not.toMatch(/location|requestPermission|checkin\(|markerCosignal\(/);
    expect(read("app/_layout.tsx")).not.toMatch(/location|requestPermission|checkin|marker/i);
  });

  it("the course page and the facility page do not call the services either: they only render the cards behind the switches", () => {
    expect(read("app/course/[id].tsx")).not.toMatch(/requestPermission|services\.|\.checkin\(/);
    expect(read("app/facility/[id].tsx")).not.toMatch(/requestPermission|services\.|markerCosignal\(/);
  });
});

describe("FOREGROUND ONLY: no background, Always or geofencing API anywhere (P4 AT 5, source half)", () => {
  const FORBIDDEN = [
    "requestBackgroundPermissionsAsync",
    "getBackgroundPermissionsAsync",
    "startLocationUpdatesAsync",
    "stopLocationUpdatesAsync",
    "hasStartedLocationUpdatesAsync",
    "startGeofencingAsync",
    "stopGeofencingAsync",
    "hasStartedGeofencingAsync",
    "isBackgroundLocationAvailableAsync",
    "watchPositionAsync",
    "requestMotionActivityPermissionsAsync",
    "getMotionActivityPermissionsAsync",
    "watchMotionActivityAsync",
    "expo-task-manager",
    "expo-background-fetch",
    "expo-background-task",
    "TaskManager",
    "react-native-background-geolocation",
    "react-native-geolocation",
    "@react-native-community/geolocation",
  ];
  it.each(FORBIDDEN)("`%s` is referenced nowhere in src/ or app/", (name) => {
    expect(where(new RegExp(name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")))).toEqual([]);
  });

  it("`expo-location` is imported by exactly one file, the adapter, and nothing else imports a location library", () => {
    expect(where(/from "expo-location"|require\("expo-location"\)/)).toEqual(["src/checkin/expo-location.ts"]);
    expect(where(/geolocation/i)).toEqual([]);
  });

  it("the adapter uses only the four foreground functions of `Location.*` (plus the Accuracy / PermissionStatus enums and the two response types)", () => {
    const used = [...read("src/checkin/expo-location.ts").matchAll(/\bLocation\.([A-Za-z]+)/g)].map((m) => m[1]!);
    expect([...new Set(used)].sort()).toEqual(["Accuracy", "LocationPermissionResponse", "PermissionStatus", "getCurrentPositionAsync", "getForegroundPermissionsAsync", "hasServicesEnabledAsync", "requestForegroundPermissionsAsync"]);
  });

  it("no background-location dependency is declared", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { dependencies: Record<string, string> };
    const deps = Object.keys(pkg.dependencies);
    expect(deps.filter((d) => /task-manager|background|geolocation|notifications/.test(d))).toEqual([]);
    expect(pkg.dependencies["expo-location"]).toBe("57.0.19"); // exact pin, no range
  });

  it("the Android location permissions are never requested at RUNTIME by name either (no PermissionsAndroid use for location)", () => {
    expect(where(/PermissionsAndroid/)).toEqual([]);
  });
});
