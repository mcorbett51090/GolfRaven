/**
 * `LocationPort` over `expo-location`: the ONLY file in the app that imports it.
 *
 * FOREGROUND ONLY (build plan §7.1, P4 AT 5). The calls used here are `getForegroundPermissionsAsync`, `requestForegroundPermissionsAsync`,
 * `hasServicesEnabledAsync` and `getCurrentPositionAsync`. The background half of the module (`requestBackgroundPermissionsAsync`, `startLocationUpdatesAsync`,
 * `startGeofencingAsync`, `watchPositionAsync`) is never referenced; `test/checkin-no-prompt-at-launch.test.ts` scans the sources for that, and the app config
 * (`app.json`, `expo-location` with every background prop `false`) makes the generated Info.plist / manifest carry no background capability either.
 *
 * `[unverified: nothing here has run on a device]`
 */
import * as Location from "expo-location";
import type { FixAttempt, LocationPermission, LocationPort } from "./location";

function toPermission(r: Location.LocationPermissionResponse): LocationPermission {
  // Approximate = Android's "Approximate" grant (`android.accuracy === "coarse"`) or iOS 14+'s "Precise Location: Off" (`ios.accuracy === "reduced"`, `PermissionDetailsLocationIOS`).
  if (r.granted) return { status: "granted", approximate: r.android?.accuracy === "coarse" || r.ios?.accuracy === "reduced" };
  if (r.status === Location.PermissionStatus.UNDETERMINED && r.canAskAgain) return { status: "undetermined" };
  return { status: "denied", canAskAgain: r.canAskAgain };
}

/** `platform` is `Platform.OS`: Android always reports the mock flag, so there an absent flag is not trusted (read as simulated); iOS reports none. */
export function createExpoLocationPort(platform: string): LocationPort {
  return {
    async permission() {
      try {
        return toPermission(await Location.getForegroundPermissionsAsync());
      } catch {
        return { status: "denied", canAskAgain: false };
      }
    },
    async requestPermission() {
      try {
        return toPermission(await Location.requestForegroundPermissionsAsync());
      } catch {
        return { status: "denied", canAskAgain: false };
      }
    },
    async servicesEnabled() {
      try {
        return await Location.hasServicesEnabledAsync();
      } catch {
        return false;
      }
    },
    currentFix({ timeoutMs }): Promise<FixAttempt> {
      return new Promise<FixAttempt>((resolve) => {
        let done = false;
        const finish = (r: FixAttempt): void => {
          if (!done) {
            done = true;
            clearTimeout(timer);
            resolve(r);
          }
        };
        // `getCurrentPositionAsync` has no timeout of its own and cannot be cancelled: a late answer is dropped.
        const timer = setTimeout(() => finish({ ok: false, reason: "timeout" }), timeoutMs);
        Location.getCurrentPositionAsync({ accuracy: Location.Accuracy.High }).then(
          (p) =>
            finish({
              ok: true,
              fix: {
                latitude: p.coords.latitude,
                longitude: p.coords.longitude,
                accuracyMeters: typeof p.coords.accuracy === "number" ? p.coords.accuracy : null,
                timestamp: p.timestamp,
                simulated: platform === "android" ? p.mocked !== false : p.mocked === true,
              },
            }),
          () => finish({ ok: false, reason: "unavailable" }),
        );
      });
    },
  };
}
