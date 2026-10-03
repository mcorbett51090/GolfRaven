/**
 * Push-token registration (`POST me-push-token`, build plan §4.7.1a). The permission prompt is NEVER requested at launch: `enable()` is
 * called only from an explicit player action (Me → Notifications), and nothing in the startup path references the adapter's request
 * method (`test/push.test.ts` scans the sources for that).
 *
 * `expo-notifications` is NOT installed in this build (it is a heavy native module with its own config plugin and a push-credentials setup that
 * is an owner decision), so the default adapter is `unavailablePushAdapter` and Me shows the control disabled. The client call, the device id
 * handling and the state machine are real and tested; wiring the native module is the P4.2 follow-up: implement `PushAdapter` over
 * `expo-notifications` (`getPermissionsAsync` / `requestPermissionsAsync` / `getExpoPushTokenAsync`), pin it, add its plugin to the policy
 * allow-list with a reason, and pass it in `runtime/services.ts`.
 */
import type { ApiClient } from "../api/types";

export type PushPermissionResult = { status: "granted"; expoToken: string } | { status: "denied" };

export interface PushAdapter {
  /** False when this binary has no notification module. */
  isAvailable(): boolean;
  /** Shows the system permission prompt (if not yet decided) and, when granted, returns the Expo push token. Player-initiated only. */
  requestPermissionAndToken(): Promise<PushPermissionResult>;
}

export function unavailablePushAdapter(): PushAdapter {
  return {
    isAvailable: () => false,
    requestPermissionAndToken: () => Promise.reject(new Error("push notifications are not built into this app version")),
  };
}

export type PushOutcome =
  | { status: "registered"; updatedAt: string }
  | { status: "denied" }
  | { status: "unavailable" }
  | { status: "failed"; error: unknown };

export interface PushDeps {
  adapter: PushAdapter;
  api: Pick<ApiClient, "registerPushToken">;
  /** The per-install device id (`runtime/device-id.ts`). */
  deviceId: () => Promise<string>;
  platform: "ios" | "android" | null;
}

/** Called from a button, never from startup. Signed-in only: the endpoint needs a session (an `unauthenticated` ApiError is returned as `failed`). */
export async function enablePushNotifications(deps: PushDeps): Promise<PushOutcome> {
  if (!deps.adapter.isAvailable()) return { status: "unavailable" };
  let permission: PushPermissionResult;
  try {
    permission = await deps.adapter.requestPermissionAndToken();
  } catch (error) {
    return { status: "failed", error };
  }
  if (permission.status === "denied") return { status: "denied" };
  try {
    const r = await deps.api.registerPushToken({ deviceId: await deps.deviceId(), expoToken: permission.expoToken, ...(deps.platform ? { platform: deps.platform } : {}) });
    return { status: "registered", updatedAt: r.updatedAt };
  } catch (error) {
    return { status: "failed", error };
  }
}
