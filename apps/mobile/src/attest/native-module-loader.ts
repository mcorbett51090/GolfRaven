/**
 * Finds the local Expo module at runtime. The ONLY file that imports `expo` for it, and imported only by the composition root (`runtime/services.ts`), so
 * the rest of `src/attest` stays loadable under Node. `requireOptionalNativeModule` returns `null` when the module is not linked: Expo Go, the web, a
 * binary built before the module existed. `null` means "this build cannot attest": `selectAttestor` then keeps `UnattestableAttestor`.
 */
import { requireOptionalNativeModule } from "expo";
import type { NativeAttestModule } from "./native-module";

export const NATIVE_MODULE_NAME = "GolfravenAttest";

export function loadNativeAttestModule(): NativeAttestModule | null {
  try {
    return requireOptionalNativeModule<NativeAttestModule>(NATIVE_MODULE_NAME);
  } catch {
    return null;
  }
}
