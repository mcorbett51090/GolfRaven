/** The CSPRNG: `expo-crypto`'s `getRandomBytes` (native; throws `UnavailabilityError` rather than falling back to `Math.random` in a release
 * build; in a dev build with remote JS debugging it falls back to `Math.random`, which is why nothing here may be treated as secret in dev). */
import { getRandomBytes } from "expo-crypto";
import type { RandomBytes } from "./nonce";

export const expoRandomBytes: RandomBytes = (n) => getRandomBytes(n);
