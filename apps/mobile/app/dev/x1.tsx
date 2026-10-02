import { Redirect } from "expo-router";

/**
 * Development-only route. `golfraven://dev/x1` exists in every build because
 * expo-router creates a deep link for every file under `app/`. In a release
 * build (`!__DEV__`) this route redirects to the home tab instead of rendering.
 *
 * The screen is `require`d inside a `__DEV__` ternary, not imported, so that
 * Metro's constant folding drops it — and the Health Connect reader behind it
 * — from release bundles. (An early `if (!__DEV__) return` followed by a
 * `require` does NOT work: the require is still collected as a dependency.
 * Checked by exporting both platforms and grepping the bundles; see README.)
 */
const X1Screen = __DEV__ ? (require("../../src/screens/X1Screen") as typeof import("../../src/screens/X1Screen")).X1Screen : null;

export default function X1Route() {
  if (!X1Screen) return <Redirect href="/" />;
  return <X1Screen />;
}
