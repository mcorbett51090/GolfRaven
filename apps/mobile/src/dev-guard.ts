/**
 * "Release builds never construct the mock." Every mock (`api/mock.ts`, `auth/mock-auth.ts`) takes a `DevOnly` token as its FIRST argument,
 * and the only way to get one is `devOnly(isDev)`, which throws `MockInReleaseError` when `isDev` is false. Three independent layers hold
 * the line (each has a test, `test/backend.test.ts`):
 *  1. selection: `selectBackendKind` never returns "demo" when `isDev` is false (`runtime/backend.ts`);
 *  2. construction: a mock cannot be built without the token, and the token cannot be made in a release build (this file);
 *  3. bundling: nothing statically imports a mock module, and the one `require` of it sits under `__DEV__` so Metro drops it from a release
 *     bundle (`runtime/dev-backend.ts`; the source scan in `test/backend.test.ts`, and an `expo export` grep recorded in the README).
 */
declare const devOnlyBrand: unique symbol;
export interface DevOnly {
  readonly [devOnlyBrand]: true;
}

export class MockInReleaseError extends Error {
  constructor() {
    super("a mock backend was requested in a release build; this is a bug (mocks exist for tests and the __DEV__ demo only)");
    this.name = "MockInReleaseError";
  }
}

/** The tokens `devOnly` has issued: a hand-made object cast to `DevOnly` is not one of them (`assertDevOnly`). */
const issued = new WeakSet<object>();

export function devOnly(isDev: boolean): DevOnly {
  if (!isDev) throw new MockInReleaseError();
  const token = Object.freeze({}) as DevOnly;
  issued.add(token);
  return token;
}

/** Called first thing by every mock factory: the type system is not the only line, the token must really have come from `devOnly(true)`. */
export function assertDevOnly(token: unknown): void {
  if (typeof token !== "object" || token === null || !issued.has(token)) throw new MockInReleaseError();
}
