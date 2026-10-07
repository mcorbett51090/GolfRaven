/**
 * Spies on every browser storage surface a token could be written to, installed on `globalThis` for node-level tests: localStorage, sessionStorage,
 * IndexedDB, Cache Storage, cookies (`document.cookie`), the Cookie Store API and `navigator.serviceWorker`, plus every `console` method. Each is a
 * Proxy that records ANY access (a get, a set, a call, a `has`), so "never touched" is a literal `calls.length === 0`, not "never wrote a known key".
 */
import { vi } from "vitest";

export interface StorageSpies {
  readonly calls: string[];
  restore(): void;
}

export function installStorageSpies(): StorageSpies {
  const calls: string[] = [];
  const saved = new Map<string, PropertyDescriptor | undefined>();
  const g = globalThis as unknown as Record<string, unknown>;

  const trap = (name: string): unknown =>
    new Proxy(function () {}, {
      get(_t, p) {
        calls.push(`${name}.get(${String(p)})`);
        return trap(`${name}.${String(p)}`);
      },
      set(_t, p) {
        calls.push(`${name}.set(${String(p)})`);
        return true;
      },
      has(_t, p) {
        calls.push(`${name}.has(${String(p)})`);
        return false;
      },
      apply() {
        calls.push(`${name}()`);
        return undefined;
      },
    });

  const define = (target: object, key: string, descriptor: PropertyDescriptor) => {
    const id = `${target === globalThis ? "globalThis" : "navigator"}.${key}`;
    if (!saved.has(id)) saved.set(id, Object.getOwnPropertyDescriptor(target, key));
    Object.defineProperty(target, key, { configurable: true, ...descriptor });
  };

  for (const name of ["localStorage", "sessionStorage", "indexedDB", "caches", "cookieStore"]) define(globalThis, name, { value: trap(name) });
  define(globalThis, "document", {
    value: {
      get cookie() {
        calls.push("document.cookie(get)");
        return "";
      },
      set cookie(_v: string) {
        calls.push("document.cookie(set)");
      },
    },
  });
  define(navigator, "serviceWorker", { value: trap("navigator.serviceWorker") });

  const consoleSpies = (["log", "info", "warn", "error", "debug", "trace"] as const).map((m) =>
    vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      calls.push(`console.${m}(${args.length} args)`);
    }),
  );

  return {
    calls,
    restore() {
      for (const s of consoleSpies) s.mockRestore();
      for (const [id, d] of saved) {
        const [scope, key] = id.split(".") as [string, string];
        const target = scope === "globalThis" ? globalThis : navigator;
        if (d === undefined) delete (target as unknown as Record<string, unknown>)[key];
        else Object.defineProperty(target, key, d);
      }
      void g;
    },
  };
}
