/**
 * sw.js — GolfRaven service worker (offline + installable). Adapted from
 * southern-wine-country's `public/sw.js` @ 572ff7e (build plan §5.1:
 * "Adapt | same | Cache `gr-v1`; app name 'GolfRaven'.").
 *
 * Same two strategies SWC used, deliberately unchanged (this is a well-
 * tested pattern, not a golf-specific concern):
 *
 *   • NAVIGATIONS (HTML) — network-first with a short timeout, cache as
 *     fallback. HTML names the hashed asset bundle, so a cached page pins
 *     the visitor to an old build; the timeout keeps this honest on bad
 *     signal (courses are exactly as rural as vineyards).
 *
 *   • EVERYTHING ELSE (CSS/JS/OG images/map GeoJSON) — cache-first,
 *     refreshed in the background. Content-hashed, so a cached copy is
 *     never the wrong copy.
 *
 * External map tiles (a different origin — `map-config.mjs`'s configured
 * tile host) are left to the network and simply don't render offline; the
 * JS-free course list (`CourseMap.astro`) still works.
 */
const CACHE = "gr-v1";
const HOME = new URL("./", self.registration.scope).href;
const SHELL = ["./", "./trails/", "./claim/", "./fr/"];

/** See SWC's own doc for the reasoning — a bare network-first would make
 * every repeat visit pay a full round-trip even when the connection is
 * merely slow, which is worse than the (bounded) staleness risk below. */
const NAV_TIMEOUT_MS = 3000;

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => Promise.allSettled(SHELL.map((u) => cache.add(u))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Copy-forward BEFORE delete — a cache-name bump on a flaky network
      // must never produce an empty new cache AND a deleted old one
      // (a total offline blackout). Inert while CACHE is unchanged, and
      // that's the point: it has to already be deployed before CACHE ever
      // changes.
      const cache = await caches.open(CACHE);
      const names = await caches.keys();
      for (const name of names) {
        if (name === CACHE) continue;
        try {
          const old = await caches.open(name);
          for (const req of await old.keys()) {
            if (await cache.match(req)) continue;
            const res = await old.match(req);
            if (res) await cache.put(req, res);
          }
          await caches.delete(name);
        } catch {
          /* copy failed — keep the old cache; stale beats nothing */
        }
      }
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // external tile host -> default network

  if (req.mode === "navigate") {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE);
        let timer;
        try {
          const res = await Promise.race([
            fetch(req).then((r) => {
              if (r && r.ok && r.type === "basic") cache.put(req, r.clone());
              return r;
            }),
            new Promise((_, reject) => {
              timer = setTimeout(() => reject(new Error("nav-timeout")), NAV_TIMEOUT_MS);
            }),
          ]);
          if (res) return res;
        } catch {
          /* offline/error/slow -> fall through to cache */
        } finally {
          clearTimeout(timer);
        }
        return (await cache.match(req)) || (await cache.match(HOME)) || Response.error();
      })(),
    );
    return;
  }

  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(req);
      const network = fetch(req)
        .then((res) => {
          if (res && res.ok && res.type === "basic") cache.put(req, res.clone());
          return res;
        })
        .catch(() => null);
      return cached || (await network) || Response.error();
    }),
  );
});
