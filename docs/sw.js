const CACHE = "vault-shell-v1";

const ASSETS = [
  "./",
  "index.html",
  "styles.css",
  "app.js",
  "config.js",
  "manifest.json",
  "icon.svg",
  "icon-192.png",
  "icon-512.png",
  "apple-touch-icon.png",
  "lib/email.js",
  "lib/crypto.js",
  "lib/merge.js",
  "lib/password.js",
  "lib/backup.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then(async (cache) => {
      await Promise.all(
        ASSETS.map(async (path) => {
          try {
            const response = await fetch(new URL(path, self.registration.scope));
            if (response.ok) await cache.put(new URL(path, self.registration.scope), response);
          } catch {
            /* A missing shell file must not block installation. */
          }
        }),
      );
      await self.skipWaiting();
    }),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  const scopePath = new URL(self.registration.scope).pathname;
  if (!url.pathname.startsWith(scopePath)) return;
  event.respondWith(networkFirst(request));
});

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    const fresh = await fetch(request);
    if (fresh.ok) await cache.put(request, fresh.clone());
    return fresh;
  } catch {
    const cached = await cache.match(request);
    if (cached) return cached;
    throw new Error("offline");
  }
}
