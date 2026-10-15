const CACHE = "vault-app-v3";

const ASSETS = [
  "./",
  "index.html",
  "styles.css",
  "app.js",
  "config.js",
  "vault-app.webmanifest",
  "icon.svg",
  "icon-192.png",
  "icon-512.png",
  "icon-maskable-512.png",
  "apple-touch-icon.png",
  "lib/email.js",
  "lib/crypto.js",
  "lib/merge.js",
  "lib/password.js",
  "lib/backup.js",
];

const SHELL_PATHS = new Set(["/vault/app", "/vault/app/", "/vault/app/index.html"]);

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
      const shell =
        (await cache.match(new URL("index.html", self.registration.scope))) ||
        (await cache.match(new URL("./", self.registration.scope)));
      if (shell) {
        await cache.put(new URL("./", self.registration.scope), shell.clone());
        await cache.put(new URL("index.html", self.registration.scope), shell.clone());
      }
      await self.skipWaiting();
    }),
  );
});

/* Only delete our own old caches: other apps share this origin. */
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key.startsWith("vault-") && key !== CACHE).map((key) => caches.delete(key))))
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
  event.respondWith(networkFirst(request, url));
});

async function networkFirst(request, url) {
  const cache = await caches.open(CACHE);
  try {
    const fresh = await fetch(request);
    if (fresh.ok) {
      await cache.put(new Request(url.href), fresh.clone());
      return fresh;
    }
    if (request.mode !== "navigate") return fresh;
  } catch {
    /* Offline or blocked. Serve the cached shell for the start URL. */
  }
  const cached = await cache.match(url.href, { ignoreSearch: true });
  if (cached) return cached;
  if (request.mode === "navigate" && SHELL_PATHS.has(url.pathname)) {
    const shell = await shellResponse(cache);
    if (shell) return shell;
  }
  return new Response("Offline", {
    status: 504,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

async function shellResponse(cache) {
  return (
    (await cache.match(new URL("./", self.registration.scope))) ||
    (await cache.match(new URL("index.html", self.registration.scope))) ||
    (await cache.match(new URL("/vault/app/", self.location.origin))) ||
    (await cache.match(new URL("/vault/app/index.html", self.location.origin)))
  );
}
