/* Replaces the old /vault/ service worker. It drops that registration and its caches. */
self.addEventListener("install", (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((key) => key !== "vault-app-v1").map((key) => caches.delete(key)));
      await self.registration.unregister();
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      await Promise.all(windows.map(async (client) => {
        const url = new URL(client.url);
        if (url.pathname.startsWith("/vault/app")) return;
        try {
          await client.navigate(new URL("/vault/app/", self.location.origin).href);
        } catch {
          /* The page can follow the redirect on its own. */
        }
      }));
    })(),
  );
});
