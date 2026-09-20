const cacheName = "cascadia-shell-v2";
const isApi = (request) => new URL(request.url).pathname.startsWith("/api/");

self.addEventListener("install", (event) => event.waitUntil(self.skipWaiting()));
self.addEventListener("activate", (event) => event.waitUntil((async () => {
  await Promise.all((await caches.keys()).filter((key) => key !== cacheName).map((key) => caches.delete(key)));
  await self.clients.claim();
})()));
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET" || isApi(event.request)) return;
  event.respondWith(fetch(event.request).then((response) => {
    if (response.ok && new URL(event.request.url).origin === self.location.origin && event.request.mode !== "navigate") void caches.open(cacheName).then((cache) => cache.put(event.request, response.clone()));
    return response;
  }).catch(async () => (await caches.match(event.request)) ?? (event.request.mode === "navigate" ? await caches.match("/") : Response.error())));
});
