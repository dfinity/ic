import { handleRequest } from './http_request';

declare const self: ServiceWorkerGlobalScope;

const DEBUG = true;

// Always install updated SW immediately
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', async () => {
  // upon activation take control of all clients (tabs & windows)
  await self.clients.claim();
  // reload all clients
  const clients = (await self.clients.matchAll()) as WindowClient[];
  clients.forEach((client) => client.navigate(client.url));
});

// Intercept and proxy all fetch requests made by the browser or DOM on this scope.
self.addEventListener('fetch', (event: FetchEvent) => {
  try {
    const response = handleRequest(event.request);
    event.respondWith(response);
  } catch (e) {
    const error_message = String(e);
    console.error(error_message);
    if (DEBUG) {
      return event.respondWith(
        new Response(error_message, {
          status: 501,
        })
      );
    }
    event.respondWith(new Response('Internal Error', { status: 502 }));
  }
});
