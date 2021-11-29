import { handleRequest } from './http_request';

declare const self: ServiceWorkerGlobalScope;

const DEBUG = true;

// Always install updated SW immediately
self.addEventListener('install', () => {
  self.skipWaiting();
});

// Intercept and proxy all fetch requests made by the browser or DOM on this scope.
self.addEventListener('fetch', (event: FetchEvent) => {
  try {
    const response = handleRequest(event.request);
    event.respondWith(response);
  } catch (e) {
    let error_message = String(e);
    console.error(error_message);
    if (DEBUG) {
      return event.respondWith(
        new Response(error_message, {
          status: 501,
        }),
      );
    }
    event.respondWith(new Response('Internal Error', { status: 502 }));
  }
});
