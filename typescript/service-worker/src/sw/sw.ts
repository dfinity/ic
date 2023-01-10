import { ServiceWorkerEvents } from '../typings';
import { CanisterResolver } from './domains';
import { handleRequest } from './http_request';

declare const self: ServiceWorkerGlobalScope;

const DEBUG = true;

// Always install updated SW immediately
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  // upon activation take control of all clients (tabs & windows)
  event.waitUntil(self.clients.claim());
});

// Intercept and proxy all fetch requests made by the browser or DOM on this scope.
self.addEventListener('fetch', (event) => {
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

// handle events from the client messages
self.addEventListener('message', async (event) => {
  const body = event.data;
  switch (body?.action) {
    case ServiceWorkerEvents.SaveICHostInfo: {
      const resolver = await CanisterResolver.setup();
      await resolver.saveICHostInfo(body.data);
      break;
    }
  }
});
