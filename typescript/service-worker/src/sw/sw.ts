import initResponseVerification from '@dfinity/response-verification';
import { ServiceWorkerEvents } from '../typings';
import { CanisterResolver } from './domains';
import { handleErrorResponse } from './views/error';
import { RequestProcessor } from './requests';

declare const self: ServiceWorkerGlobalScope;

// Always install updated SW immediately
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  // upon activation take control of all clients (tabs & windows)
  event.waitUntil(initResponseVerification().then(() => self.clients.claim()));
});

// Intercept and proxy all fetch requests made by the browser or DOM on this scope.
self.addEventListener('fetch', (event) => {
  const isNavigation = event.request.mode === 'navigate';
  try {
    const request = new RequestProcessor(event.request);
    event.respondWith(
      request
        .perform()
        .then((response) => {
          if (response.status >= 400) {
            return handleErrorResponse({
              isNavigation,
              error: response.statusText,
            });
          }

          return response;
        })
        .catch((e) => handleErrorResponse({ isNavigation, error: e }))
    );
  } catch (e) {
    return event.respondWith(
      handleErrorResponse({
        isNavigation,
        error: e,
      })
    );
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
