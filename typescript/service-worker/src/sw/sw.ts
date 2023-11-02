import { AgentHTTPResponseError } from '@dfinity/agent/lib/cjs/agent/http/errors';
import { ServiceWorkerEvents, ServiceWorkerMessages } from '../typings';
import { CanisterResolver } from './domains';
import { RequestProcessor } from './requests';
import {
  getBoundaryNodeRequestId,
  loadResponseVerification,
  reloadServiceWorkerClients,
  uninstallServiceWorker,
} from './requests/utils';
import { handleErrorResponse } from './views/error';

declare const self: ServiceWorkerGlobalScope;

// Always install updated SW immediately
self.addEventListener('install', (event) => {
  event.waitUntil(loadResponseVerification().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  // upon activation take control of all clients (tabs & windows)
  event.waitUntil(self.clients.claim());
});

// Intercept and proxy all fetch requests made by the browser or DOM on this scope.
self.addEventListener('fetch', (event) => {
  event.respondWith(
    (async () => {
      const isNavigation = event.request.mode === 'navigate';
      const request = new RequestProcessor(event.request);

      try {
        const response = await request.perform();

        if (response.status >= 400) {
          return handleErrorResponse({
            isNavigation,
            requestId: request.requestId,
            error: response.statusText ?? (await response.text()),
            request: event.request,
            response,
          });
        }

        return response;
      } catch (error) {
        let requestId = request.requestId;
        if (error instanceof AgentHTTPResponseError) {
          requestId = getBoundaryNodeRequestId(error.response);
        }

        return await handleErrorResponse({
          isNavigation,
          requestId,
          error,
          request: event.request,
        });
      }
    })()
  );
});

// handle events from the client messages
self.addEventListener('message', async (event) => {
  const body = event.data as ServiceWorkerMessages;
  switch (body?.action) {
    case ServiceWorkerEvents.SaveICHostInfo: {
      const resolver = await CanisterResolver.setup();
      await resolver.saveICHostInfo(body.data);
      break;
    }
    case ServiceWorkerEvents.ResetServiceWorker: {
      await uninstallServiceWorker();
      if (body.data.reloadFromWorker) {
        await reloadServiceWorkerClients();
      }
      break;
    }
  }
});
