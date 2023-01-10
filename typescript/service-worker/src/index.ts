import {
  ICHostInfoEvent,
  SaveICHostInfoMessage,
  ServiceWorkerEvents,
} from './typings';
import { getValueFromCookie } from './utils';

function updateStatus(message: string) {
  const statusEl = document.getElementById('status');
  if (statusEl) {
    statusEl.innerText = message;
  }
}

function resolveICHostInfo(): ICHostInfoEvent | null {
  const gateway = getValueFromCookie('__Secure-IcGateway');
  const canisterId = getValueFromCookie('__Secure-IcCanisterId');
  if (gateway && canisterId) {
    return {
      hostname: window.location.hostname,
      canisterId,
      gateway,
    };
  }

  return null;
}

window.addEventListener('load', async () => {
  // Verify user's web browser has necessary support
  const unsupported = [
    ['serviceWorker', window.navigator.serviceWorker],
    ['BigInt', window.BigInt],
    ['WebAssembly', window.WebAssembly],
    ['indexedDB', window.indexedDB],
  ]
    .filter((tuple) => !tuple[1])
    .map((tuple) => tuple[0])
    .join(', ');
  if (unsupported) {
    updateStatus(
      `This web browser cannot interact with the Internet Computer securely.  (No: ${unsupported})
       Please try new web browser software.`
    );

    return;
  }

  console.log(
    `Installing a service worker ${process.env.VERSION} to proxy and validate content...`
  );

  // Ok, let's install the service worker...
  // note: if the service worker was already installed, when the browser requested <domain>/, it would have
  // proxied the response from <domain>/<canister-id>/, so this bootstrap file would have never been
  // retrieved from the boundary nodes
  await navigator.serviceWorker.register('/sw.js');

  // delays code execution until serviceworker is ready
  const worker = await navigator.serviceWorker.ready;

  // caches the domain ic host equivalent to avoid an additional fetch call
  const icHostInfo = resolveICHostInfo();
  if (icHostInfo) {
    const message: SaveICHostInfoMessage = {
      action: ServiceWorkerEvents.SaveICHostInfo,
      data: icHostInfo,
    };
    worker.active.postMessage(message);
  }

  // // reload the page so the service worker can intercept the requests
  window.location.reload();
});
