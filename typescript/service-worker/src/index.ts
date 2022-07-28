function updateStatus(message: string) {
  const statusEl = document.getElementById('status');
  if (statusEl) {
    statusEl.innerText = message;
  }
}

window.addEventListener('load', async () => {
  // Verify user's web browser has necessary support
  const unsupported = [
    ['serviceWorker', window.navigator.serviceWorker],
    ['BigInt', window.BigInt],
    ['WebAssembly', window.WebAssembly],
  ]
    .filter((tuple) => !tuple[1])
    .map((tuple) => tuple[0])
    .join(', ');
  if (unsupported) {
    updateStatus(
      `This web browser cannot interact with the Internet Computer securely.  (No: ${unsupported})
       Please try new web browser software.`
    );
  } else {
    console.log(
      'Installing a service worker to proxy and validate raw content into the browser...'
    );
    // Ok, let's install the service worker...
    // note: if the service worker was already installed, when the browser requested <domain>/, it would have
    // proxied the response from <domain>/<canister-id>/, so this bootstrap file would have never been
    // retrieved from the boundary nodes
    try {
      await navigator.serviceWorker.register('sw.js');
    } catch (e) {
      await navigator.serviceWorker.register('/sw.js');
    }

    const registration = await navigator.serviceWorker.getRegistration();
    if (registration.active && !navigator.serviceWorker.controller) {
      // There's an active SW, but no controller for this tab. The service worker events are also _not_ fired.
      // This happens after a hard refresh --> Perform a soft reload to load everything from the SW.
      window.location.reload();
    }
  }
});
