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
  await navigator.serviceWorker.ready;

  // // reload the page so the service worker can intercept the requests
  window.location.reload();
});
