// install immediately
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => {
  // uninstall itself & then reload page
  self.registration
    .unregister()
    .then(function () {
      return self.clients.matchAll();
    })
    .then(function (clients) {
      clients.forEach((client) => client.navigate(client.url));
    });
});
