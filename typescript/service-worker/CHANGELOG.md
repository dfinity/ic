# Changelog

## Unreleased

## 1.8.8

- Upgrade response verification package to version 1.2.0. Fixing an issue non-latin characters in the URL path.
- Fix an issue where `/_/` paths on requests to non-raw domains was throwing an exception.

## 1.8.7

- Upgrade response verification package to version 1.1.0. Fixing an issue with query param decoding on asset URLs.
- Button added to the main error page to uninstall the active service worker and reload all associated client windows
- Added theme color to the main error page and service worker installation page

## 1.8.6

- Revert usage of DecompressionStreams API, it is not yet widely supported by Safari or Firefox

## 1.8.5

- Fix service worker upgrades that would try to load the new wasm module from the old service worker, the wasm is now inline loaded

## 1.8.4

- upgrade response verification package to version 1.0.0

## 1.8.3

- Upgrade agent-js to version 0.18.0
- Add boundary node X-Request-Id to the error page and logs

## 1.8.2

- Re-enable response verification v2

## 1.8.1

- Temporarily disable response verification v2 until asset canister v0.14.1 is sufficiently circulated

## 1.8.0

- Allow redirects for canisters implementing response verification v2
- Show error details when an exception occurs to make error reporting easier for end users

## 1.7.2

- Moved wasm loading to the install event, this prevents the Service Worker from becoming active without required dependencies

## 1.7.1

- Do not throw exceptions for response bodies larger than 10mb

## 1.7.0

- Integrate verification logic with `@dfinity/response-verification` package

## 1.6.1 (2023-03-26)

- Create a new IndexedDB database instead of upgrading the version of the existing one, this allows Service Worker releases to be rolled back easily
- Fix an issue with resolving the root domain of the service worker on custom domains

## 1.6.0 (2023-03-15)

- Reduce the number of HEAD requests made for custom domain resolution
- Add a custom error page for `navigation` type requests that fail
- Fix raw domain detection on testnets
- Add a custom error page for service worker installation failures
