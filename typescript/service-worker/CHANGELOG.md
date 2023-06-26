# Changelog

## Unreleased 

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
