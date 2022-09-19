# DFINITY Service Worker

Service worker which transforms browser asset request to the IC to canister calls and verifies the asset certification.

## Build

| Usage                  | Folder    | Command             | Note                                              |
| ---------------------- | --------- | ------------------- | ------------------------------------------------- |
| dev build for testnets | dist-dev  | `npm run build-dev` | - sets `FORCE_FETCH_ROOT_KEY=1`<br>- not minified |
| prod build for mainnet | dist-prod | `npm run build`     | - uses IC root key<br>- minified                  |

### Prerequisites

- Node.js 17
- npm 8.5

### Build With `FORCE_FETCH_ROOT_KEY`

By setting the `FORCE_FETCH_ROOT_KEY=1` environment variable prior to building, the service worker will
always fetch the root key of the network before doing the validation.

**THIS SHOULD ONLY BE USED ON A TEST OR LOCAL NETWORK.** The IC mainnet public key is hard coded in
the agent and, for security reasons, should not be fetched by the agent.

## Develop

To start the local development instance:

1. Run `npm install`
2. Run `npm start`

This will start serving the files built using `npm run build-dev` on http://localhost:8080. Any path that don't match a file instead will be sent to https://ic0.app.
Note that for the service worker to correctly relay the canister call to a canister there must be a query parameter `canisterId=<canisterId>`.
The service worker can be tested against any mainnet canister.

For example:

- Internet Identity: http://localhost:8080/?canisterId=rdmx6-jaaaa-aaaaa-aaadq-cai
- DSCVR: http://localhost:8080/?canisterId=h5aet-waaaa-aaaab-qaamq-cai

### Developing locally on Safari

Safari does not allow service workers to be served on non-secure connections, even on localhost. So to test the service worker locally first follow the setup instructions on [web.dev](https://web.dev/how-to-use-local-https/) (except for the final step to generate SSL certs), then generate SSL certificates by running `npm run create-ssl-certs`. This will create self-signed certificates that will be stored in a temporary folder called `certs`. Now you can run `npm run start-ssl`. Now you can test using HTTPS.

For example:

- Internet Identity: https://localhost:8080/?canisterId=rdmx6-jaaaa-aaaaa-aaadq-cai
- DSCVR: https://localhost:8080/?canisterId=h5aet-waaaa-aaaab-qaamq-cai

## Generating HTTP Gateway bindings

### JavaScript binding

Generate the binding:

```shell
didc bind ./src/http-interface/canister_http_interface.did --target js > ./src/http-interface/canister_http_interface.js
```

Then move the `StreamingCallbackHttpResponse` variable outside of the `idlFactory` function, rename to `streamingCallbackHttpResponseType` and then export it.

```typescript
export const streamingCallbackHttpResponseType = // ...
```

and then add the `import { IDL } from '@dfinity/candid';` import, move the `Token` variable outside of the `idlFactory` function, and set its value to be `IDL.Unknown`.

```typescript
import { IDL } from '@dfinity/candid';

const Token = IDL.Unknown;
```

### TypeScript binding

Generate the binding:

```shell
didc bind ./src/http-interface/canister_http_interface.did --target ts > ./src/http-interface/canister_http_interface_types.d.ts
```

Add the following import:

```typescript
import { IDL } from '@dfinity/candid';
```

and then replace:

```typescript
export type Token = { type: any };
```

with:

```typescript
export type Token = { type: <T>() => IDL.Type<T> };
```

## Release

1. Create MR that updates `version` in `package.json`
2. Test the built artifact using testnet boundary node VMs
   1. TODO https://dfinity.atlassian.net/browse/L2-442
3. Merge MR to master
4. Tag the commit on `master` with `service-worker_v${version}`
5. Verify that the desired version has been pushed to NPM: https://www.npmjs.com/package/@dfinity/service-worker
6. Create an MR for the boundary nodes team that updates the `sw_version` and `sw_sha256` in `ic-os/boundary-guestos/rootfs/Dockerfile`
