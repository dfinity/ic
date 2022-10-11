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

## Testing locally
1. Install [mkcert](https://github.com/FiloSottile/mkcert).
      ```shell
      brew install mkcert
      brew install nss # optional, for Firefox support
      ```
1. Optionally, install the mkcert root CA
      ```shell
      mkcert -install
      ```
1. Generate SSL certificates:
      ```shell
      npm run create-ssl-certs
      ```
1. Add the following to your `/etc/hosts` file.
      ```shell
      127.0.0.1 ic0.local

      # Internet Identity
      127.0.0.1 rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.local
      127.0.0.1 identity.ic0.local

      # NNS
      127.0.0.1 qoctq-giaaa-aaaaa-aaaea-cai.ic0.local
      127.0.0.1 nns.ic0.local

      # Distrikt
      127.0.0.1 az5sd-cqaaa-aaaae-aaarq-cai.ic0.local
      127.0.0.1 distrikt.ic0.local

      # Distrikt Staging
      127.0.0.1 am2do-dyaaa-aaaae-aaasa-cai.ic0.local
      127.0.0.1 distrikt-staging.ic0.local

      # DSCVR
      127.0.0.1 h5aet-waaaa-aaaab-qaamq-cai.ic0.local
      127.0.0.1 dscvr.ic0.local
      ```
1. Set the `hostnameCanisterIdMap` value in the `http_request.ts` file (make sure to revert this before commiting):
      ```shell
      const hostnameCanisterIdMap: Record<string, [string, string]> = {
            'identity.ic0.local': ['rdmx6-jaaaa-aaaaa-aaadq-cai', 'ic0.app'],
            'nns.ic0.local': ['qoctq-giaaa-aaaaa-aaaea-cai', 'ic0.app'],
            'dscvr.ic0.local': ['h5aet-waaaa-aaaab-qaamq-cai', 'ic0.app'],
            'distrikt.ic0.local': ['az5sd-cqaaa-aaaae-aaarq-cai', 'ic0.app'],
            'distrikt-staging.ic0.local': ['am2do-dyaaa-aaaae-aaasa-cai', 'ic0.app'],
      };
      ```
1. Build and watch the service worker:
      ```shell
      npm run build-dev -- --watch
      ```
1. In a separate shell, build and run the docker image:
      ```shell
      docker compose up
      ```
1. If you installed the root CA, that's all there is to do. If you chose not to install the root CA, then you will need to launch your browser with certain flags:
      ```
      /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --user-data-dir=/tmp/no-ssl --ignore-certificate-errors
      ```

## Release

1. Create MR that updates `version` in `package.json`
2. Test the built artifact using testnet boundary node VMs
   1. TODO https://dfinity.atlassian.net/browse/L2-442
3. Merge MR to master
4. Tag the commit on `master` with `service-worker_v${version}`
5. Verify that the desired version has been pushed to NPM: https://www.npmjs.com/package/@dfinity/service-worker
6. Create an MR for the boundary nodes team that updates the `sw_version` and `sw_sha256` in `ic-os/boundary-guestos/rootfs/Dockerfile`
