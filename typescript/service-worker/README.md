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

      # Nuance
      127.0.0.1 exwqn-uaaaa-aaaaf-qaeaa-cai.ic0.local
      127.0.0.1 nuance.ic0.local

      # Open Chat
      127.0.0.1 6hsbt-vqaaa-aaaaf-aaafq-cai.ic0.local
      127.0.0.1 oc.ic0.local

      # Local custom domains for service worker
      127.0.0.1 demo.ic.local
      127.0.0.1 internetcomputer.ic.local
      127.0.0.1 distrikt.ic.local
      127.0.0.1 dscvr.ic.local
      127.0.0.1 nns.ic.local
      ```
1. Set the `hostnameCanisterIdMap` value in the `domains/static.ts` file (make sure to revert this before commiting):
      ```shell
      Object.entries({
            'identity.ic0.local': {
                  canister: {
                        principal: Principal.from('rdmx6-jaaaa-aaaaa-aaadq-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'nns.ic0.local': {
                  canister: {
                        principal: Principal.from('qoctq-giaaa-aaaaa-aaaea-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'dscvr.ic0.local': {
                  canister: {
                        principal: Principal.from('h5aet-waaaa-aaaab-qaamq-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'distrikt.ic0.local': {
                  canister: {
                        principal: Principal.from('az5sd-cqaaa-aaaae-aaarq-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'distrikt-staging.ic0.local': {
                  canister: {
                        principal: Principal.from('am2do-dyaaa-aaaae-aaasa-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'nuance.ic0.local': {
                  canister: {
                        principal: Principal.from('exwqn-uaaaa-aaaaf-qaeaa-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
            'oc.ic0.local': {
                  canister: {
                        principal: Principal.from('6hsbt-vqaaa-aaaaf-aaafq-cai'),
                        gateway: DEFAULT_GATEWAY,
                  },
            },
      });
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

1. Make an MR to bump the service worker version
      1. Update `version` in `package.json`
      1. Run `npm i --package-lock-only`
      1. Test the built artifact using testnet boundary node VMs
            - Currently needs to be done before making the MR as the boundary nodes are not built if only service worker files are updated
1. Merge MR to master
1. Tag the commit on `master` with `service-worker_v${version}`
1. Verify that the desired version has been pushed to NPM: https://www.npmjs.com/package/@dfinity/service-worker
1. Create an MR for the boundary nodes team that updates the `sw_version` and `sw_sha256` in `ic-os/boundary-guestos/rootfs/Dockerfile`
