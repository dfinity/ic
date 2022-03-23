# IC Service Worker

Service worker which transforms browser asset request to canister calls and verifies the asset certification.

## Build

| Usage                  | Folder    | Command             | Note                                              |
|------------------------|-----------|---------------------|---------------------------------------------------|
| dev build for testnets | dist-dev  | `npm run build-dev` | - sets `FORCE_FETCH_ROOT_KEY=1`<br>- not minified |
| prod build for mainnet | dist-prod | `npm run build`     | - uses IC root key<br>- minified                  |


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
* Internet Identity: http://localhost:8080/?canisterId=rdmx6-jaaaa-aaaaa-aaadq-cai
* DSCVR: http://localhost:8080/?canisterId=h5aet-waaaa-aaaab-qaamq-cai

