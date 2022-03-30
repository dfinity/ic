# DFINITY Service Worker

Service worker which transforms browser asset request to the IC to canister calls and verifies the asset certification.

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

## Release
1. Create MR that updates `version` in `package.json`
2. Test the built artifact using testnet boundary node VMs
   1. TODO https://dfinity.atlassian.net/browse/L2-442
3. Merge MR to master
4. Tag the commit on `master` with `service-worker_v${version}`
5. Verify that the desired version has been pushed to NPM: https://www.npmjs.com/package/@dfinity/service-worker
6. Create an MR for the boundary nodes team that updates the `sw_version` and `sw_sha256` in `ic-os/boundary-guestos/rootfs/Dockerfile`
