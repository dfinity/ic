# Certifying Service Worker

Certified fun guaranteed.

## Build

**TESTED**

From the root of this repo, `npm install && npm build`. The output should be in a `dist/` folder next to this file.

### Build With `FORCE_FETCH_ROOT_KEY`

**PARTIALLY TESTED**

By setting the `FORCE_FETCH_ROOT_KEY=1` environment variable prior to building, the service worker will
always fetch the root key of the network before doing the validation.

**THIS SHOULD ONLY BE USED ON A TEST OR LOCAL NETWORK.** The IC mainnet public key is hard coded in
the agent and, for security reasons, should not be fetched by the agent.

## Develop

**TESTED**

You will need to build the the repo first (see Build section above).

Start a replica on the port 8080 (doesn't have to be `dfx start` or a proxy, can be a plain replica).

Start a watch mode webpack build with `npm run build -- --watch`.

To start the local development instance: `npm start`. This will start serving the files built. Any path that don't match a file instead will be sent to localhost:8000.

It's important to not use `webpack-dev-server` (even if it's available) as it is not fully compatible with Service Workers.

## Commit

You may find it useful to install a pre-commit hook that formats the code.  See: `.husky/pre-commit`

## Deploy

There is no CI for the service worker, so please ensure that any changes are tested thoroughly before deployment.  Changes MUST be tested manually on all supported browsers.  Selenium tests are being developed to ease some, but not all, of this work.

**TESTED**

- Build and copy the artefacts into ansible territory: `npm run deploy`

**UTESTED AND UNDOCUMENTED**

- The rest of the deployment process
