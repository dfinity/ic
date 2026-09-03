# Deploying canisters to ic-local-net

The local network speaks the standard IC public spec on `http://localhost:8080`
(node-0). dfx, icp-cli, ic-agent, and curl-over-CBOR all work. This document
covers dfx (full deploy path) and icp-cli (ping/inspection — see notes on
deploys below).

## One-time dfx setup

Add a network entry to `~/.config/dfx/networks.json`:

```json
{
  "local-cluster": {
    "providers": ["http://localhost:8080"],
    "type": "ephemeral"
  }
}
```

`ephemeral` tells dfx not to manage the replica process or expect a
persistent wallet canister.

## Deploying

dfx insists on a wallet canister by default, which we don't have (and don't
need — `prep.sh` set the provisional whitelist to `["*"]`, so
`provisional_create_canister_with_cycles` is allowed). Pass `--no-wallet` to
`dfx canister create` and the rest works normally:

```sh
dfx canister --network local-cluster create --all --no-wallet
dfx build
dfx canister --network local-cluster install --all
```

`dfx deploy --network local-cluster` will fail with `cannot use a wallet
before dfx start` because it tries to use a wallet implicitly. The
three-step flow above is the workaround.

## Smoke test from scratch

```sh
mkdir /tmp/ic-local-smoke && cd /tmp/ic-local-smoke
dfx new hello --type=motoko --no-frontend
cd hello
dfx canister --network local-cluster create --all --no-wallet
dfx build
dfx canister --network local-cluster install --all
dfx canister --network local-cluster call hello_backend greet '("world")'
# → ("Hello, world!")
```

## Canister IDs

`prep.sh` passes `--use-specified-ids-allocation-range` to `ic-prep`, so
the subnet has the canister-ID range that matches mainnet conventions
(the same range `dfx start` uses). The first canister you create will be
`bnz7o-iuaaa-aaaaa-qaaaa-cai`, the second `bd3sg-...`, and so on — i.e.
familiar dfx IDs work.

## NNS-dependent flows

Anything that requires NNS canisters (`dfx wallet`, `dfx ledger`,
`dfx nns ...`, governance proposals, cycles-ledger interactions) needs
the NNS canisters installed first. Run `./nns-init.sh` against the
running network — it builds and installs Registry, Governance, Root,
Lifeline, Cycles-Minting, Ledger, GTC, SNS-WASM, and friends as real
canisters on the existing subnet. After that, `ic-admin --nns-url
http://localhost:8080 get-topology` works, and so do the dfx
NNS-dependent commands.

## Using icp-cli

[icp-cli](https://cli.internetcomputer.org) is the newer successor to dfx.
It uses an `icp.yaml` per project (vs. dfx's `dfx.json` + `networks.json`).

A pre-made `icp.yaml` lives in this directory, declaring the network as
`local-cluster`. From here you can:

```sh
cd dev/local-net
icp network ping local-cluster
icp environment list
```

### Pointing your own project at this network

In your project's `icp.yaml`, add the network and a matching environment:

```yaml
networks:
  - name: local-cluster
    mode: connected
    url: http://localhost:8080
    # Optional but required for any cert-verifying call (anything beyond
    # `ping`). Extract from the local network's NNS public key:
    #   grep -v 'PUBLIC KEY' .../bootstrap/nns_public_key.pem \
    #     | tr -d '\n' | base64 -d | xxd -p | tr -d '\n'
    root-key: 308182301d060d2b06...

environments:
  - name: local-cluster
    network: local-cluster
    canisters: [your_canister_names]
```

Then deploy with:

```sh
icp deploy your_canister -e local-cluster
```

### Caveat: `icp deploy` requires the Cycles Ledger

icp-cli's deploy flow funds new canisters through the **Cycles Ledger**
canister (`um5iw-rqaaa-aaaaq-qaaba-cai`). That canister is not installed by
`nns-init.sh` — it lives in a separate repo
([dfinity/cycles-ledger](https://github.com/dfinity/cycles-ledger)). Until
that's plumbed in, `icp deploy` against this network will fail with
`Canister um5iw-rqaaa-aaaaq-qaaba-cai not found`.

For day-to-day canister deployment, use **dfx** (above) — its
`provisional_create_canister_with_cycles` path is the documented local-dev
flow and works without a cycles ledger.

`icp-cli` is still useful here for:

- `icp network ping local-cluster` — confirm the network is alive
- `icp canister status <id> -e local-cluster` — inspect canisters you
  already know the ID of (e.g. the NNS canisters after `nns-init.sh`,
  or canisters you deployed via dfx)
- `icp canister logs <id> -e local-cluster` — read canister logs
- `icp canister call <id> <method> ... -e local-cluster` — call methods
