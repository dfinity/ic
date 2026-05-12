# Deploying canisters to ic-local-net

The local network speaks the standard IC public spec on `http://localhost:8080`
(node-0). dfx, ic-agent, and curl-over-CBOR all work. This document covers
the dfx path.

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
