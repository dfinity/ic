# Proposal to upgrade the ledger suite orchestrator canister to add ckWSTETH

Git hash: `de29a1a55b589428d173b31cdb8cec0923245657`

New compressed Wasm hash: `81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/131374

---

## Motivation

This proposal upgrades the ckERC20 ledger suite orchestrator to add support for [wstETH](https://etherscan.io/token/0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0#tokenInfo). Once executed, the twin token ckWSTETH will be available on ICP, refer to the [documentation](https://github.com/dfinity/ic/blob/master/rs/ethereum/cketh/docs/ckerc20.adoc) on how to proceed with deposits and withdrawals.

## Upgrade args

```
git fetch
git checkout de29a1a55b589428d173b31cdb8cec0923245657
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { AddErc20Arg = record { contract = record { chain_id = 1; address = "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0" }; ledger_init_arg = record { decimals = 18; transfer_fee = 1_000_000_000_000; token_symbol = "ckWSTETH"; token_name = "ckWSTETH"; token_logo = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAiIGhlaWdodD0iODAiIHZpZXdCb3g9IjAgMCA4MCA4MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXAwXzI3NzZfMzgwMSkiPgo8cmVjdCB3aWR0aD0iODAiIGhlaWdodD0iODAiIHJ4PSI0MCIgZmlsbD0iIzAwQTNGRiIvPgo8cGF0aCBvcGFjaXR5PSIwLjYiIGQ9Ik01NC43NjcyIDM1Ljk0MzdMNTUuMTcwMyAzNi41NjJDNTkuNzE2MSA0My41MzU0IDU4LjcwMDkgNTIuNjY4MSA1Mi43Mjk0IDU4LjUxOTFDNDkuMjE2NCA2MS45NjEyIDQ0LjYxMjIgNjMuNjgyNSA0MC4wMDc5IDYzLjY4M0M0MC4wMDc5IDYzLjY4MyA0MC4wMDc5IDYzLjY4MyA1NC43NjcyIDM1Ljk0MzdaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBvcGFjaXR5PSIwLjIiIGQ9Ik00MC4wMDYgNDQuMzc0NEw1NC43NjU0IDM1Ljk0MzdDNDAuMDA2MSA2My42ODMgNDAuMDA2IDYzLjY4MyA0MC4wMDYgNjMuNjgzQzQwLjAwNiA1Ny42NDE1IDQwLjAwNiA1MC43MTg5IDQwLjAwNiA0NC4zNzQ0WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTI1LjIzMjggMzUuOTQzN0wyNC44Mjk3IDM2LjU2MkMyMC4yODM5IDQzLjUzNTQgMjEuMjk5MSA1Mi42NjgxIDI3LjI3MDYgNTguNTE5MUMzMC43ODM2IDYxLjk2MTIgMzUuMzg3OCA2My42ODI1IDM5Ljk5MjEgNjMuNjgzQzM5Ljk5MjEgNjMuNjgzIDM5Ljk5MjEgNjMuNjgzIDI1LjIzMjggMzUuOTQzN1oiIGZpbGw9IndoaXRlIi8+CjxwYXRoIG9wYWNpdHk9IjAuNiIgZD0iTTM5Ljk4NzYgNDQuMzc0NEwyNS4yMjgzIDM1Ljk0MzdDMzkuOTg3NyA2My42ODMgMzkuOTg3NiA2My42ODMgMzkuOTg3NiA2My42ODNDMzkuOTg3NiA1Ny42NDE1IDM5Ljk4NzYgNTAuNzE4OSAzOS45ODc2IDQ0LjM3NDRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBvcGFjaXR5PSIwLjIiIGQ9Ik00MC4wMTE3IDI1LjU0MDVWNDAuMDgxMUw1Mi43MjUzIDMyLjgxNTVMNDAuMDExNyAyNS41NDA1WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggb3BhY2l0eT0iMC42IiBkPSJNNDAuMDA3OSAyNS41NDA1TDI3LjI4NTIgMzIuODE1NEw0MC4wMDc5IDQwLjA4MTFWMjUuNTQwNVoiIGZpbGw9IndoaXRlIi8+CjxwYXRoIGQ9Ik00MC4wMDc5IDEzLjMxMThMMjcuMjg1MiAzMi44MTk5TDQwLjAwNzkgMjUuNTI0NlYxMy4zMTE4WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggb3BhY2l0eT0iMC42IiBkPSJNNDAuMDExNyAyNS41MjI2TDUyLjczNSAzMi44MTgxTDQwLjAxMTcgMTMuMzAwM1YyNS41MjI2WiIgZmlsbD0id2hpdGUiLz4KPC9nPgo8ZGVmcz4KPGNsaXBQYXRoIGlkPSJjbGlwMF8yNzc2XzM4MDEiPgo8cmVjdCB3aWR0aD0iODAiIGhlaWdodD0iODAiIHJ4PSI0MCIgZmlsbD0id2hpdGUiLz4KPC9jbGlwUGF0aD4KPC9kZWZzPgo8L3N2Zz4K"; }}})'
```

* [`0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0`](https://etherscan.io/token/0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0) is the address of the wstETH smart contract on Ethereum Mainnet which can be verified on [Lido's website](https://docs.lido.fi/deployed-contracts/).
* The transfer fee is `1_000_000_000_000`, corresponding approximatively to 0.004 USD. This value was selected to be easy to reason about (1 followed by zeroes), while remaining within the acceptable range of 0.1 to 1 cent.

## Release Notes

No changes to the ckERC20 ledger suite orchestrator canister codebase, since this proposal uses the same version `de29a1a55b589428d173b31cdb8cec0923245657` as the previous proposal ([131374](https://dashboard.internetcomputer.org/proposal/131374)).

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout de29a1a55b589428d173b31cdb8cec0923245657
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
