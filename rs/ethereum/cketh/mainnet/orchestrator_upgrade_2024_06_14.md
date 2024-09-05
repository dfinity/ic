# Proposal to upgrade the ledger suite orchestrator canister to add ckLINK

Git hash: `7fbb84aad7188d1d5b3e17b170997c29d1598cb8`

New compressed Wasm hash: `9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/130342

---

## Motivation
This proposal upgrades the ckERC20 ledger suite orchestrator to add support for [LINK](https://docs.chain.link/resources/link-token-contracts). Once executed, the twin token ckLINK will be available on ICP, refer to the [documentation](https://github.com/dfinity/ic/blob/master/rs/ethereum/cketh/docs/ckerc20.adoc) on how to proceed with deposits and withdrawals.


## Upgrade args

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { AddErc20Arg = record { contract = record { chain_id = 1; address = "0x514910771AF9Ca656af840dff83E8264EcF986CA" }; ledger_init_arg = record { minting_account = record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai" }; fee_collector_account = opt record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai"; subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee"; }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 100_000_000_000_000; token_symbol = "ckLINK"; token_name = "ckLINK"; token_logo = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjEyMCIgdmlld0JveD0iMCAwIDEyMCAxMjAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxnIGNsaXAtcGF0aD0idXJsKCNjbGlwMF8yMV85NjEpIj4KPHBhdGggZD0iTTYwIDBDOTMuMTMzMyAwIDEyMCAyNi44NjY3IDEyMCA2MEMxMjAgOTMuMTMzMyA5My4xMzMzIDEyMCA2MCAxMjBDMjYuODY2NyAxMjAgMCA5My4xMzMzIDAgNjBDMCAyNi44NjY3IDI2Ljg2NjcgMCA2MCAwWiIgZmlsbD0iIzA4NDdGNyIvPgo8cGF0aCBkPSJNNjAgMThMMjMgMzlWODEuMDAwMUw2MCAxMDJMOTcgODEuMDAwMVYzOUw2MCAxOFpNODEuMzI0OSA3Mi4wOTk1TDYwLjAwNjkgODQuMTk4N0wzOC42ODg3IDcyLjA5OTVWNDcuOTAwOEw2MC4wMDY5IDM1LjgwMTNMODEuMzI0OSA0Ny45MDA4VjcyLjA5OTVaIiBmaWxsPSJ3aGl0ZSIvPgo8L2c+CjxkZWZzPgo8Y2xpcFBhdGggaWQ9ImNsaXAwXzIxXzk2MSI+CjxyZWN0IHdpZHRoPSIxMjAiIGhlaWdodD0iMTIwIiBmaWxsPSJ3aGl0ZSIvPgo8L2NsaXBQYXRoPgo8L2RlZnM+Cjwvc3ZnPgo="; initial_balances = vec {}; maximum_number_of_accounts = null; accounts_overflow_trim_quantity = null }; git_commit_hash = "7fbb84aad7188d1d5b3e17b170997c29d1598cb8";  ledger_compressed_wasm_hash = "4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679"; index_compressed_wasm_hash = "55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33"; }})'
```
* [`0x514910771AF9Ca656af840dff83E8264EcF986CA`](https://etherscan.io/token/0x514910771AF9Ca656af840dff83E8264EcF986CA) is the address of the LINK smart contract on Ethereum Mainnet which can be verified on [Chainlink's website](https://docs.chain.link/resources/link-token-contracts).
* [`sv3dd-oaaaa-aaaar-qacoa-cai`](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai) is the
  ckETH minter canister.
* The fee collector is the 0000000000000000000000000000000000000000000000000000000000000fee subaccount of the minter
  canister.
* The transfer fee is `100_000_000_000_000`, corresponding approximately to 0.0015 USD, roughly in the same ballpark as ckBTC transfer fees of 10
  satoshi and ckETH transfer fees of 2_000_000_000_000 wei.
* The ledger compressed wasm hash `4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679` and the index compressed wasm hash `55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33` are the version that will be used by the orchestrator to spawn off the ckLINK ledger and index, respectively. This is exactly the same version as used by the ckUSDC ledger and index that were created with the proposal [129750](https://dashboard.internetcomputer.org/proposal/129750) at commit `4472b0064d347a88649beb526214fde204f906fb`.

## Release Notes

No changes to the ckERC20 ledger suite orchestrator canister codebase, since this proposal uses the same version `7fbb84aad7188d1d5b3e17b170997c29d1598cb8` as the previous proposal ([130342](https://dashboard.internetcomputer.org/proposal/130342)).

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger and index match the proposed hash.
Note that the git commit hash is different because it reuses the same version for the ledger and for the index as for ckUSDC, that were recorded by the ledger suite orchestrator with the proposal [129750](https://dashboard.internetcomputer.org/proposal/129750) at commit `4472b0064d347a88649beb526214fde204f906fb` when ckUSDC was added.
```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
```
