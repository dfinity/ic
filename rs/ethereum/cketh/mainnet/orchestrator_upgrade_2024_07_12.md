# Proposal to upgrade the ledger suite orchestrator canister to add ckWBTC

Git hash: `7fbb84aad7188d1d5b3e17b170997c29d1598cb8`

New compressed Wasm hash: `9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

Previous ledger suite orchestrator proposal: https://dashboard.internetcomputer.org/proposal/130982

---

## Motivation

This proposal upgrades the ckERC20 ledger suite orchestrator to add support for [Wrapped BTC (WBTC)](https://etherscan.io/token/0x2260fac5e5542a773aa44fbcfedf7c193bc2c599#tokenInfo). Once executed, the twin token ckWBTC will be available on ICP, refer to the [documentation](https://github.com/dfinity/ic/blob/master/rs/ethereum/cketh/docs/ckerc20.adoc) on how to proceed with deposits and withdrawals.

## Upgrade args

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { AddErc20Arg = record { contract = record { chain_id = 1; address = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599" }; ledger_init_arg = record { minting_account = record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai" }; fee_collector_account = opt record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai"; subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee"; }; feature_flags  = opt record { icrc2 = true }; decimals = opt 8; max_memo_length = opt 80; transfer_fee = 10; token_symbol = "ckWBTC"; token_name = "ckWBTC"; token_logo = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDkuMjYgMTA5LjI2Ij48ZGVmcz48c3R5bGU+LmNscy0xe2ZpbGw6IzVhNTU2NDt9LmNscy0ye2ZpbGw6I2YwOTI0Mjt9LmNscy0ze2ZpbGw6IzI4MjEzODt9PC9zdHlsZT48L2RlZnM+PHRpdGxlPndyYXBwZWQtYml0Y29pbi13YnRjPC90aXRsZT48ZyBpZD0iTGF5ZXJfMiIgZGF0YS1uYW1lPSJMYXllciAyIj48ZyBpZD0iTGF5ZXJfMS0yIiBkYXRhLW5hbWU9IkxheWVyIDEiPjxnIGlkPSJQYWdlLTEiPjxnIGlkPSJ3YnRjX2NvbG91ciIgZGF0YS1uYW1lPSJ3YnRjIGNvbG91ciI+PHBhdGggaWQ9IlNoYXBlIiBjbGFzcz0iY2xzLTEiIGQ9Ik04OS4wOSwyMi45M2wtMywzYTQyLjQ3LDQyLjQ3LDAsMCwxLDAsNTcuMzJsMywzYTQ2Ljc2LDQ2Ljc2LDAsMCwwLDAtNjMuMzlaIi8+PHBhdGggaWQ9IlNoYXBlLTIiIGRhdGEtbmFtZT0iU2hhcGUiIGNsYXNzPSJjbHMtMSIgZD0iTTI2LDIzLjE5YTQyLjQ3LDQyLjQ3LDAsMCwxLDU3LjMyLDBsMy0zYTQ2Ljc2LDQ2Ljc2LDAsMCwwLTYzLjM5LDBaIi8+PHBhdGggaWQ9IlNoYXBlLTMiIGRhdGEtbmFtZT0iU2hhcGUiIGNsYXNzPSJjbHMtMSIgZD0iTTIzLjE5LDgzLjI4YTQyLjQ3LDQyLjQ3LDAsMCwxLDAtNTcuMjlsLTMtM2E0Ni43Niw0Ni43NiwwLDAsMCwwLDYzLjM5WiIvPjxwYXRoIGlkPSJTaGFwZS00IiBkYXRhLW5hbWU9IlNoYXBlIiBjbGFzcz0iY2xzLTEiIGQ9Ik04My4yOCw4Ni4wNWE0Mi40Nyw0Mi40NywwLDAsMS01Ny4zMiwwbC0zLDNhNDYuNzYsNDYuNzYsMCwwLDAsNjMuMzksMFoiLz48cGF0aCBpZD0iU2hhcGUtNSIgZGF0YS1uYW1lPSJTaGFwZSIgY2xhc3M9ImNscy0yIiBkPSJNNzMuNTcsNDQuNjJjLS42LTYuMjYtNi04LjM2LTEyLjgzLTlWMjdINTUuNDZ2OC40NmMtMS4zOSwwLTIuODEsMC00LjIyLDBWMjdINDZ2OC42OEgzNS4yOXY1LjY1czMuOS0uMDcsMy44NCwwYTIuNzMsMi43MywwLDAsMSwzLDIuMzJWNjcuNDFhMS44NSwxLjg1LDAsMCwxLS42NCwxLjI5LDEuODMsMS44MywwLDAsMS0xLjM2LjQ2Yy4wNy4wNi0zLjg0LDAtMy44NCwwbC0xLDYuMzFINDUuOXY4LjgyaDUuMjhWNzUuNkg1NS40djguNjVoNS4yOVY3NS41M2M4LjkyLS41NCwxNS4xNC0yLjc0LDE1LjkyLTExLjA5LjYzLTYuNzItMi41My05LjcyLTcuNTgtMTAuOTNDNzIuMSw1Miw3NCw0OS4yLDczLjU3LDQ0LjYyWk02Ni4xNyw2My40YzAsNi41Ni0xMS4yNCw1LjgxLTE0LjgyLDUuODFWNTcuNTdDNTQuOTMsNTcuNTgsNjYuMTcsNTYuNTUsNjYuMTcsNjMuNFpNNjMuNzIsNDdjMCw2LTkuMzgsNS4yNy0xMi4zNiw1LjI3VjQxLjY5QzU0LjM0LDQxLjY5LDYzLjcyLDQwLjc1LDYzLjcyLDQ3WiIvPjxwYXRoIGlkPSJTaGFwZS02IiBkYXRhLW5hbWU9IlNoYXBlIiBjbGFzcz0iY2xzLTMiIGQ9Ik01NC42MiwxMDkuMjZhNTQuNjMsNTQuNjMsMCwxLDEsNTQuNjQtNTQuNjRBNTQuNjMsNTQuNjMsMCwwLDEsNTQuNjIsMTA5LjI2Wm0wLTEwNUE1MC4zNCw1MC4zNCwwLDEsMCwxMDUsNTQuNjIsNTAuMzQsNTAuMzQsMCwwLDAsNTQuNjIsNC4yNloiLz48L2c+PC9nPjwvZz48L2c+PC9zdmc+"; initial_balances = vec {}; maximum_number_of_accounts = null; accounts_overflow_trim_quantity = null }; git_commit_hash = "7fbb84aad7188d1d5b3e17b170997c29d1598cb8";  ledger_compressed_wasm_hash = "4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679"; index_compressed_wasm_hash = "55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33"; }})'
```

* [`0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`](https://etherscan.io/token/0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599) is the address of the WBTC smart contract on Ethereum Mainnet.
* [`sv3dd-oaaaa-aaaar-qacoa-cai`](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai) is the ckETH minter canister.
* The fee collector is the `0000000000000000000000000000000000000000000000000000000000000fee` subaccount of the minter canister.
* The transfer fee is `10`, corresponding approximately to 0.006 USD. This value was selected to be easy to reason about (1 followed by zeroes), while remaining within the acceptable range of 0.1 to 1 cent. This is also the same transfer fee as for the [ckBTC ledger](https://dashboard.internetcomputer.org/canister/mxzaz-hqaaa-aaaar-qaada-cai).
* The ledger compressed wasm hash `4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679` and the index compressed wasm hash `55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33` are the version that will be used by the orchestrator to spawn off the ckWBTC ledger and index, respectively. This is exactly the same version as used by the ckUSDC ledger and index that were created with the proposal [129750](https://dashboard.internetcomputer.org/proposal/129750) at commit `4472b0064d347a88649beb526214fde204f906fb`.

## Release Notes

No changes to the ckERC20 ledger suite orchestrator canister codebase, since this proposal uses the same version `7fbb84aad7188d1d5b3e17b170997c29d1598cb8` as the previous proposal ([130982](https://dashboard.internetcomputer.org/proposal/130982)).

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger and index match the proposed hash.

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
```
