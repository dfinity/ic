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
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { AddErc20Arg = record { contract = record { chain_id = 1; address = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599" }; ledger_init_arg = record { minting_account = record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai" }; fee_collector_account = opt record { owner = principal "sv3dd-oaaaa-aaaar-qacoa-cai"; subaccount = opt blob "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0f\ee"; }; feature_flags  = opt record { icrc2 = true }; decimals = opt 8; max_memo_length = opt 80; transfer_fee = 10; token_symbol = "ckWBTC"; token_name = "ckWBTC"; token_logo = ""; initial_balances = vec {}; maximum_number_of_accounts = null; accounts_overflow_trim_quantity = null }; git_commit_hash = "7fbb84aad7188d1d5b3e17b170997c29d1598cb8";  ledger_compressed_wasm_hash = "4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679"; index_compressed_wasm_hash = "55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33"; }})'
```

* [`0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`](https://etherscan.io/token/0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599) is the address of the WBTC smart contract on Ethereum Mainnet.
* [`sv3dd-oaaaa-aaaar-qacoa-cai`](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai) is the ckETH minter canister.
* The fee collector is the `0000000000000000000000000000000000000000000000000000000000000fee` subaccount of the minter canister.
* The transfer fee is `10`, corresponding approximately to 0.006 USD. This value was selected to be easy to reason about (1 followed by zeroes), while remaining within the acceptable range of 0.1 to 1 cent. This is also the same transfer fee as for the [ckBTC ledger](https://dashboard.internetcomputer.org/canister/mxzaz-hqaaa-aaaar-qaada-cai).
* The ledger compressed wasm hash `4ca82938d223c77909dcf594a49ea72c07fd513726cfa7a367dd0be0d6abc679` and the index compressed wasm hash `55dd5ea22b65adf877cea893765561ae290b52e7fdfdc043b5c18ffbaaa78f33` are the version that will be used by the orchestrator to spawn off the ckSHIB ledger and index, respectively. This is exactly the same version as used by the ckUSDC ledger and index that were created with the proposal [129750](https://dashboard.internetcomputer.org/proposal/129750) at commit `4472b0064d347a88649beb526214fde204f906fb`.

## Release Notes

No changes to the ckERC20 ledger suite orchestrator canister codebase, since this proposal uses the same version `7fbb84aad7188d1d5b3e17b170997c29d1598cb8` as the previous proposal ([130982](https://dashboard.internetcomputer.org/proposal/130982)).

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 7fbb84aad7188d1d5b3e17b170997c29d1598cb8
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```

Verify that the hash of the gzipped WASM for the ledger and index match the proposed hash.

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
sha256sum ./artifacts/canisters/ic-icrc1-index-ng-u256.wasm.gz
```
