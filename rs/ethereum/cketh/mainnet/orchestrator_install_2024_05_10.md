# Proposal to install the ckERC20 ledger suite orchestrator canister

Git hash: `4472b0064d347a88649beb526214fde204f906fb`

New compressed Wasm hash: `658c5786cf89ce77e58b3c38e01259c9655e20d83caff346cb5e5719c348cb5e`

Target canister: `vxkom-oyaaa-aaaar-qafda-cai`

---

## Motivation
This proposal installs the ckERC20 ledger suite orchestrator to the NNS-controlled canister ID `vxkom-oyaaa-aaaar-qafda-cai` on subnet `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`.

## Install args

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
cd rs/ethereum/ledger-suite-orchestrator
didc encode -d ledger_suite_orchestrator.did -t '(OrchestratorArg)' '(variant { InitArg = record { more_controller_ids = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai"; }; minter_id = opt principal "sv3dd-oaaaa-aaaar-qacoa-cai"; cycles_management = opt record { cycles_for_ledger_creation = 150_000_000_000_000 ; cycles_for_archive_creation = 50_000_000_000_000; cycles_for_index_creation = 100_000_000_000_000; cycles_top_up_increment = 10_000_000_000_000 } }})'
```
* All canisters spawned off by the orchestrator will be controlled by the orchestrator itself `vxkom-oyaaa-aaaar-qafda-cai` and by the NNS root `r7inp-6aaaa-aaaaa-aaabq-cai`.
* [`sv3dd-oaaaa-aaaar-qacoa-cai`](https://dashboard.internetcomputer.org/canister/sv3dd-oaaaa-aaaar-qacoa-cai) is the ckETH minter canister.
* ICRC1 ledgers will be created with 150T cycles, indexes with 100T cycles and archives with 50T cycles. The top-up increment is 10T cycles and all canisters managed by the orchestrator will be topped-up as necessary to always have at least 70T cycles available.

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 4472b0064d347a88649beb526214fde204f906fb
./ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/ic-ledger-suite-orchestrator-canister.wasm.gz
```
