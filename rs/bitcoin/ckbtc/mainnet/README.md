# ckBTC mainnet deployment

Root canister id: `r7inp-6aaaa-aaaaa-aaabq-cai`.
Subnet: `pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`

## Installing the minter ([`mqygn-kiaaa-aaaar-qaadq-cai`](https://dashboard.internetcomputer.org/canister/mqygn-kiaaa-aaaar-qaadq-cai))

Notes on init args:

* The ledger id comes from the `canister_ids.json` file.
* Max time in queue is ten minutes, or 600 billion nanoseconds.
* We set a very conservative requirement of at least 72 transaction confirmations.
* Min retrieve BTC amount is 10K satoshi.
  That's enough to cover the fees for the type of transactions we create.
* ECDSA key name is "key_1".

Encoding the init args:

```shell
didc encode -d ../minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Init = record { mode = variant { ReadOnly }; btc_network = variant { Mainnet }; ledger_id = principal "mxzaz-hqaaa-aaaar-qaada-cai"; ecdsa_key_name = "key_1"; min_confirmations = opt 72; retrieve_btc_min_amount = 100_000; max_time_in_queue_nanos = 600_000_000_000 } })' | xxd -r -p > minter_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mqygn-kiaaa-aaaar-qaadq-cai \
    --mode install \
    --wasm-module-path ./ic-ckbtc-minter.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg minter_arg.bin \
    --summary-file ./minter_proposal.md
```

We first installed the minter with proposal [102640](https://dashboard.internetcomputer.org/proposal/102640).

Submitting an upgrade proposal:

```shell
didc encode -d ../minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p > minter_upgrade_arg.bin
```

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mqygn-kiaaa-aaaar-qaadq-cai \
    --mode upgrade \
    --wasm-module-path ./ic-ckbtc-minter.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg minter_upgrade_arg.bin \
    --summary-file ./minter_upgrade.md
```

## Installing the ledger ([`mxzaz-hqaaa-aaaar-qaada-cai`](https://dashboard.internetcomputer.org/canister/mxzaz-hqaaa-aaaar-qaada-cai))

```shell
didc encode -d ../../../ledger_suite/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant { Init = record { minting_account = record { owner = principal "mqygn-kiaaa-aaaar-qaadq-cai" }; transfer_fee = 10; token_symbol = "ckBTC"; token_name = "ckBTC"; metadata = vec { record { "icrc1:logo"; variant { Text = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45MzlDMzcuMzA4NyAxMzMuODY3IDEyLjEzMyAxMDguNjkxIDEwLjA2MDUgNzcuMjA1MkgxNi4zODM3WiIgZmlsbD0idXJsKCNwYWludDBfbGluZWFyXzExMF81NzIpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNjguNzY0NiAxNi4zNTM0QzQwLjc2MzggMTguNDAzNiAxOC40MDM3IDQwLjc2MzcgMTYuMzUzNSA2OC43NjQ2TDEwLjAzMDMgNjguNzY0NkMxMi4xMDI3IDM3LjI3ODQgMzcuMjc4NSAxMi4xMDI2IDY4Ljc2NDYgMTAuMDMwMkw2OC43NjQ2IDE2LjM1MzRaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTI5LjYxNiA2OC43MzQzQzEyNy41NjYgNDAuNzMzNSAxMDUuMjA2IDE4LjM3MzQgNzcuMjA1MSAxNi4zMjMyTDc3LjIwNTEgMTBDMTA4LjY5MSAxMi4wNzI0IDEzMy44NjcgMzcuMjQ4MiAxMzUuOTM5IDY4LjczNDNMMTI5LjYxNiA2OC43MzQzWiIgZmlsbD0idXJsKCNwYWludDFfbGluZWFyXzExMF81NzIpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNzcuMjM1NCAxMjkuNTg2QzEwNS4yMzYgMTI3LjUzNiAxMjcuNTk2IDEwNS4xNzYgMTI5LjY0NyA3Ny4xNzQ5TDEzNS45NyA3Ny4xNzQ5QzEzMy44OTcgMTA4LjY2MSAxMDguNzIyIDEzMy44MzcgNzcuMjM1NCAxMzUuOTA5TDc3LjIzNTQgMTI5LjU4NloiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZD0iTTk5LjgyMTcgNjQuNzI0NUMxMDEuMDE0IDU2Ljc1MzggOTQuOTQ0NyA1Mi40Njg5IDg2LjY0NTUgNDkuNjEwNEw4OS4zMzc2IDM4LjgxM0w4Mi43NjQ1IDM3LjE3NUw4MC4xNDM1IDQ3LjY4NzlDNzguNDE1NSA0Ny4yNTczIDc2LjY0MDYgNDYuODUxMSA3NC44NzcxIDQ2LjQ0ODdMNzcuNTE2OCAzNS44NjY1TDcwLjk0NzQgMzQuMjI4NUw2OC4yNTM0IDQ1LjAyMjJDNjYuODIzIDQ0LjY5NjUgNjUuNDE4OSA0NC4zNzQ2IDY0LjA1NiA0NC4wMzU3TDY0LjA2MzUgNDQuMDAyTDU0Ljk5ODUgNDEuNzM4OEw1My4yNDk5IDQ4Ljc1ODZDNTMuMjQ5OSA0OC43NTg2IDU4LjEyNjkgNDkuODc2MiA1OC4wMjM5IDQ5Ljk0NTRDNjAuNjg2MSA1MC42MSA2MS4xNjcyIDUyLjM3MTUgNjEuMDg2NyA1My43NjhDNTguNjI3IDYzLjYzNDUgNTYuMTcyMSA3My40Nzg4IDUzLjcxMDQgODMuMzQ2N0M1My4zODQ3IDg0LjE1NTQgNTIuNTU5MSA4NS4zNjg0IDUwLjY5ODIgODQuOTA3OUM1MC43NjM3IDg1LjAwMzQgNDUuOTIwNCA4My43MTU1IDQ1LjkyMDQgODMuNzE1NUw0Mi42NTcyIDkxLjIzODlMNTEuMjExMSA5My4zNzFDNTIuODAyNSA5My43Njk3IDU0LjM2MTkgOTQuMTg3MiA1NS44OTcxIDk0LjU4MDNMNTMuMTc2OSAxMDUuNTAxTDU5Ljc0MjYgMTA3LjEzOUw2Mi40MzY2IDk2LjMzNDNDNjQuMjMwMSA5Ni44MjEgNjUuOTcxMiA5Ny4yNzAzIDY3LjY3NDkgOTcuNjkzNEw2NC45OTAyIDEwOC40NDhMNzEuNTYzNCAxMTAuMDg2TDc0LjI4MzYgOTkuMTg1M0M4NS40OTIyIDEwMS4zMDYgOTMuOTIwNyAxMDAuNDUxIDk3LjQ2ODQgOTAuMzE0MUMxMDAuMzI3IDgyLjE1MjQgOTcuMzI2MSA3Ny40NDQ1IDkxLjQyODggNzQuMzc0NUM5NS43MjM2IDczLjM4NDIgOTguOTU4NiA3MC41NTk0IDk5LjgyMTcgNjQuNzI0NVpNODQuODAzMiA4NS43ODIxQzgyLjc3MiA5My45NDM4IDY5LjAyODQgODkuNTMxNiA2NC41NzI3IDg4LjQyNTNMNjguMTgyMiA3My45NTdDNzIuNjM4IDc1LjA2ODkgODYuOTI2MyA3Ny4yNzA0IDg0LjgwMzIgODUuNzgyMVpNODYuODM2NCA2NC42MDY2Qzg0Ljk4MyA3Mi4wMzA3IDczLjU0NDEgNjguMjU4OCA2OS44MzM1IDY3LjMzNEw3My4xMDYgNTQuMjExN0M3Ni44MTY2IDU1LjEzNjQgODguNzY2NiA1Ni44NjIzIDg2LjgzNjQgNjQuNjA2NloiIGZpbGw9IndoaXRlIi8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU3MiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTcyIiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==" }}}; initial_balances = vec {}; max_memo_length = opt 80; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 100_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "r7inp-6aaaa-aaaaa-aaabq-cai" } } })' | xxd -r -p > ledger_arg.bin
```

Notes on init args:

* `mqygn-kiaaa-aaaar-qaadq-cai` is the governance-controlled ckBTC minter canister (see proposal 102640).
* The transfer fee is 10 ckBTC Satoshis.
* There are no initial balances: the minter is responsible for minting all ckBTC.
* Archive max memory size is 3 GiB, or 3_221_225_472 bytes. We can afford to use that much memory because archives store transactions in stable memory.
* The `max_memo_length` was last updated to 80 in [NNS proposal 123422](https://dashboard.internetcomputer.org/proposal/123422).

The metadata contains the official ckBTC logo.

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-ledger.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_arg.bin \
    --summary-file ./ledger_proposal.md
```

We first installed the ledger with proposal [104499](https://dashboard.internetcomputer.org/proposal/104499).

Submitting an upgrade proposal:

```shell
didc encode -d ../../../ledger_suite/icrc1/ledger/ledger.did -t '(LedgerArg)' '(variant { Upgrade = null })' | xxd -r -p > ledger_upgrade_arg.bin
```

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id mxzaz-hqaaa-aaaar-qaada-cai \
    --mode upgrade \
    --wasm-module-path ./ic-icrc1-ledger.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg ledger_upgrade_arg.bin \
    --summary-file ./ledger_upgrade.md
```

## Installing the index ([`n5wcd-faaaa-aaaar-qaaea-cai`](https://dashboard.internetcomputer.org/canister/n5wcd-faaaa-aaaar-qaaea-cai))

Encoding the init args:

```shell
didc encode -d ../../../ledger_suite/icrc1/index-ng/index-ng.did -t '(opt IndexArg)' '(opt variant { Init = record { ledger_id = principal "mxzaz-hqaaa-aaaar-qaada-cai" } })' | xxd -r -p > index_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id n5wcd-faaaa-aaaar-qaaea-cai \
    --mode install \
    --wasm-module-path ./ic-icrc1-index-ng.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg index_arg.bin \
    --summary-file ./index_proposal.md
```

Submitting an upgrade proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id n5wcd-faaaa-aaaar-qaaea-cai \
    --mode upgrade \
    --wasm-module-path ./ic-icrc1-index-ng.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --summary-file ./index_upgrade.md
```

We first installed the index with proposal [105128](https://dashboard.internetcomputer.org/proposal/105128).

# Archive ([nbsys-saaaa-aaaar-qaaga-cai](https://dashboard.internetcomputer.org/canister/nbsys-saaaa-aaaar-qaaga-cai))

Submitting an upgrade proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id nbsys-saaaa-aaaar-qaaga-cai \
    --mode upgrade \
    --wasm-module-path ./ic-icrc1-archive.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --summary-file ./archive_proposal.md
```

## KYT canister [pjihx-aaaaa-aaaar-qaaka-cai](https://dashboard.internetcomputer.org/canister/pjihx-aaaaa-aaaar-qaaka-cai)

Encoding the init args:

```shell
didc encode -d ../kyt/kyt.did -t '(LifecycleArg)' '(variant { InitArg = record { minter_id = principal "mqygn-kiaaa-aaaar-qaadq-cai"; maintainers = vec {}; mode = variant { Normal }}})' | xxd -r -p > kyt_arg.bin
```

Submitting the install proposal:

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id pjihx-aaaaa-aaaar-qaaka-cai \
    --mode install \
    --wasm-module-path ./ic-ckbtc-kyt.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --arg kyt_arg.bin \
    --summary-file ./kyt_proposal.md
```

Submitting an upgrade proposal:

```shell
didc encode -d kyt.did -t '(LifecycleArg)' '(variant { UpgradeArg = record { maintainers = opt vec { principal "pzc5r-ctmyf-4menu-zt2d3-y57i4-hodcg-dfvpi-bfj3w-7jqef-d7s35-xqe" } } })' | xxd -r -p > kyt_upgrade_arg.bin
```

```shell
bazel build //rs/registry/admin:ic-admin

../../../../bazel-bin/rs/registry/admin/ic-admin \
    --use-hsm \
    --key-id $KEY_ID \
    --slot 0 \
    --pin $HSM_PIN \
    --nns-url "https://ic0.app" \
    propose-to-change-nns-canister \
    --proposer $NEURON_ID \
    --canister-id pjihx-aaaaa-aaaar-qaaka-cai \
    --mode upgrade \
    --wasm-module-path ./ic-ckbtc-kyt.wasm.gz \
    --wasm-module-sha256 $WASM_SHA256 \
    --summary-file ./kyt_upgrade.md
```
