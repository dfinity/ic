# Proposal to upgrade the ckDOGE ledger canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `cf41372e3d4dc1accfe2c09a7969f8bddc729dc1`

New compressed Wasm hash: `390e22377640748f5a63fc35d50680d27a05d3e9a05c1c25c4061cacebda4c56`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `efmc5-wyaaa-aaaar-qb3wa-cai`

Previous ckDOGE ledger proposal: https://dashboard.internetcomputer.org/proposal/140523

---

## Motivation
Upgrade the ckDOGE ledger canister to the latest version [ledger-suite-icrc-2026-03-09](https://github.com/dfinity/ic/releases/tag/ledger-suite-icrc-2026-03-09).


## Release Notes

```
git log --format='%C(auto) %h %s' 653c927f2c732398bfd6e6b9dbfaf983cfb9b911..cf41372e3d4dc1accfe2c09a7969f8bddc729dc1 -- rs/ledger_suite/icrc1/ledger
b34d5ed28c chore: Upgrade rustc to 1.93.1  (#9113)
11306dd454 chore: always add canbench test (#9151)
8910873dcc chore: bump candid to v0.10.22 (#8780)
 ```

## Upgrade args

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout cf41372e3d4dc1accfe2c09a7969f8bddc729dc1
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-icrc1-ledger-u256.wasm.gz
```
