# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9`

New compressed Wasm hash: `8a5c77ddafee85bee18e3fa76c11922ed5b7bd11f81c2d66b578b0c1b00f5b23`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/134264

---

## Motivation
TODO: THIS MUST BE FILLED OUT


## Upgrade args

```
git fetch
git checkout 5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9
cd rs/ethereum/cketh/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 2181ddf2a690ca0262d2d9d0511b093bfa350ece..5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9 -- rs/ethereum/cketh/minter
5ce01d0a8 fix(cketh): Undo breaking change in `get_minter_info` (#2907)
68d1088d5 chore(XC-48): extract cketh minter minicbor encoder and decoders into a separate library (#2769)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 5ce01d0a871d5162d0b2ff0b585d71ef2e644ac9
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
