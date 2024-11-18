# Proposal to upgrade the ckBTC minter canister and reduce minimum retrieval amount

Repository: `https://github.com/dfinity/ic.git`

Git hash: `bcbccf79c89a3e81b1a38d8233f8f81d1af1b245`

New compressed Wasm hash: `e90d3f24a6eb3e1da8f42f3160756c40598e2a6783097db1beeb31873224e787`

Upgrade args hash: `0b7d4ab8fe7adf7c609c7d565765abfa309ba7d03660439ec12c2e08e33ee6a5`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/133840

---

## Motivation
Reduce the minimum ckbtc retrieval amount to 0.0005 BTC, as proposed by a recently passed motion proposal https://dashboard.internetcomputer.org/proposal/133462.

The previous proposal https://dashboard.internetcomputer.org/proposal/133840 failed to change this setting because the ckBTC minter implementation was using a hardcoded value.
A fix has since been implemented, and this upgrade will apply the fix.

## Upgrade args

```
git fetch
git checkout bcbccf79c89a3e81b1a38d8233f8f81d1af1b245
cd rs/bitcoin/ckbtc/minter
didc encode -d ckbtc_minter.did -t '(MinterArg)' '(variant {Upgrade = opt record { retrieve_btc_min_amount = opt 50000 }})' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 511ad1cf505003e33baf0ce0eefa0168aad91bf1..bcbccf79c89a3e81b1a38d8233f8f81d1af1b245 -- rs/bitcoin/ckbtc/minter
b79edc2d0 fix(ckbtc): Fix a problem with retrieve_btc_min_amount setting (#2435)
aa7a0739d refactor(cross-chain): rename metrics related to memory (#2372)
15d752c5d chore: avoid reexports from StateMachine tests (#2370)
c5e6242f5 chore: remove unneeded clippy allows (#2326)
69e9f0763 chore: do not pin to crate versions (#2073)
fcbc91f0a chore: update `ic-cdk` to 0.16.0 (#1868)
6ed86361e chore: duplicate btc header validation to main repo #769 (#1766)
3bbabefb7 chore(Ledger-Suite): FI-1502 move icp and icrc ledger suites (#1682)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout bcbccf79c89a3e81b1a38d8233f8f81d1af1b245
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
