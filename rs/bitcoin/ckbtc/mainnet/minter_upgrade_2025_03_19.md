# Proposal to upgrade the ckBTC minter canister

Git hash: `307d063f3473cf5261ce84ccafaecceb8440e4e8`

New compressed Wasm hash: `d0e39a247fc0bcc8ea50f1fbfcc39798f2a22ad69b57930050cfb4ef8a550796`

Upgrade args hash: `abf6b9f54bb94025c0aff10c4eb05e182118052d6c7a490c2aa50ea651ed7d23`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/140492

---

## Security patch update

In accordance with the Security Patch Policy and Procedure that was adopted in proposal [48792](https://dashboard.internetcomputer.org/proposal/48792), the source code that was used to build this canister release will be exposed at the latest 10 days after the fix is rolled out.

The community will be able to retroactively verify the wasm binaries that were rolled out.

## Argument verification

```
git fetch
git checkout 307d063f3473cf5261ce84ccafaecceb8440e4e8
didc encode -d rs/bitcoin/ckbtc/minter/ckbtc_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```
