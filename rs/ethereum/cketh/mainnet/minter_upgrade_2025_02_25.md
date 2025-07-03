# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `e96ff00c35856d11d5cce98fd2f969dd9afe797f`

New compressed Wasm hash: `c5edc1c5f701fba85c00ad63009e7874f403417b068cf85613dc7546e2a67d9a`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/134556

---

## Motivation

Update the ckETH minter canister to include the latest code changes:
* Replace the [rpc.sepolia.org](https://rpc.sepolia.org/) Sepolia RPC provider by Ankr.
* Update the OFAC checklist.

## Upgrade args

```
git fetch
git checkout e96ff00c35856d11d5cce98fd2f969dd9afe797f
cd rs/ethereum/cketh/minter
didc encode '()' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 8843e7e6c89aa13efc7caca275d8dd053c11c815..e96ff00c35856d11d5cce98fd2f969dd9afe797f -- rs/ethereum/cketh/minter
e96ff00c35 chore(cketh): update OFAC checklist (#4085)
810eeb14ca chore: use cdk::api::in_replicated_execution (#3949)
6612119c34 chore: Bump ic_cdk version (#3939)
5506c7c41e chore: [EXC-1835] Make ic-management-canister-types private (#3814)
97bcf0945c chore(crypto): CRP-2693 Move ic-crypto-secp256k1 to packages (#3784)
225b046aad chore(cketh/ckerc20): Replace rpc.sepolia.org by Ankr (#3523)
484a58d15c test(cketh): end-to-end test with `foundry` (#3014)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout e96ff00c35856d11d5cce98fd2f969dd9afe797f
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```
