# Proposal to upgrade the ckETH minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `3ce03862433d189f0d32c8a19cf99f502260ea98`

New compressed Wasm hash: `5a923e48361ae247b6e93a9daae16796ea3190e38658d4fd49776110889f4da0`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `sv3dd-oaaaa-aaaar-qacoa-cai`

Previous ckETH minter proposal: https://dashboard.internetcomputer.org/proposal/144023

---

## Motivation

Bound and adapt how many transaction receipts the ckETH minter fetches per finalization round.

When two of the minter's four Ethereum RPC providers failed to reach consensus on `eth_getTransactionReceipt`, no withdrawal could be finalized, and the minter re-fetched the receipts of its entire pending set every few minutes. The outcalls grew from a few hundred a day to over 11,000 an hour, exhausting one provider's request quota and quadrupling the minter's cycle burn. The withdrawals themselves were executed on Ethereum throughout; only the minter's bookkeeping was stuck.

With this upgrade:
* The number of withdrawals whose receipts are fetched in a round is capped and adapts to the providers' behaviour: it doubles after a clean round, halves after a partly failed one and drops to one after a fully failed one.
* Receipts that were successfully retrieved are kept even if other lookups in the same round failed, so a backlog drains as providers recover.
* A withdrawal for which no receipt can be found no longer traps the minter; it stays pending and is retried later.
* New metrics expose the receipt fetch behaviour and the backlog of withdrawals and sweeps awaiting finalization.

Creating, signing and sending withdrawal transactions, as well as deposits, are not affected.


## Release Notes

```
git log --format='%C(auto) %h %s' 2c2c7c99bd526d8c3da51df32aeeb977e852292d..3ce03862433d189f0d32c8a19cf99f502260ea98 -- rs/ethereum/cketh/minter
3ce0386243 feat(cketh): DEFI-3013: Bound and adapt the per-round transaction receipt fan-out (#11636)
37681d65c8 feat(cketh): DEFI-3012: Expose the withdrawal finalization backlog as metrics (#11637)
 ```

## Upgrade args

```
git fetch
git checkout 3ce03862433d189f0d32c8a19cf99f502260ea98
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 3ce03862433d189f0d32c8a19cf99f502260ea98
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-cketh-minter.wasm.gz
```