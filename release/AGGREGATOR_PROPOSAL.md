# Upgrade SNS aggregator canister to commit `57566996c28c06f2840210eb28eaa8784d14b366`
Wasm sha256 hash: `3eda593552bf779968b9410ce59871917925f0c2a7956112edce3dd210489e41` (`release/ci/sns_aggregator.wasm.gz`)

## Change Log

### Added

* Start aggregating data related to SNS proposal topics.

### Fixed

* Keep existing data when a call to an SNS canister fails.

## Commit Log

```
+ bash -xc "git log --format='%C(auto) %h %s' 08e7433bc..57566996c ./rs/sns_aggregator/"
 57566996c bot: Update sns_aggregator candid bindings (#6641)
 476cbb552 bot: Update sns_aggregator candid bindings (#6621)
 5d517dfa2 bot: Update sns_aggregator candid bindings (#6613)
 2dacd804e feat(sns_aggregator): Collect data from the new `SnsGov.list_topics` endpoint (#6547)
 61ae3affa bot: Update sns_aggregator candid bindings (#6565)
 0ff0e7ed5 build(deps): bump serde_bytes from 0.11.15 to 0.11.17 (#6550)
 a77c6ada0 build(deps): bump serde from 1.0.218 to 1.0.219 (#6552)
 762f61d11 bot: Update sns_aggregator candid bindings (#6527)
 5d8d4de50 bot: Update sns_aggregator candid bindings (#6487)
 f1c0000d2 bot: Update sns_aggregator candid bindings (#6446)
 27e6defcf chore(deps): update ic-management-canister-types to public repo (#6439)
 08b030a19 bot: Update sns_aggregator candid bindings (#6390)
 d6d1dff74 Migrate from dfn_core to ic_cdk (#6347)
 73c0ee479 bot: Update sns_aggregator candid bindings (#6332)
 b421f5efe bot: Update sns_aggregator candid bindings (#6262)
 513ad3b0c bot: Update sns_aggregator candid bindings (#6197)
 89a0cd36a build(deps): bump serde_json from 1.0.135 to 1.0.137 (#6186)
 b8e278aa4 Bump serde from 1.0.216 to 1.0.217 (#6084)
 4b5c9c3f2 Bump ic-cdk from 0.17.0 to 0.17.1 (#6065)
 d9f71202e Bump anyhow from 1.0.94 to 1.0.95 (#6064)
 92034794b Bump serde_json from 1.0.133 to 1.0.134 (#6066)
 3d0f24042 bot: Update sns_aggregator candid bindings (#5963)
 1de5c6fb7 bot: Update sns_aggregator candid bindings (#5900)
 472153ef6 Update rust version to 1.83.0 (#5890)
 e2c57c97e Keep existing data in SNS aggregator when new data can't be loaded (#5858)
 ea8cf3b44 bot: Update sns_aggregator candid bindings (#5856)
 925bd4565 bot: Update sns_aggregator candid bindings (#5808)
 286399cd3 bot: Update sns_aggregator candid bindings (#5761)
 5124e7997 Bump ic-cdk-macros from 0.16.0 to 0.17.0 (#5754)
 7da2f2597 Bump ic-cdk-timers from 0.10.0 to 0.11.0 (#5752)
 0d923e89d Bump ic-cdk from 0.16.0 to 0.17.0 (#5755)
 ec1106bff bot: Update sns_aggregator candid bindings (#5726)
 e578229cd bot: Update sns_aggregator candid bindings (#5699)
 26ba775a0 bot: Update sns_aggregator candid bindings (#5665)
 a1b2afe21 Download ledger.did from new path (#5617)
 329001668 bot: Update sns_aggregator candid bindings (#5556)
 d063a3fee bot: Update sns_aggregator candid bindings (#5511)
 41561553f bot: Update sns_aggregator candid bindings (#5475)
 374c396c9 bot: Update sns_aggregator candid bindings (#5427)
 c04108594 bot: Update sns_aggregator candid bindings (#5397)
 b59f52786 Bump ic-cdk from 0.15.1 to 0.16.0 (#5387)
 43f0b7e22 Bump ic-cdk-timers from 0.9.0 to 0.10.0 (#5384)
 5f293f88d Bump ic-cdk-macros from 0.15.0 to 0.16.0 (#5385)
 37123c7a3 bot: Update sns_aggregator candid bindings (#5363)
 d300ba028 Bump serde from 1.0.208 to 1.0.209 (#5354)
 3bfb5f5b1 Bump serde_json from 1.0.125 to 1.0.127 (#5353)
```

## Forum

https://forum.dfinity.org/t/43120

## Wasm Verification

To build the wasm module yourself and verify its hash, run the following commands from the root 
of the [nns-dapp repo](https://github.com/dfinity/nns-dapp):

```
git fetch  # to ensure you have the latest changes.
git checkout "57566996c28c06f2840210eb28eaa8784d14b366"
./scripts/docker-build
sha256sum sns_aggregator.wasm.gz
```
## Argument Verification

```
ARG='(null : null)'
didc encode $ARG | xxd -r -p | sha256sum
```
