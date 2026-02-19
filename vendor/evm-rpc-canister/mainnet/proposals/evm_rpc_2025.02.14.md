# Proposal to upgrade the EVM RPC canister

Repository: `https://github.com/internet-computer-protocol/evm-rpc-canister.git`

Git hash: `c3592e02905e68dba671b055468fea97612c0374`

New compressed Wasm hash: `d3d5f1ba715b5d67718bff088a75a498e83dcaa5c8b7c375c772ce6391aa5d9a`

Upgrade args hash: `6005397a2ddf2ee644ceaca123c9afbd2360f0644e7e5e6c4ac320a5f7bd4a82`

Target canister: `7hfb6-caaaa-aaaar-qadga-cai`

Previous EVM RPC proposal: https://dashboard.internetcomputer.org/proposal/133448

---

## Motivation

Upgrade the EVM RPC canister to the latest version [v2.3.0](https://github.com/dfinity/evm-rpc-canister/releases/tag/v2.3.0),
which includes the following main changes:
* Fix the HTTPs outcall cycles cost calculation to avoid overcharging.


## Upgrade args

```
git fetch
git checkout c3592e02905e68dba671b055468fea97612c0374
didc encode -d candid/evm_rpc.did -t '(InstallArgs)' '(record {})' | xxd -r -p | sha256sum
```

## Release Notes

```
git log --format='%C(auto) %h %s' 3de8830e509cb97411367a153494e524573903f4..c3592e02905e68dba671b055468fea97612c0374 --
c3592e0 chore: release v2.3.0 (#366)
705d4e3 build(deps-dev): bump braces from 3.0.2 to 3.0.3 (#337)
b0a4dc5 build(deps-dev): bump elliptic from 6.5.4 to 6.6.1 (#336)
4302ec6 build(deps-dev): bump secp256k1 from 4.0.3 to 4.0.4 (#335)
7d6ba9e build(deps): bump serde from 1.0.215 to 1.0.217 (#349)
31024b4 build(deps): bump thiserror from 2.0.8 to 2.0.11 (#355)
d9df5d8 ci: remove protoc (#365)
6a2322f fix: make subnet nodes configurable and fix https outcall cost calculation (#351)
66c27da build(deps): bump proptest from 1.5.0 to 1.6.0 (#345)
f7e8218 build(deps): bump candid from 0.10.12 to 0.10.13 (#360)
afce5ae build: change dependabot config (#363)
a89e720 build(deps): bump serde_json from 1.0.133 to 1.0.138 (#362)
c27c080 chore: Move Ankr to default ETH Sepolia services (#358)
9df7365 fix: build pipeline (#359)
15ee1d2 build(deps): bump candid from 0.10.10 to 0.10.12 (#356)
b3ebd09 feat: allow to override provider url upon installation (#346)
5c843c4 build: update libraries (#347)
284a4dc refactor: metrics (#341)
dda8dc0 build(deps): bump serde from 1.0.210 to 1.0.215 (#331)
9996555 build(deps): bump serde_json from 1.0.132 to 1.0.133 (#334)
825b940 build(deps): bump ic-stable-structures from 0.6.6 to 0.6.7 (#340)
f539c0b ci: Fix CODEOWNERS (#339)
c72a852 build(deps): bump ic-stable-structures from 0.6.5 to 0.6.6 (#332)
2be18d8 build(deps): bump thiserror from 1.0.64 to 1.0.69 (#330)
146f4cc build(deps): bump regex from 1.11.0 to 1.11.1 (#324)
0d7a73c build(deps): bump serde_json from 1.0.129 to 1.0.132 (#319)
ed3447f docs: remove outdated authorization commands (#323)
2a2b9a9 build: use pocket IC action (#320)
c743044 chore: proposal to deploy v2.2.0 (#317)
e920757 build(deps): bump serde_json from 1.0.128 to 1.0.129 (#318)
 ```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout c3592e02905e68dba671b055468fea97612c0374
"./scripts/docker-build"
sha256sum ./evm_rpc.wasm.gz
```
