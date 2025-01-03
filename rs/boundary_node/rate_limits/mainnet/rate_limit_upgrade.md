# Upgrade the Rate-Limit Canister to Commit ab29295

__Proposer__: DFINITY Foundation

__Source code__: [ab29295b39258e753aafaaad72c740d938d61e35][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/ab29295b39258e753aafaaad72c740d938d61e35

## Summary

Following the adoption of the motion proposal addressing [incident handling](https://dashboard.internetcomputer.org/proposal/134031) within the framework of the new decentralized boundary node architecture, we propose the deployment of the new rate-limit canister.

This canister will enable API boundary nodes to enforce rate-limiting rules issued by an authorized Dfinity principal, hence protecting the Internet Computer during incidents. Canister is designed as an append-only storage model, ensuring transparency and auditability of rate-limit rules after incidents disclosure. 

The authorized principal responsible for pushing new rate-limit configurations and disclosing them is specified through the upgrade arguments in this proposal.

## Upgrade Arguments

```candid
(record {authorized_principal = opt principal "2igsz-4cjfz-unvfj-s4d3u-ftcdb-6ibug-em6tf-nzm2h-6igks-spdus-rqe"; registry_polling_period_secs = 60;})
```

## Verification

See the general instructions on [how to verify] proposals like this. A "quick
start" guide is provided here.

[how to verify]: https://github.com/dfinity/ic/tree/ab29295b39258e753aafaaad72c740d938d61e35/rs/nervous_system/docs/proposal_verification.md


### WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/ab29295b39258e753aafaaad72c740d938d61e35/README.adoc#building-the-code

```
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout ab29295b39258e753aafaaad72c740d938d61e35

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/rate-limit-canister.wasm.gz
```

This should match `wasm_module_hash` field of this proposal.


### Upgrade Arguments Verification

[`didc`][latest-didc] is required.

[latest-didc]: https://github.com/dfinity/candid/releases/latest

```
didc encode '(record {authorized_principal = opt principal "2igsz-4cjfz-unvfj-s4d3u-ftcdb-6ibug-em6tf-nzm2h-6igks-spdus-rqe"; registry_polling_period_secs = 60;})' | xxd -r -p | sha256sum
```

This should match the `arg_hash` field of this proposal.
