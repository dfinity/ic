# Install the Rate-Limit Canister from Commit ab29295

__Proposer__: DFINITY Foundation

__Source code__: [ab29295b39258e753aafaaad72c740d938d61e35][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/ab29295b39258e753aafaaad72c740d938d61e35

## Summary

Following the adoption of the motion proposal addressing [incident handling](https://dashboard.internetcomputer.org/proposal/134031) within the framework of the new decentralized boundary node architecture, we propose the deployment of the new rate-limit canister.

This canister will enable API boundary nodes to enforce rate-limiting rules issued by an authorized DFINITY principal, hence protecting the ICP during incidents. Canister is designed as an append-only storage model, ensuring transparency and auditability of rate-limit rules after incidents disclosure. 

The authorized principal responsible for pushing new rate-limit configurations and disclosing them is specified through the upgrade arguments in this proposal.

## Verifying the installation

First, make sure your Git repo has the right information.

```
# Option A. Get a fresh copy of the code.
git clone git@github.com:dfinity/ic.git && cd ic
# Option B. If you already have a copy of the ICP repo.
git fetch
```

Second, checkout the right version of the code.

```
git checkout ab29295b39258e753aafaaad72c740d938d61e35
```

### Argument Verification

The [didc][latest_didc] tool is required.

[latest_didc]: https://github.com/dfinity/candid/releases/latest

Fingerprint the canister argument:

```
didc encode \
    -d rs/boundary_node/rate_limits/canister/interface.did \
    -t '(InitArg)' \
    '(record {
        authorized_principal = opt principal "2igsz-4cjfz-unvfj-s4d3u-ftcdb-6ibug-em6tf-nzm2h-6igks-spdus-rqe";
        registry_polling_period_secs = 60;
    })' | xxd -r -p | sha256sum
```

This should match `arg_hash` field of this proposal.

### WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/ab29295b39258e753aafaaad72c740d938d61e35/README.adoc#building-the-code

Build the release version of canisters:

```
./ci/container/build-ic.sh -c
```

Fingerprint the canister module:

```
sha256sum ./artifacts/canisters/rate-limit-canister.wasm.gz
```

This should match `wasm_module_hash` field of this proposal.
