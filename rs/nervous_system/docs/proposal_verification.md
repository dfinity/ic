# NNS and SNS Proposal Verification
__Author__: Daniel Wong (daniel.wong at dfinity.org)\
__Date__: Sep, 2024

You most likely came here via a link in a proposal to either upgrade an NNS
canister, or publish a new SNS WASM (to the SNS-W canister). (Regardless of how
you came here, welcome 🤗)

What this page explains is how to verify claims that are typically made in the
title and summary of such proposals. The most interesting claim in such
proposals is what source code was used (to build the WASM in the proposal). Some
technical savvy is required to follow these instructions.

Alternatively, the following videos cover mostly the same information as this
page:

[![How to Verify NNS Canister Upgrade Proposals](https://img.youtube.com/vi/BsIg4JZobqU/0.jpg)](https://www.youtube.com/watch?v=BsIg4JZobqU)

[![How to Verify NNS Canister Upgrade Proposals](https://img.youtube.com/vi/i_ANhb0E1Io/0.jpg)](https://www.youtube.com/watch?v=i_ANhb0E1Io)


## Why?

The title and summary of a proposal has _no impact_ on the _actual effect_ of
executing a proposal. Therefore, the proposer can _claim_ that the proposal will
do one thing in the title and/or summary, while the actual effect of the
proposal could be something completely different.

Therefore, it is incumbant upon NNS neurons to verify proposals before casting
their votes, especially for neurons who recruit others to follow them.

Furthermore, the Internet Computer handles substantial amounts of value.

> With great power comes great responsibility.\
> --Uncle Ben

If the proposer is malicious, the summary would falsely claim that the proposal
does something desirable, when in fact, the proposal does something very
fraudulent (if adopted and executed).

In most cases, when the title and/or summary is incorrect, it is simply due to a
mistake by the proposer, or a bug in the tool(s) that they used. Verification is
also a safeguard against mistakes.


## WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic?tab=readme-ov-file#building-the-code

In a terminal, run these commands:

```
# 0. Get this from the proposal summary.
PROPOSAL_COMMIT_ID=???

# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
git fetch  # In case you cloned earlier.
git checkout $PROPOSAL_COMMIT_ID

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/*.wasm.gz
```

The last command will print out the fingerprints of many files. Look for the
line corresponding to the canister targetted by the proposal.

In the case of NNS canister upgrade proposals, the fingerprint should match the
proposal's `wasm_module_hash` field; in the case of proposals that publish a new
SNS WASM, the fingerprint should match the proposal's `wasm` field.


## Upgrade Arguments Verification

Especially in the case of Cycles Minting canister upgrades, the `arg_hash` field
of an NNS upgrade proposal might be nonempty. In that case, the summary should
say what the upgrade arguments are (in Candid text format). This section
explains how to verify this part of the summary.

These instructions assume that [`didc`][latest-didc] is in your `$PATH`.

[latest-didc]: https://github.com/dfinity/candid/releases/latest

In a terminal, run the following commands:

```
# 0. If args_hash is nonempty, get this from the proposal summary.
UPGRADE_ARGS=???

# 1. Encode and fingerprint the upgrade arguments.
didc encode "${UPGRADE_ARGS}" | xxd -r -p | sha256sum
```

The last command should print the value in the `arg_hash` field of the proposal.


## Verifying Other Fields

### NNS

* `canister_id` - Usually, the title of the proposal will refer to the target
  canister by name (such as "governance"), but the canister that will actually
  be affected is referred to by an ID. NNS canisters themselves use constants
  defined in [this file][nns-canister-ids] to map between name and ID.
  
[nns-canister-ids]: https://sourcegraph.com/search?q=repo:%5Egithub%5C.com/dfinity/ic%24+%22REGISTRY_CANISTER_ID:+CanisterId+%3D%22+f:nns&patternType=keyword&sm=0

* `install_mode`: This field contains an integer code, whose meaning can be
  gleaned from the definition of the [CanisterInstallMode enum]. In general,
  this would be set to 3 (upgrade).
  
[CanisterInstallMode enum]: https://sourcegraph.com/search?q=repo:%5Egithub%5C.com/dfinity/ic%24+f:nns/governance/api+enum+InstallMode&patternType=regexp&case=yes&sm=0


### SNS

* `canister_type` - This field contains an integer code, whose meaning can be
  gleaned from the definition of the [SnsCanisterType enum]. E.g. for
  governance, this field would contain 2.
  
[SnsCanisterType enum]: https://sourcegraph.com/search?q=context:%40daniel.wong1/ic+f:sns-wasm+enum+SnsCanisterType&patternType=regexp&case=yes&sm=1
