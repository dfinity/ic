Each canister has a "primary" code directory (e.g. NNS governance's primary code
directory is `rs/nns/governance`). Within that directory, there lives two files:

1. `unreleased_changelog.md`
2. `CHANGELOG.md`

The next section describes how these files are maintained.

# Standard Operating Procedure

1. When a PR introduces user-visible behavior change in release builds (e.g. the
   PR simply consists of `IS_MY_FEATURE_ENABLED = true`), add an entry to the
   corresponding `unreleased_changelog.md` file (under the "Next Upgrade
   Proposal" heading). This new entry should be added in the **same** PR. There
   is a bot that reminds you to do this.

2. When making an NNS proposal to upgrade this canister (or in the case of SNS,
   publish a new WASM), copy entries from `unreleased_changelog.md` to the
   proposal's "Features & Fixes" section. This is handled automatically by our
   proposal generator scripts.

3. After the proposal is executed, move the entries from
   `unreleased_changelog.md` to its sibling `CHANGELOG.md` file. This can be
   done by running

   ```bash
   PROPOSAL_ID=???

   ./rs/nervous_system/tools/release/add-release-to-changelog.sh $PROPOSAL_ID
   ```

If your new code is not active in release builds (because it is behind a feature
flag, or it is simply not called yet), then, do NOT add an entry to
`unreleased_changelog.md`. Instead, wait until your code is actually active in
release builds (e.g. the feature flag is flipped to "enable") before adding an
entry to `unreleased_changelog.md`.


# How to Write a Good Entry

The intended audience of your new entry is people who vote on NNS proposals. In
particular, these people are not necessarily engineers who develop this
canister. In fact, it is best to assume that the reader does not know how to
program at all. (In fact, very many very intelligent people do not know how to
write code!)

Look at [this example]. Notice how the only Rust code changes in that PR just
sets some `IS_MY_FEATURE_ENABLED` "feature flags" to true. The entry being added
to the `unreleased_changelog.md` file in that same PR describes what the code
behind the flag does, because suddenly, that code is now active in release
builds.

[this example]: https://github.com/dfinity/ic/pull/3371/files#diff-a0dc71a90ca0ffb3298781894bae5c9dce11c53078ad815c5df1bec4cf0bf625


# The Origin of This Process

This process is modeled after the process used by nns-dapp. nns-dapp in turn
links to keepachangelog.com as its source of inspiration.
