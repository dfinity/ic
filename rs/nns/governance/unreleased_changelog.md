# How This File Is Used

1. When there is a user-visible behavior change to this canister, add an entry
   to this file (in the "Next Upgrade Proposal" section) in the same PR.

2. When making an NNS proposal to upgrade this canister, copy entries to the
   proposal's summary.

3. After the proposal is executed, move the entries from this file to a new
   section in the adjacent CHANGELOG.md file.

If your new code is not active in release builds (because it is behind a feature
flag, or it is simply not called yet), then do NOT add an entry to this file,
because this new function has no user-visible behavior change yet. Wait until it
is active (e.g. the feature flag is flipped to "enable") before adding an entry
to this file.

TODO: Automate moving content from unreleased_changelog.md to CHANGELOG.md.


# How to Write a Good Entry

The intended audience here is people who vote (with their neurons) in NNS, not
necessarily engineers who develop this canister.


# The Origin of This Process

This process is modeled after the process used by nns-dapp. nns-dapp in turn
links to keepachangelog.com as its source of inspiration.


# Next Upgrade Proposal

## Added

### Periodic Confirmation

Enabled voting power adjustment and follow pruning.

#### Prior Work

This section describes related changes in previous releases.

We already started recording how long it's been since neurons have confirmed
their following (aka refreshed voting power). Neurons were also given the
ability to confirm their following. Those who have never confirmed are
considered as having refreshed on Sep 1, 2024.

This feature was proposed and approved in motion [proposal 132411].

[proposal 132411]: https://dashboard.internetcomputer.org/proposal/132411

#### New Behavior(s) (In This Release)

With this enablement, not refreshing for more than 6 months will start to affect
the neuron. More precisely,

1. If a neuron has not refreshed in 6 months, then votes have less influence on
   the outcome of proposals.

2. If a neuron has not refreshed in 7 months,

    a. It stops following other neurons (except on the NeuronManagement topic;
       those followees are retained).

    b. Its influence on proposals goes to 0.

## Changed

## Deprecated

## Removed

## Fixed

## Security
