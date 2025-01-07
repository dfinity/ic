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

## Changed

## Deprecated

## Removed

## Fixed

## Security
