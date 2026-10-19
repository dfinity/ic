# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

* Proposals that execute a generic (non-native) nervous system function now
  store the raw reply bytes from the target canister in the proposal itself
  (`ProposalData.execution_reply`). Previously, the reply was just discarded.
  To avoid using too much space, only the first 5 KB of the reply is stored.

## Security
