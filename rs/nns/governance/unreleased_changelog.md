# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Record votes by known neurons before clearing ballots.
* Added `committed_topics` to the `KnownNeuronData` that can be submitted as part of the
  `RegisterKnownNeuron` proposal.

## Changed

## Deprecated

* The `StopOrStartCanister` NNS Function is now obsolete (Use `Action::StopOrStartCanister`
  instead).

## Removed

## Fixed

## Security
