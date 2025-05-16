# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* The `DisburseMaturity` neuron command is enabled. See https://forum.dfinity.org/t/disburse-maturity-in-nns/43228 for more details.

## Changed

* Proposal topics are persisted throughout its lifecycle instead of being recomputed every time.

## Deprecated

## Removed

## Fixed

## Security
Enforce a lower bound for `min_participant_icp_e8s` of `1_000_000`.