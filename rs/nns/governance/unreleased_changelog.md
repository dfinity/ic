# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enabled `SplitSubnet` proposals (topic: Subnet Management). They were previously
  rejected at submission time.

## Changed

## Deprecated

## Removed

## Fixed

* Refreshing a neuron's stake no longer locks the neuron when the balance of
  the neuron's account equals its recorded stake. Such a refresh now succeeds
  even while another operation on the neuron is in progress, and does not delay
  other operations on the neuron.

## Security
