# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new proposal type `DeregisterKnownNeuron` without enabling it (behind feature flag).

* Enable FulfillSubnetRentalRequest proposals. The main effect of such proposals
  is the creation of an EXCLUSIVE subnet, meaning that only ONE principal is
  allowed to create canisters in the subnet. For details, see
  https://forum.dfinity.org/t/subnet-rental-canister-work-on-next-phase-has-started/52803
  (This is also discussed under the heading "Swiss subnet".)

* Added links to the `KnownNeuronData` that can be submitted as part of the `RegisterKnownNeuron`
  proposal.

## Changed

## Deprecated

* The `StopOrStartCanister` NNS Function is now obsolete (Use `Action::StopOrStartCanister`
  instead).

## Removed

## Fixed

## Security
