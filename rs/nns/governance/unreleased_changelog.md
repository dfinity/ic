# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Record votes by known neurons before clearing ballots.
* Allow updating known neuron through RegisterKnownNeuron without having to change its name.
* Added `committed_topics` to the `KnownNeuronData` that can be submitted as part of the
  `RegisterKnownNeuron` proposal.
* Add an API to list neuron votes given a specific neuron id. In the short term it only works for
  known neurons as only known neuron votes are recorded.
* Enable 2 features - (1) recording known enuron voting history and (2) proposal type to deregister
  known neurons.

## Changed

* Stop exposing known neuron data in list_neurons so that it's less likely to exceed message size
  limit.

* The Dogecoin canister (ID begins with gordg-) is considered a "protocol"
  canister. This affects proposal topics.

## Deprecated

* The `StopOrStartCanister` NNS Function is now obsolete (Use `Action::StopOrStartCanister`
  instead).

## Removed

## Fixed

## Security
