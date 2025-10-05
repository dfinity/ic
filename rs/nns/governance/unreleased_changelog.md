# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Record votes by known neurons before clearing ballots.
* Introduces two new proposals called `PauseMigrations` and `UnpauseMigrations`.

## Changed

* Stop exposing known neuron data in list_neurons so that it's less likely to exceed message size
  limit.

## Deprecated

* The `StopOrStartCanister` NNS Function is now obsolete (Use `Action::StopOrStartCanister`
  instead).

## Removed

## Fixed

## Security
