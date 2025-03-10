# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `NetworkEconomics.voting_power_economics.neuron_minimum_dissolve_delay_to_vote_seconds`.

## Changed

* Refactor `prune_following` task to use the `timer_task` library, and therefore enables metrics to
  be collected about its execution.

## Deprecated

## Removed

* Removed a migration mechanism previously used for data migrations through heartbeat.

## Fixed

## Security
