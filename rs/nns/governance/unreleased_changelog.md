# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Collect metrics about timer tasks defined using ic_nervous_system_timer_task library.
* Re-enable neuron migration to stable memory:
  * Setting `MIGRATE_ACTIVE_NEURONS_TO_STABLE_MEMORY` to true, which will cause active neurons
  to be continously moved from heap memory to stable memory.
  * Compared to the last time it was enabled, several improvements were made:
    * Distribute rewards is moved to timer, and has a mechanism to distribute in batches in
    multiple messages.
    * Unstaking maturity task has a limit of 100 neurons per message, which prevents it from 
    exceeding instruction limit.
    * The execution of `ApproveGenesisKyc` proposals have a limit of 1000 neurons, above which
    the proposal will fail.
    * More benchmarks were added.

## Changed

* Voting Rewards will be scheduled by a timer instead of by heartbeats.
* Unstaking maturity task will be processing up to 100 neurons in a single message, to avoid
  exceeding the instruction limit in a single execution.
* Voting Rewards will be distributed asynchronously in the background after being calculated.  
  * This will allow rewards to be compatible with neurons being stored in Stable Memory. 
* Ramp up the failure rate of _pb method to 0.7 again.

## Deprecated

## Removed

* Removed a migration mechanism previously used for data migrations through heartbeat.

## Fixed

* Avoid applying `approve_genesis_kyc` to an unbounded number of neurons, but at most 1000 neurons.

## Security
