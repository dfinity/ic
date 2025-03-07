# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Collect metrics about timer tasks defined using ic_nervous_system_timer_task library.
* Added `NetworkEconomics.voting_power_economics.neuron_minimum_dissolve_delay_to_vote_seconds`.

## Changed

* Voting Rewards will be scheduled by a timer instead of by heartbeats.
* Unstaking maturity task will be processing up to 100 neurons in a single message, to avoid
  exceeding the instruction limit in a single execution.
* Voting Rewards will be distributed asynchronously in the background after being calculated.  
  * This will allow rewards to be compatible with neurons being stored in Stable Memory. 
* Ramp up the failure rate of _pb method to 0.7 again.

## Deprecated

## Removed

## Fixed

* Avoid applying `approve_genesis_kyc` to an unbounded number of neurons, but at most 1000 neurons.

## Security
