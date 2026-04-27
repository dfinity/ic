# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* `TakeCanisterSnapshot` proposals now store the new snapshot ID in the
  `success_value` field.

## Changed

* Relax eight year gang membership requirement(s): Instead of needing to have dissolve
  delay >= 8 * 365.25 days (8 "years"), which is exactly 252_460_800 seconds, a second
  round of induction requires only that neurons had dissolve delay >= 8 * 365 days,
  which is exactly 252_288_000 seconds. This is less than a 0.07% difference.
  Additionally, to avoid bonusing newly staked ICP, the neuron must currently be aging
  since before March 30 (midnight UTC). (Furthermore, neurons that are already members
  will not have their eight year gang bonus base re-assessed.)

## Deprecated

## Removed

## Fixed

## Security
