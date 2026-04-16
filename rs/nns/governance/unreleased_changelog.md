# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enabled CreateCanisterAndInstallCode proposals.

## Changed

* The minimum dissolve delay required to submit non-manage-neuron proposals is now
  a fixed 6 months, decoupled from the voting eligibility threshold which can be lower.
* Mission 70 voting rewards adjustment has been re-calculated. Now: 63.29%. Before: 65.5%.
* Enabled Mission 70 voting rewards. This activates: max dissolve delay capped at
  2 years, voting rewards pool scaled by 0.6329, quadratic dissolve delay bonus,
  reduced minimum dissolve delay to vote, and the 8 year gang 10% voting power bonus.

## Deprecated

## Removed

## Fixed

## Security
