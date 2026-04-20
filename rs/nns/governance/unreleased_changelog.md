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

* Enable Mission 70 voting rewards changes. This includes the following:
  1. Reduce max dissolve delay from 8 years to 2 years. This includes capping existing neurons via data migration.
  2. Reduce voting rewards pool by approximately 36.71% (equivalently, scale by 0.6329 times).
  3. Dissolve delay bonus: quadratic instead of linear, with a maximum of 3x instead of 2x.
  4. Reduce the minimum dissolve delay needed to vote to 2 weeks instead of 6 months.
  5. 8 year gang 10% bonus.

## Deprecated

## Removed

## Fixed

## Security
