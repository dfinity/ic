# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added a new `NnsFunction` variant `SetDefaultInitialDkgSubnet`, which
  proposes to set or unset the default subnet to which `SetupInitialDKG`
  management canister calls are routed when no subnet is specified explicitly
  in the request.

## Changed

## Deprecated

## Removed

## Fixed

* Tolerate XRC failures when updating maturity modulation: compute the average
  over available days using last-observation-carried-forward, and advance past
  days where XRC returns no rate so that a single persistent gap no longer
  stalls maturity modulation updates.

## Security
