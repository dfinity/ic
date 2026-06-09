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
* Added a new `NnsFunction` variant `DeployGuestosToAllCloudEngines`, which
  proposes to deploy a given (elected) GuestOS version to every CloudEngine
  subnet at once. The set of affected subnets is resolved from the registry at
  execution time rather than captured in the proposal payload.

## Changed

## Deprecated

## Removed

## Fixed

## Security
