# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.

* A subnet-split request will now fail if a concurrent call modified the `StandardEngineReplicaVersionRecord`
  while the fresh key material was being generated for the splitting subnet.

## Changed

## Deprecated

## Removed

## Fixed

## Security
