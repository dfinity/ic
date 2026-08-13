# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.
* Invariant requiring that both versions of the `StandardEngineReplicaVersionRecord` have
  `guest_launch_measurements`. This holds regardless of whether any engine is SEV-enabled, because
  a CloudEngine that leaves `replica_version_id` blank runs those versions.

## Changed

## Deprecated

## Removed

The `blessed_replica_versions` record has been removed.

## Fixed

## Security
