# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.
* Invariant requiring that both versions of the `StandardEngineReplicaVersionRecord` have
  `guest_launch_measurements`.
* Add a `replica_version_id` to `ReplicaVersionRecord`s, and backfill with a data migration.

## Changed

* Guest launch measurements are now required (when electing a new GuestOS version).

## Deprecated

## Removed

The `blessed_replica_versions` record has been removed.

## Fixed

## Security
