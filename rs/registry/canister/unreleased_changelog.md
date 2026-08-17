# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

Add a `replica_version_id` to `ReplicaVersionRecord`s, and backfill with a data migration.

## Changed

* Guest launch measurements are now required (when electing a new GuestOS version).

* `deploy_guestos_to_all_subnet_nodes` now accepts a blank `replica_version_id`
  for Cloud Engines, provided a `StandardEngineReplicaVersionRecord` exists.
  This is how a Cloud Engine that pins a version goes back to following the
  standard engine version. Previously, only engine *creation* could leave
  `replica_version_id` blank, because this endpoint required the version to be
  elected, and a blank version never is.

## Deprecated

## Removed

The `blessed_replica_versions` record has been removed.

## Fixed

## Security
