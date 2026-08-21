# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.

* Enforce that every `hostos_version_id` matches its `HostosVersionRecord`'s registry key.

## Changed

* `deploy_guestos_to_all_subnet_nodes` now accepts a blank `replica_version_id`
  for Cloud Engines, provided a `StandardEngineReplicaVersionRecord` exists.
  This is how a Cloud Engine that pins a version goes back to following the
  standard engine version. Previously, only engine *creation* could leave
  `replica_version_id` blank, because this endpoint required the version to be
  elected, and a blank version never is.

## Deprecated

## Removed

## Fixed

## Security
