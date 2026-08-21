# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.

* Invariant requiring that every elected GuestOS and HostOS version ID is well-formed,
  i.e. that it consists only of alphanumeric characters, dots, dashes and underscores.
  Such IDs are what `ReplicaVersion` and `HostosVersion` accept, so until now, it was
  possible to elect a version that consumers could not read back out of the Registry.

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
