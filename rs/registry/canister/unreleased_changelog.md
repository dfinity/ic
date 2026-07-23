# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* Cloud Engines are now allowed to have blank `replica_version_id` (in their
  `SubnetRecord`). In this case, `StandardEngineReplicaVersionRecord` is used to
  determine the Cloud Engine's replica version.

## Deprecated

## Removed

## Fixed

## Security
