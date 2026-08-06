# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `maximum_query_instructions` and `maximum_query_walltime_seconds` fields to the
  subnet record's `ResourceLimits`, allowing the query instruction limit and the maximum query
  wall-clock time to be configured per subnet via `create_subnet` and `update_subnet`.
  `maximum_query_instructions` applies both to a single (non-composite) query method execution
  and to the total across a composite query call graph; `maximum_query_walltime_seconds`
  bounds the wall-clock time a query (including a composite query call graph) may run. For each,
  a value of `0` (or unset) means the replica's default is used.

## Changed

* Cloud Engines are now allowed to have blank `replica_version_id` (in their
  `SubnetRecord`). In this case, `StandardEngineReplicaVersionRecord` is used to
  determine the Cloud Engine's replica version.
* `revise_elected_guestos_versions` now treats `guest_launch_measurements` as one of the parameters
  that electing a GuestOS version requires, alongside `replica_version_to_elect`,
  `release_package_sha256_hex` and `release_package_urls`: those parameters all have to be either
  set or unset. Consequently, a proposal that elects a version without measurements is now
  rejected, and so is one that provides measurements without electing a version (they would have
  been dropped silently). The corresponding error message now also names the parameters that are
  missing. Unelecting versions on its own is unaffected.

## Deprecated

## Removed

## Fixed

## Security
