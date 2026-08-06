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
* A SEV-enabled subnet may only run a GuestOS version that has
  `guest_launch_measurements`. Without a launch measurement, the nodes of such a
  subnet cannot be attested, which defeats the purpose of enabling SEV. This is
  enforced as a registry invariant, so any mutation that would leave a
  SEV-enabled subnet on a version without launch measurements is rejected. For a
  Cloud Engine with a blank `replica_version_id`, the versions of the
  `StandardEngineReplicaVersionRecord` are the ones that must have launch
  measurements.

## Deprecated

## Removed

## Fixed

## Security
