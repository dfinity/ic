# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

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

The `blessed_replica_versions` record has been removed.

## Fixed

## Security
