# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Invariant requiring that SEV-enabled subnets may only run a GuestOS version that has
  `guest_launch_measurements`.

* `cooling_down` field in `SubnetRecord`, settable via `UpdateSubnetRecord` proposals. See
  `ic_replicated_state::SubnetTopology::cooling_down` for the exact semantics. The field must not
  be set on mainnet before the replica version rejecting ingress messages to cooling down subnets
  has been rolled out to all subnets.

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
