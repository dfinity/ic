# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* `cooling_down` field in `SubnetRecord`, settable via `UpdateSubnetRecord` proposals. See
  `ic_replicated_state::SubnetTopology::cooling_down` for the exact semantics. The field must not
  be set on mainnet before the replica version rejecting ingress messages to cooling down subnets
  has been rolled out to all subnets.

* A subnet-split request will now fail if a concurrent call modified the `StandardEngineReplicaVersionRecord`
  while the fresh key material was being generated for the splitting subnet.

* A subnet-split request whose source subnet is a cloud engine that derives its replica version from the
  `StandardEngineReplicaVersionRecord` will now be rejected while a deployment of a new replica version is
  in progress. This guarantees that both subnets run the same replica version after the split.

## Changed

## Deprecated

## Removed

## Fixed

## Security
