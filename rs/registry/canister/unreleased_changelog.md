# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* A subnet-split request will now fail if a concurrent call modified the `StandardEngineReplicaVersionRecord`
  while the fresh key material was being generated for the splitting subnet.

* A subnet-split request whose source subnet is a cloud engine that derives its replica version from the
  `StandardEngineReplicaVersionRecord` will now be rejected while a deployment of a new replica version is
  in progress. This guarantees that both subnets run the same replica version after the split.

* Invariant requiring that every elected GuestOS and HostOS version ID is well-formed, i.e. that it consists
  only of alphanumeric characters, dots, dashes and underscores.  Such IDs are what `ReplicaVersion` and
  `HostosVersion` accept, so until now, it was possible to elect a version that consumers could not read
  back out of the Registry.

* `merge_subnets` endpoint, callable through a `MergeSubnets` proposal. It takes a source and a
  destination subnet ID, and merges the canister ID ranges of the source subnet into the canister
  ID range set of the destination subnet, i.e., the canisters hosted by the source subnet are
  routed to the destination subnet afterwards. Only the routing table is updated: neither subnet
  record is modified and the source subnet is not deleted.

## Changed

* `UpdateStandardEngineReplicaVersion` can now start a new deployment after the previous one has been
  fully rolled back (`deployment_progress == 0.0`), not just after it has been fully rolled forward
  (`deployment_progress == 1.0`).

## Deprecated

## Removed

## Fixed

## Security
