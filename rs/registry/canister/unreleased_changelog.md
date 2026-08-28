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

* Invariant requiring that every elected GuestOS and HostOS version ID is well-formed,
  i.e. that it consists only of alphanumeric characters, dots, dashes and underscores.
  Such IDs are what `ReplicaVersion` and `HostosVersion` accept, so until now, it was
  possible to elect a version that consumers could not read back out of the Registry.

## Changed

## Deprecated

## Removed

## Fixed

## Security
