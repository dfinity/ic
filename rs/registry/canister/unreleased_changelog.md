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

* `merge_subnets` endpoint. It takes a source and a destination subnet ID, and merges the canister
  ID ranges of the source subnet into the canister ID range set of the destination subnet, i.e., the
  canisters hosted by the source subnet are routed to the destination subnet afterwards. Only the
  routing table is updated: neither subnet record is modified and the source subnet is not deleted.

## Changed

## Deprecated

## Removed

## Fixed

## Security
