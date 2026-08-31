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

* `merge_subnets` endpoint, callable through a `MergeSubnets` proposal. It takes a source and a
  destination subnet ID, plus the height, time and state hash of the merged state, and performs the
  whole registry-side part of a subnet merge in a single registry version:

  * the canister ID ranges of the source subnet are merged into the canister ID range set of the
    destination subnet, i.e., the canisters hosted by the source subnet are routed to the
    destination subnet afterwards;
  * a recovery catch-up package is created for the destination subnet, at the given height, time
    and state hash, running a fresh DKG for the destination subnet's membership; and
  * the destination subnet is brought back online.

  The caller is expected to have taken both subnets offline and to have extended the state of the
  destination subnet with the state of the canisters of the source subnet beforehand. The source
  subnet record is not modified and the source subnet is not deleted: it merely does not host any
  canister ID range anymore. Merging into a subnet holding chain keys is rejected, as the recovery
  catch-up package does not reshare them.

## Changed

## Deprecated

## Removed

## Fixed

## Security
