# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enabled subnet splitting: the `split_subnet` endpoint, called by `SplitSubnet` proposals, now
  splits a subnet instead of rejecting every request.

## Changed

* The invariant requiring that every subnet's `CatchUpPackageContents` record has a `cup_type` set
  now also requires that `cup_type` is decodable.

* `add_node` accepts SEV-SNP attestation reports from AMD EPYC Turin CPUs with models 0x12 to 0x1F, as
  it already did for models 0x00 to 0x11.

## Deprecated

## Removed

## Fixed

* Creating or splitting off a subnet no longer reuses the canister IDs of a deleted subnet. A
  deleted subnet's ranges are removed from the routing table, so a new subnet used to receive
  exactly the same canister IDs whenever the deleted subnet had held the last range. The registry
  now stores a `CanisterIdAllocation` record (key `canister_id_allocation`) such that no canister
  index at or above its `next_unallocated_canister_index` has ever been allocated to a subnet, and
  new ranges start at or above it. The upgrade backfills the record from the full history of the
  routing table.

## Security
