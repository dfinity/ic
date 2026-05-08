# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
* Added an optional field `initial_dkg_subnet_id` to `SplitSubnetPayload` and `FulfillSubnetRentalRequest`,
  which allows the proposer to choose which subnet should be responsible for generating the initial key
  material of the split or rented subnet.

## Changed
* Updated the response text of some failed registry mutations. "Blessed" -> "Elected".
* Tightened chain-key config validation and invariants:
  `pre_signatures_to_create_in_advance` must be non-zero for keys that require pre-signatures,
  and must be `None` for keys that do not.

## Deprecated

## Removed
* Removed the completed `fix_vetkd_pre_signatures_field` post-upgrade data migration and its
  migration-specific unit test.

## Fixed

## Security
