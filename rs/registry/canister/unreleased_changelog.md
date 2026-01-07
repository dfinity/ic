# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

* Display correct error message for node swaps in case of rate limit errors
* Migrate vetKD chain keys in specific subnets: change the chain key config's `pre_signatures_to_create_in_advance` field from `Some(0)` to `None` to align with the correct representation for keys that do not have pre-signatures

## Security
