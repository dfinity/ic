# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

Promoted the check for empty SEV measurements in replica versions from a check
on proposals, to an invariant of the registry.

## Deprecated

## Removed

## Fixed

* Migrate vetKD chain keys in specific subnets: change the chain key config's `pre_signatures_to_create_in_advance` field from `Some(0)` to `None` to align with the correct representation for keys that do not have pre-signatures

## Security
