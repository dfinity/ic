# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed
Guest launch measurements should now be stored hex encoded under
`encoded_measurement` as well as the deprecated `measurement`.

## Deprecated
The `measurement` field is now deprecated, but should continue to be populated
until it is completely removed.

## Removed

## Fixed

## Security
