# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

Logo validation now checks that the decoded bytes start with the PNG magic bytes
(signature), instead of accepting any base64 that carries the `data:image/png;base64,`
prefix.

## Deprecated

## Removed

## Fixed

## Security
