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

### Disable replacement of nodes that are active in subnets

Direct node replacements of nodes that are active in a subnet may result in unexpected behavior and potential problems in the current Consensus code.
So to be on the safe side we need to disable the functionality on the Registry side until the rest of the core protocol can handle it safely.

## Security
