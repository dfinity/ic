# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed
* Compile the `lifeline` canister with the latest Motoko compiler (0.16.3) (compared to compiling with 0.8.7 before)
  but keep using classical orthogonal persistence by compiling with `--legacy-persistence`.
  Note that this compiler upgrade does not change the behaviour of the `lifeline` canister.

## Deprecated

## Removed

## Fixed

## Security
