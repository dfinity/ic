# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* When performing subnet creation, subnet update, or subnet recovery, it is now mandatory to omit the `KeyConfig`'s `pre_signatures_to_create_in_advance` field for keys that do not have pre-signatures. Currently only vetKD keys do not have pre-signatures (unlike Ecdsa/Schnorr keys).

  This is a *breaking* change because setting the `pre_signatures_to_create_in_advance` field for vetKD keys is no longer allowed. However, only governance proposals are affected, which are typically constructed via ic-admin, which was adapted to behave correctly.

## Deprecated

## Removed

## Fixed

* Display correct error message for node swaps in case of rate limit errors

## Security
