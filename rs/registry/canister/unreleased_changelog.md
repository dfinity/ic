# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* When performing subnet creation, subnet update, or subnet recovery, it is now allowed to omit the `KeyConfig`'s `pre_signatures_to_create_in_advance` field for keys that do not have pre-signatures. Currently only vetKD keys do not have pre-signatures (unlike Ecdsa/Schnorr keys). When the field is omitted, it is automatically set to zero.

## Deprecated

## Removed

## Fixed

* When performing `RemoveNodes`, generate 1 update mutation per node operator key. Before this change, a single node operator record would be changed multiple times in a single version if the remove nodes proposal removed multiple nodes from the same node operator, which caused confusion.

## Security
