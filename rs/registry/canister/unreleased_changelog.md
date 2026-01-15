# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

* Promoted the check for empty SEV measurements in replica versions from a check on proposals, to an invariant of the registry.

* When performing subnet creation, subnet update, or subnet recovery, it is now mandatory to omit the `KeyConfig`'s `pre_signatures_to_create_in_advance` field for keys that do not have pre-signatures. Currently only vetKD keys do not have pre-signatures (unlike Ecdsa/Schnorr keys).

  This is a *breaking* change because setting the `pre_signatures_to_create_in_advance` field for vetKD keys is no longer allowed. However, only governance proposals are affected, which are typically constructed via ic-admin, which was adapted to behave correctly.

## Deprecated

## Removed

## Fixed

* Migrate vetKD chain keys in specific subnets: change the chain key config's `pre_signatures_to_create_in_advance` field from `Some(0)` to `None` to align with the correct representation for keys that do not have pre-signatures
* When performing `RemoveNodes`, generate 1 update mutation per node operator key. Before this change, a single node operator record would be changed multiple times in a single version if the remove nodes proposal removed multiple nodes from the same node operator, which caused confusion.

## Security
