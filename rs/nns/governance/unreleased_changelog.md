# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* The `init` method now supports candid decoding in addition to protobuf. Protobuf decoding will be
  removed in the future, giving clients time to migrate.

## Changed

* Increased the probability of failure from 70% to 90% for the deprecated _pb methods.
* Increase the neurons limit to 500K now that neurons are stored in stable memory.

## Deprecated

## Removed

* The `topic_followee_index` in the heap is removed, along with the flag
  `USE_STABLE_MEMORY_FOLLOWING_INDEX` that was set to true in the proposal 135063.

## Fixed

## Security
