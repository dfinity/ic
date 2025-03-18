# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Added `Neuron.topic_followees` to support the upcoming [SNS topics](https://forum.dfinity.org/t/sns-topics-design) feature

## Changed

* Proposal criticality is now defined based on topics. This makes the following two native proposal
  types critical:
    * `AddGenericNervousSystemFunction`
    * `RemoveGenericNervousSystemFunction`

    For more details, please refer to
    [PSA(SNS): Proposal criticality to be defined based on proposal topics](https://forum.dfinity.org/t/psa-sns-proposal-criticality-to-be-defined-based-on-proposal-topics/41685).

## Deprecated

## Removed

## Fixed

## Security
