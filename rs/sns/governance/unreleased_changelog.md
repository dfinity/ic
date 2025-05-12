# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

## Changed

The DAO community settings topic is promoted to being critical. For context, please refer to
the [forum thread](https://forum.dfinity.org/t/make-sns-topic-dao-community-settings-critical/46689).

SNS neuron baskets created for swap participants are now set up using topic-based following.
Within each basket, there is still a root neuron with the largest dissolve delay (which does not
follow anyone), and all other neurons in the same basket will now follow the root on all topics,
including the critical ones (beforehand only non-critical following was set up within each basket).
Read more details in the [forum thread](https://forum.dfinity.org/t/topic-based-following-for-swap-neuron-baskets/43649).

## Deprecated

## Removed

## Fixed

## Security
