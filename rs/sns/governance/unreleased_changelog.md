# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

The concept of topics has now been introduced to the SNS. This means that when custom function is added via an `AddGenericNervousSystemFunction` proposal, a topic can be specified for that custom function. This can be used for organizing the following page, and could be used for more in the future.

A `list_topics` API has been added, which returns a list of topics and all the functions categorized in those topics. 

## Changed

The new `topic` field is required when submitting an `AddGenericNervousSystemFunction` proposal.

## Deprecated

## Removed

## Fixed

## Security
