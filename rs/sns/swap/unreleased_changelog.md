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

Fix an issue occurring when the NNS Governance cannot find proposals corresponding the creation
of the SNS that requests Neurons' Fund participation during finalization. Note that currently,
SNSs that do not even request Neurons' Fund participation are potentially risking that their
finalization halts if the NNS proposal that created that SNS cannot be found (this recently
happened due to an
[unrelated problem in the NNS](https://forum.dfinity.org/t/nns-governance-bug-in-proposal-136693/48224)).

The solution is to avoid calling the NNS Governance's `settle_neurons_fund_participation_result`
function if the SNS does not specifically request Neurons' Fund participation.

## Security
