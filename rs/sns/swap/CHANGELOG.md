# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-09-05: Proposal 138374

http://dashboard.internetcomputer.org/proposal/138374

## Changed

* Expose a metric for whether auto finalization has failed.


# 2025-08-01: Proposal 137686

http://dashboard.internetcomputer.org/proposal/137686

## Added

Swap `get_canister_status` method now returns the `memory_metrics` field.


# 2025-07-11: Proposal 137349

http://dashboard.internetcomputer.org/proposal/137349

## Fixed

Fix an issue occurring when the NNS Governance cannot find proposals corresponding the creation
of the SNS that requests Neurons' Fund participation during finalization. Note that currently,
SNSs that do not even request Neurons' Fund participation are potentially risking that their
finalization halts if the NNS proposal that created that SNS cannot be found (this recently
happened due to an
[unrelated problem in the NNS](https://forum.dfinity.org/t/nns-governance-bug-in-proposal-136693/48224)).

The solution is to avoid calling the NNS Governance's `settle_neurons_fund_participation_result`
function if the SNS does not specifically request Neurons' Fund participation.


# 2025-03-21: Proposal 135936

https://dashboard.internetcomputer.org/proposal/135936

No behavior changes. This is just a maintenance upgrade.


# 2025-02-15: Proposal 135316

http://dashboard.internetcomputer.org/proposal/135316

## Added

* Added the `query_stats` field for the `get_canister_status` method.


# 2025-01-20: Proposal 134907

http://dashboard.internetcomputer.org/proposal/134907

No behavior changes. This was just a maintenance release.


END
