# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-02-21: Proposal 135437

http://dashboard.internetcomputer.org/proposal/135437

## Changed

NNS Root is no longer the controller of a newly deployed SNS's Swap canister. For more details,
please refer to [this forum thread](https://forum.dfinity.org/t/making-swap-a-proper-sns-canister/36519?u=aterga).


# 2025-02-14: Proposal 135314

http://dashboard.internetcomputer.org/proposal/135314

## Removed

* Logos are no longer included into *serialized* initial SNS initialization parameters for newly
  deployed SNSs. They are, of course, still included in the metadata responses: 
  `SnsGov.get_metadata` and `SnsLedger.icrc1_metadata`.


END
