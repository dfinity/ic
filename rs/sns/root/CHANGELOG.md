# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-02-07: Proposal 135209

http://dashboard.internetcomputer.org/proposal/135209

## Added

* Added the `query_stats` field for `canister_status`/`get_sns_canisters_summary` methods.


# 2025-02-03: Proposal 135066

http://dashboard.internetcomputer.org/proposal/135066

## Changed

- The `LogVisibility` returned from `canister_status` has one more variant `allowed_viewers`,
  consistent with the corresponding management canister API. Calling `canister_status` for a
  canister with such a log visibility setting will no longer panic.


# 2025-01-20: Proposal 134905

http://dashboard.internetcomputer.org/proposal/134905

## Added

Enable upgrading SNS-controlled canisters using chunked WASMs. This is implemented as an extension
of the existing `UpgradeSnsControllerCanister` proposal type with new field `chunked_canister_wasm`.
This field can be used for specifying an upgrade of an SNS-controlled *target* canister using
a potentially large WASM module (over 2 MiB) uploaded to some *store* canister, which:
* must be installed on the same subnet as target.
* must have SNS Root as one of its controllers.
* must have enough cycles for performing the upgrade.

You can now set wasm_memory_threshold via proposal.


END
