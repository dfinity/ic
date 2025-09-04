# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-08-15: Proposal 137920

http://dashboard.internetcomputer.org/proposal/137920

## Fixed

- A lock was added to `change_canister` to prevent two simultaneous upgrade operations from being executed  
  at the same time. The second upgrade will now fail immediately instead of attempting to run, which prevents
  dangerous edge cases where the canister is restarted by one operation while being upgraded by another.


# 2025-08-01: Proposal 137688

http://dashboard.internetcomputer.org/proposal/137688

## Added

SNS Root now returns the field `memory_metrics` from the `canister_status` API.


# 2025-07-18: Proposal 137501

http://dashboard.internetcomputer.org/proposal/137501

## Added

SNS Root now has a function called `register_extension` that is similar to `register_dapp_canister`,
but different in the following ways:

* The controllers of an SNS extension are the Root and the Governance canisters of the SNS (as
  opposed to just Root). This allows SNS Governance to call functions of the extension that can
  be called only by an extension's controller.
* Extensions are listed separately in the respone of `list_sns_canisters`.

Similar to `register_dapp_canister` and `register_dapp_canisters`, `register_extension` can be
called only by the SNS Governance.


# 2025-05-16: Proposal 136895

http://dashboard.internetcomputer.org/proposal/136895

* This ensures that this canister will be ready for chunked registry records/mutations.


# 2025-05-16: Proposal 136697

http://dashboard.internetcomputer.org/proposal/136697

## Removed
- The fields `compute_allocation` and `memory_allocation` in the input type `ChangeCanisterRequest`
  of the endpoint `change_canister`.


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
