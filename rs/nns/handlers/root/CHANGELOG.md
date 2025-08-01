# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-08-01: Proposal 137685

http://dashboard.internetcomputer.org/proposal/137685

## Added

NNS Root now returns the field `memory_metrics` from the `canister_status` API.


# 2025-07-06: Proposal 137253

http://dashboard.internetcomputer.org/proposal/137253

## Changed

* Root now gets the NNS subnet via `get_subnet_for_canister` instead of getting the routing table bytes from the
  registry. This change is needed, as the routing table records will be sharded into multiple records moving forward.


# 2025-06-06: Proposal 136891

http://dashboard.internetcomputer.org/proposal/136891

* This ensures that this canister will be ready for chunked registry records/mutations.


# 2025-05-16: Proposal 136694

http://dashboard.internetcomputer.org/proposal/136694

## Removed
- The fields `compute_allocation` and `memory_allocation` in the input type `ChangeCanisterRequest`
  of the endpoint `change_nns_canister`.


# 2025-05-02: Proposal 136429

No behavior change.

Code for new behavior is inactive (behind a flag).

# 2025-02-14: Proposal 135313

http://dashboard.internetcomputer.org/proposal/135313

## Added

* Added the `query_stats` field for the `canister_status` method.

# 2025-02-03: Proposal 135064

https://dashboard.internetcomputer.org/proposal/135064

## Changed

* The `LogVisibility` returned from `canister_status` has one more variant `allowed_viewers`,
  consistent with the corresponding management canister API. Calling `canister_status` for a
  canister with such a log visibility setting will no longer panic.

END
