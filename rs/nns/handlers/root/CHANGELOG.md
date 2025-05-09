# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


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
