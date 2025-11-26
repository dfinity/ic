# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-10-31: Proposal 139211

http://dashboard.internetcomputer.org/proposal/139211

## Added

* Added support for more Mangement canister features:
    * Added `allowed_viewers` to `log_visibility` (used by `CanisterSettings`).
    * Added `log_memory_limit` to `CanisterSettings`.


# 2025-10-24: Proposal 139088

Just a "maintenance" release, i.e. no behavior changes, just making
sure that we do not become too behind, and avoid too many changes
piling up in for the next "real" upgrade.


# 2025-10-17: Proposal 138993

https://dashboard.internetcomputer.org/proposal/138993

## Added

- Added `environment_variables` to canister settings for `create_canister` and `notify_create_canister`


# 2025-09-05: Proposal 138372

http://dashboard.internetcomputer.org/proposal/138372

## Removed

- Removed `transaction_notification` and `transaction_notification_pb` endpoints as they
  no longer be called. The ICP ledger removed the notify flow, and these methods were not
  callable by callers other than the ICP ledger.


# 2025-08-15: Proposal 137918

http://dashboard.internetcomputer.org/proposal/137918

## Changed

The CMC's `set_authorized_subnetwork_list` method is now also callable by the Subnet Rental Canister, in addition to the NNS Governance Canister.


# 2025-07-25: Proposal 137583

http://dashboard.internetcomputer.org/proposal/137583

## Changed

* Cycles Minting Limit is not enforced for the Subnet Rental Canister when it is topping up itself.
  This is necessary for the canister to mint large amounts of cycles to pay for the subnet rentals.


# 2025-05-31: Proposal 136797

http://dashboard.internetcomputer.org/proposal/136797

## Changed

- Use the mint_cycles128 system API, so larger amounts of cycles can now be minted.


# 2025-02-07: Proposal 135205

http://dashboard.internetcomputer.org/proposal/135205

## Added

* Automatically refund when the memo in an incoming ICP transfer is not one of
  the special values that indicate the purpose of the transfer (e.g. to create a
  new canister). This was originally proposed without objection in [the forum].

[the forum]: https://forum.dfinity.org/t/extend-cycles-minting-canister-functionality/37749/2


END
