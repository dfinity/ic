# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

SNS Root now has a function called `register_extension` that is similar to `register_dapp_canister`,
but different in the following ways:

* The controllers of an SNS extension are the Root and the Governance canisters of the SNS (as
  opposed to just Root). This allows SNS Governance to call functions of the extension that can
  be called only by an extension's controller.
* Extensions are listed separately in the respone of `list_sns_canisters`.

Similar to `register_dapp_canister` and `register_dapp_canisters`, `register_extension` can be
called only by the SNS Governance.

## Changed

## Deprecated

## Removed

## Fixed

## Security
