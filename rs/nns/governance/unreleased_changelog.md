# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added


* Enabled BlessAlternativeGuestOsVersion, which would generally be used to
  recover a subnet where a) orchestrator is not working for whatever reason, and
  b) SEV is enabled and/or there is no DFINITY node in the subnet.

* Proposal types for taking and loading a snapshot of a canister controlled by the NNS Root canister.

* Enabled self-describing proposals:

- A `self_describing_action` field is added to `Proposal` when it's created, to describe the
  proposal in a generic way, which can be parsed by a client without having to constantly adapt to
  the new proposal types.
- APIs like `get_proposal_info`, `list_proposals` and `get_pending_proposals` returns this new field
  (`list_proposals` and `get_pending_proposals` require passing an additional boolean flag in order
  to get this new behavior).
- This field is backfilled for existing proposals.

## Changed

- Change the minimum requirement for maturity disbursement from ~1.06 to 1 (ICP equivalent).

## Deprecated

## Removed

## Fixed

## Security
