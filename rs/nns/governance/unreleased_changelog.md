# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* A ManageNeuron proposal can now have the `MakeProposal` command again. The
  proposal it makes cannot itself be a ManageNeuron proposal with the
  `MakeProposal` command.

* The action of a ManageNeuron proposal can be at most 10,000 bytes (protobuf
  encoded). With the `MakeProposal` command, this limits the size of the
  nested proposal.

## Changed

* Limit decoded `payload` of `ExecuteNnsFunction` proposals. If the result is
  too large, the `self_describing_action.value` field is left blank. This never
  stops proposal creation.

* In `self_describing_action`, the `type_name` and `type_description` subfields
  are now ALWAYS populated, even when there is a failure while trying to
  populate the `value` field (e.g. due to not being able to fetch the callee's
  Candid interface). Previously, the whole `self_describing_action` field was
  left empty.

## Deprecated

## Removed

## Fixed

## Security
