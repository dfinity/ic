# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* A ManageNeuron proposal can now have the `MakeProposal` command again, but
  only to make another ManageNeuron proposal, whose command is not
  `MakeProposal`.

* The action of a ManageNeuron proposal can be at most 10,000 bytes (protobuf
  encoded). With the `MakeProposal` command, this limits the size of the
  nested proposal.

* If neuron C follows neuron B on the NeuronManagement topic, and B follows
  neuron A, then the controller and hotkeys of A can now read the full neuron C
  (via `get_full_neuron` and `list_neurons`), and see ManageNeuron proposals for
  C in `list_proposals`.

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
