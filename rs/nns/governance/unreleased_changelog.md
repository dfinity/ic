# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* If neuron C follows neuron B on the NeuronManagement topic, and B follows
  neuron A, then the controller and hotkeys of A can now read the full neuron C
  (via `get_full_neuron` and `list_neurons`), and see ManageNeuron proposals for
  C in `list_proposals`.

## Changed

## Deprecated

## Removed

## Fixed

## Security
