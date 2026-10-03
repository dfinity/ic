# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

- Expose each neuron's exact voting reward shares for its latest participating reward event through
  `get_neuron` and `list_neurons`.

## Changed

## Deprecated

## Removed

## Fixed

- Heap memory optimizations: proposal ballots now release their underlying
  capacity after reward distribution, and `check_heap_can_grow` is enforced
  more broadly across `manage_neuron` commands (except `MakeProposal` /
  `RegisterVote`, which must remain available to recover from low-resource
  situations), `claim_swap_neurons`, and non-emergency proposal validation.

## Security
