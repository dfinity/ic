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

* Proposals that execute a generic (non-native) nervous system function now
  store the raw reply bytes from the target canister on the proposal
  (`ProposalData.execution_reply`), instead of silently discarding them, so
  the outcome of the call can be inspected after the fact.

## Security
