# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added
* Introduces two new proposals called `PauseCanisterMigrations` and `UnpauseCanisterMigrations`.

## Changed
* Following private neurons has changed. A private neuron P can be followed by another neuron N, if either they share a controller or N's controller is listed as P's hotkey.
Following private neurons on the topic `NeuronManagement` is not a subject of this limitation. Furthermore, following public neurons is always allowed.

## Deprecated

## Removed

## Fixed

## Security
