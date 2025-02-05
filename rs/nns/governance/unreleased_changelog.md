# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### List Neurons API Change: Query by Subaccount

The `list_neurons` API now supports querying by neuron subaccount.  This is useful for neuron holders who
have many neurons and want to list only the neurons associated with a particular subaccount.

A new field `neuron_subaccounts` is added to the request, which is a list of subaccounts to query
for.  If this field is present, any neurons found will be added to the response.  If duplicate
neurons are found between this field and others, they will be deduplicated before returning the value.

This new field works in the same way that the existing `neuron_ids` field works.

## Changed

* `InstallCode` proposal payload hashes are now computed when making the proposal instead of when
  listing proposal. Hashes for existing proposals are backfilled.

* The `list_neurons` behavior is slightly changed: the `include_empty_neurons_readable_by_caller`
  was default to true before, and now it's default to true. More details can be found at:
  https://forum.dfinity.org/t/listneurons-api-change-empty-neurons/40311

* The limit of the number of neurons is increased from 380K to 400K.

## Deprecated

## Removed

## Fixed

## Security
