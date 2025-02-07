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

### Migrating Active Neurons to Stable Memory

In this release, we turn on the feature to migrate active neurons to stable memory:
`migrate_active_neurons_to_stable_memory`. After the feature is turned on, a timer task will
gradually move active neurons from the heap to stable memory. Clients should not expect any
functional behavior changes, since no APIs rely on where the neurons are stored.

## Changed

* The limit of the number of neurons is increased from 380K to 400K.

## Deprecated

## Removed

## Fixed

## Security
