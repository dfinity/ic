# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

### List Neurons Paging

Two new fields are added to the request, and one to the response.

The request now supports `page_size` and `page_number`.  If `page_size` is greater than 
`MAX_LIST_NEURONS_RESULTS` (currently 500), the API will treat it as `MAX_LIST_NEURONS_RESULTS`, and
continue procesisng the request.  If `page_number` is None, the API will treat it as Some(0)

In the response, a field `total_pages_available` is available to tell the user how many
additional requests need to be made.

This will only affect neuron holders with more than 500 neurons, which is a small minority.

This allows neuron holders with many neurons to list all of their neurons, whereas before, 
responses could be too large to be sent by the protocol.

### Migrating Active Neurons to Stable Memory

In this relesae, we turn on 2 features related to migrating active neurons to stable memory:

1. `allow_active_neurons_in_stable_memory`: this allows the canister to look for active neurons in
   stable memory, while previously the canister always assumes active neurons are always in the heap.

2. `use_stable_memory_following_index`: this lets the canister use the neuron following index in the
   stable memory, instead of the one in the heap.

No neurons are actually migrated yet.

## Changed

* `InstallCode` proposal payload hashes are now computed when making the proposal instead of when
  listing proposal. Hashes for existing proposals are backfilled.

* The `list_neurons` behavior is slightly changed: the `include_empty_neurons_readable_by_caller`
  was default to true before, and now it's default to true. More details can be found at:
  https://forum.dfinity.org/t/listneurons-api-change-empty-neurons/40311

## Deprecated

## Removed

## Fixed

## Security
