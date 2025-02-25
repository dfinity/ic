# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-02-21: Proposal 135436

http://dashboard.internetcomputer.org/proposal/135436

## Changed

* ManageNetworkEconomics proposals can now modify deep fields one at a time.
  Previously, this was only possible for top level fields.

* Added validation for ManageNetworkEconomics proposals. Previously, there was
  none. The result must have all the following properties:

  * All "optional" fields are actually set.

  * `maximum_icp_xdr_rate >= minimum_icp_xdr_rate`

  * Decimal fields have parsable `human_readable` values.

  * `one_third_participation_milestone_xdr < full_participation_milestone_xdr`


# 2025-02-11: Proposal 135265

https://dashboard.internetcomputer.org/proposal/135265

## Removed

* Neuron migration (`migrate_active_neurons_to_stable_memory`) is rolled back due to issues with
  reward distribution. It has already been rolled back with a hotfix ([proposal
  135265](https://dashboard.internetcomputer.org/proposal/135265))


# 2025-02-07: Proposal 135206

http://dashboard.internetcomputer.org/proposal/135206

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

# 2025-02-03: Proposal 135063

http://dashboard.internetcomputer.org/proposal/135063

## Added

### Migrating Active Neurons to Stable Memory

In this relesae, we turn on 2 features related to migrating active neurons to stable memory:

1. `allow_active_neurons_in_stable_memory`: this allows the canister to look for active neurons in
   stable memory, while previously the canister always assumes active neurons are always in the heap.

2. `use_stable_memory_following_index`: this lets the canister use the neuron following index in the
   stable memory, instead of the one in the heap.

No neurons are actually migrated yet.

## Changed

* The `list_neurons` behavior is slightly changed: the `include_empty_neurons_readable_by_caller`
  was default to true before, and now it's default to true. More details can be found at:
  https://forum.dfinity.org/t/listneurons-api-change-empty-neurons/40311


# 2021-01-27: Proposal 134988

https://dashboard.internetcomputer.org/proposal/134988

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

## Changed

* `InstallCode` proposal payload hashes are now computed when making the proposal instead of when
  listing proposal. Hashes for existing proposals are backfilled.

# 2025-01-13: Proposal 134777

http://dashboard.internetcomputer.org/proposal/134777

### Periodic Confirmation

Enabled voting power adjustment and follow pruning.

#### Prior Work

This section describes related changes in previous releases.

We already started recording how long it's been since neurons have confirmed
their following (aka refreshed voting power). Neurons were also given the
ability to confirm their following. Those who have never confirmed are
considered as having refreshed on Sep 1, 2024.

This feature was proposed and approved in motion [proposal 132411].

[proposal 132411]: https://dashboard.internetcomputer.org/proposal/132411

#### New Behavior(s) (In This Release)

With this enablement, not refreshing for more than 6 months will start to affect
the neuron. More precisely,

1. If a neuron has not refreshed in 6 months, then votes have less influence on
   the outcome of proposals.

2. If a neuron has not refreshed in 7 months,

    a. It stops following other neurons (except on the NeuronManagement topic;
       those followees are retained).

    b. Its influence on proposals goes to 0.


END