# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-11-28: Proposal 139575

http://dashboard.internetcomputer.org/proposal/139575

##  Fixed

- Add default case for start_date fetching in Performance Based Rewards. This is done to ensure that a valid start date
  is always returned, even when no previous rewards exist.
  
- Added `algorithm_version` field to node provider rewards.


# 2025-11-07: Proposal 139313

http://dashboard.internetcomputer.org/proposal/139313

## Fixed

* Previously, a lock was released only in the happy case (during minting node
  provider rewards). Now, it is released no matter how the function returns.


# 2025-10-24: Proposal 139086

http://dashboard.internetcomputer.org/proposal/139086

## Added

* New proposal types:

    * `PauseCanisterMigrations` & `UnpauseCanisterMigrations`

    * `SetSubnetOperationalLevel`

        * Mainly, this sets the `is_halted` field in `SubnetRecord`.

        * This also sets a couple other things:
            * `ssh_readonly_access` - Also in `SubnetRecord`.
            * `ssh_node_state_write_access` - In `NodeRecord` (not `SubnetRecord`!).

        * Motivation: This will be used in a slightly enhanced subnet recovery
          procedure. This is needed before we can fully enable SEV.

* A new API function `get_neuron_index` is added. It accepts an exclusive lower bound on the neuron ID and a page size, and returns all neurons whose IDs are greater than the specified lower bound.

# 2025-10-17: Proposal 138991

https://dashboard.internetcomputer.org/proposal/138991

## Added

* `PauseCanisterMigrations` & `UnpauseCanisterMigrations`

## Changed

* Following private neurons is now generally disallowed. There are some exceptions to this though: 
    * A private neuron P can be followed by another neuron N, if either they share a controller or N's controller is listed as P's hotkey.
    * Following private neurons on the topic `NeuronManagement` is not a subject of this limitation. Furthermore, following public neurons is always allowed.

* Following non-existing Neuron IDs is disallowed as well.

# 2025-10-10: Proposal 138913

http://dashboard.internetcomputer.org/proposal/138913

## Added

* Record votes by known neurons before clearing ballots.
* Allow updating known neuron through RegisterKnownNeuron without having to change its name.
* Added `committed_topics` to the `KnownNeuronData` that can be submitted as part of the
  `RegisterKnownNeuron` proposal.
* Add an API to list neuron votes given a specific neuron id. In the short term it only works for
  known neurons as only known neuron votes are recorded.
* Enable 2 features - (1) recording known enuron voting history and (2) proposal type to deregister
  known neurons. See [the forum post](https://forum.dfinity.org/t/better-known-neurons/55747) for
  more details.

## Changed

* Stop exposing known neuron data in list_neurons so that it's less likely to exceed message size
  limit.

* The Dogecoin canister (ID begins with gordg-) is considered a "protocol"
  canister. This affects proposal topics.

## Deprecated

* The `StopOrStartCanister` NNS Function is now obsolete (Use `Action::StopOrStartCanister`
  instead).


# 2025-09-19: Proposal 138583

https://dashboard.internetcomputer.org/proposal/138583

## Added

* Added links to the `KnownNeuronData` that can be submitted as part of the `RegisterKnownNeuron`
  proposal.

# 2025-09-12: Proposal 138475

https://dashboard.internetcomputer.org/proposal/138475

## Added

* Added a new proposal type `DeregisterKnownNeuron` without enabling it (behind feature flag).

* Enable FulfillSubnetRentalRequest proposals. The main effect of such proposals
  is the creation of an EXCLUSIVE subnet, meaning that only ONE principal is
  allowed to create canisters in the subnet. For details, see
  https://forum.dfinity.org/t/subnet-rental-canister-work-on-next-phase-has-started/52803
  (This is also discussed under the heading "Swiss subnet".)

# 2025-09-05: Proposal 138369

http://dashboard.internetcomputer.org/proposal/138369

## Added

* The neuron `Split` command accepts an optional `memo` field that can be used to derive the neuron
  subaccount, rather than generating a random one.

## Changed

* The protobuf-encoded `Storable` implementations are changed to `Unbounded`.

## Removed

* The `IcpXdrConversionRate` proposal is now obsolete and cannot be submitted.


# 2025-07-25: Proposal 137582

http://dashboard.internetcomputer.org/proposal/137582

## Added

* Minor improvement on voting power spike detection mechanism - the mechanism is kept in place even
  when the voting power snapshot is not full.

## Changed

* `AddOrRemoveNodeProvider` and `update_node_provider` now require 32-byte account-identifiers, which are equivalent
  to the 28-byte identifiers except with the checksum. This is a breaking change for the API.
* `NodeProvider.reward_account` always returns the 32-byte account identifier, even if the
  node provider was created with a 28-byte identifier. This is to ensure consistency in the API and to make it easier
  to use the reward account in other contexts, such as looking up the account in the ledger. All clients needed to
  support the 32-byte address already, so this is not a breaking change for the API.


# 2025-07-18: Proposal 137499

http://dashboard.internetcomputer.org/proposal/137499

## Added

* Minor improvements on voting power spike detection mechanism.

# 2025-07-11: Proposal 137346

http://dashboard.internetcomputer.org/proposal/137346

## Added

* Add new unreleased proposal type.

# 2025-07-06: Proposal 137252

http://dashboard.internetcomputer.org/proposal/137252

## Added

* Add a metric for the nubmer of spawning neurons.
* Use a previous voting power snapshot to create ballots if a voting power spike is detected.

## Changed

* Rename a metric related to voting power spike according to convention.

# 2025-06-20: Proposal 137080

http://dashboard.internetcomputer.org/proposal/137080

## Added

* Neurons can now perform SetFollowing to configure their following on multiple
  topics at once. Whereas, before, they would have to perform multiple Follow
  operations, one for each topic. This brings NNS into alignment with SNS.

# 2025-06-13: Proposal 136987

http://dashboard.internetcomputer.org/proposal/136987

## Changed

* Task execution metrics are added for `neuron_data_validation` and
  `unstake_maturity_of_dissolved_neurons` timer tasks.

## Fixed

* The `account_identifier_to_disburse_to` in the maturity disbursement now contains a 32-byte
  address rather than the 28-byte one without checksum.

# 2025-06-06: Proposal 136890

http://dashboard.internetcomputer.org/proposal/136890

## Added

* Support disbursing maturity to an account identifier, in addition to icrc1 account.

# 2025-05-31: Proposal 136795

http://dashboard.internetcomputer.org/proposal/136795

## Added

* Expose a new metric `voting_power_snapshots_latest_snapshot_is_spike`.
* Enabling `DisburseMaturity` neuron management proposals.

## Changed

* `MAX_NEURON_CREATION_SPIKE` is increased from 120 to 300.

# 2025-05-16: Proposal 136693

http://dashboard.internetcomputer.org/proposal/136693

## Added

* The `DisburseMaturity` neuron command is enabled. See https://forum.dfinity.org/t/disburse-maturity-in-nns/43228 for
  more details.

## Changed

* Proposal topics are persisted throughout its lifecycle instead of being recomputed every time.

## Removed

* The `IcpXdrConversionRate` proposal is now obsolete and cannot be submitted.

## Security

Enforce a lower bound for `min_participant_icp_e8s` of `1_000_000`.

# 2025-05-10: Proposal 136580

http://dashboard.internetcomputer.org/proposal/136580

## Removed

* The `governance_heap_neuron_count` metric is removed as there are no neurons in the heap anymore.

# 2025-05-02: Proposal 136427

http://dashboard.internetcomputer.org/proposal/136427

## Changed

* The Governance canister will fetch rewards from the new Node Rewards Canister instead of from Registry.

## Removed

* All the `_pb` methods are removed as they already always panic, as well as decoding the init arg
  as protobuf.

# 2025-04-25: Proposal 136370

http://dashboard.internetcomputer.org/proposal/136370

## Fixed

* Use `StableBTreeMap::init` instead of `::new` for voting power snapshots.

# 2025-04-15: Proposal 136285

http://dashboard.internetcomputer.org/proposal/136285

## Added

* A timer task is added to take daily snapshots of voting power for standard proposals.

## Fixed

* Turned off `DisburseMaturity` that was incorrectly turned on before.

# 2025-04-11: Proposal 136224

http://dashboard.internetcomputer.org/proposal/136224

## Added

* Governance now gets node provider rewards from the Node Reward Canister in test builds.

## Changed

* The `_pb` methods now always panic.

# 2025-04-05: Proposal 136071

http://dashboard.internetcomputer.org/proposal/136071

## Changed

* Disable Neuron's Funds for ongoing SNSs, as approved in
  proposal [135970](https://dashboard.internetcomputer.org/proposal/135970).

## Removed

* The `topic_followee_index` in the heap is removed, along with the flag
  `USE_STABLE_MEMORY_FOLLOWING_INDEX` that was set to true in the proposal 135063.

# 2025-03-28: Proposal 136006

http://dashboard.internetcomputer.org/proposal/136006

## Added

* The `init` method now supports candid decoding in addition to protobuf. Protobuf decoding will be
  removed in the future, giving clients time to migrate.

## Changed

* Increased the probability of failure from 70% to 90% for the deprecated _pb methods.
* Increase the neurons limit to 500K now that neurons are stored in stable memory.

# 2025-03-25: Proposal 135955

https://dashboard.internetcomputer.org/proposal/135955

## Security

* Prevent large manage neuron proposals by making sure their proposal payloads are bounded, and
  lower the maximum number of open manage neuron proposals. More details can be seen here:
  https://forum.dfinity.org/t/nns-updates-2025-03-25-nns-governance-security-hotfix/42978.

# 2025-03-21: Proposal 135933

http://dashboard.internetcomputer.org/proposal/135933

## Changed

* Refactor `prune_following` task to use the `timer_task` library, and therefore enables metrics to
  be collected about its execution.

# 2025-03-17: Proposal 135847

https://dashboard.internetcomputer.org/proposal/135847

## Added

* Added `NetworkEconomics.voting_power_economics.neuron_minimum_dissolve_delay_to_vote_seconds`.

## Removed

* Removed a migration mechanism previously used for data migrations through heartbeat.

# 2025-03-08: Proposal 135702

http://dashboard.internetcomputer.org/proposal/135702

## Added

* Collect metrics about timer tasks defined using ic_nervous_system_timer_task library.
* Re-enable neuron migration to stable memory:
    * Setting `MIGRATE_ACTIVE_NEURONS_TO_STABLE_MEMORY` to true, which will cause active neurons
      to be continously moved from heap memory to stable memory.
    * Compared to the last time it was enabled, several improvements were made:
        * Distribute rewards is moved to timer, and has a mechanism to distribute in batches in
          multiple messages.
        * Unstaking maturity task has a limit of 100 neurons per message, which prevents it from
          exceeding instruction limit.
        * The execution of `ApproveGenesisKyc` proposals have a limit of 1000 neurons, above which
          the proposal will fail.
        * More benchmarks were added.
* Enable timer task metrics for better observability.

## Changed

* Voting Rewards will be scheduled by a timer instead of by heartbeats.
* Unstaking maturity task will be processing up to 100 neurons in a single message, to avoid
  exceeding the instruction limit in a single execution.
* Voting Rewards will be distributed asynchronously in the background after being calculated.
    * This will allow rewards to be compatible with neurons being stored in Stable Memory.
* Ramp up the failure rate of _pb method to 0.7 again.

## Fixed

* Avoid applying `approve_genesis_kyc` to an unbounded number of neurons, but at most 1000 neurons.

# 2025-03-01: Proposal 135613

http://dashboard.internetcomputer.org/proposal/135613

## Added

* Define API for disburse maturity. While disburse maturity is not yet enabled, clients may already
  start preparing for this new NNS neuron operation.

## Deprecated

* NnsCanisterUpgrade/NnsRootUpgrade NNS funtions are made obsolete.

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

The `list_neurons` API now supports querying by neuron subaccount. This is useful for neuron holders who
have many neurons and want to list only the neurons associated with a particular subaccount.

A new field `neuron_subaccounts` is added to the request, which is a list of subaccounts to query
for. If this field is present, any neurons found will be added to the response. If duplicate
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

The request now supports `page_size` and `page_number`. If `page_size` is greater than
`MAX_LIST_NEURONS_RESULTS` (currently 500), the API will treat it as `MAX_LIST_NEURONS_RESULTS`, and
continue procesisng the request. If `page_number` is None, the API will treat it as Some(0)

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
