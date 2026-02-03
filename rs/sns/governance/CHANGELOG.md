# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


# 2025-11-28: Proposal 139578

http://dashboard.internetcomputer.org/proposal/139578

## Changed

* Clean up if RegisterExtension fails.


# 2025-11-07: Proposal 139316

https://dashboard.internetcomputer.org/proposal/139316

Just a "maintenance" release, i.e. no behavior changes, just making sure that we
do not become too behind, and avoid too many changes piling up in for the next
"real" upgrade.


# 2025-09-19: Proposal 138584

https://dashboard.internetcomputer.org/proposal/138584

## Added

* The feature flag `SNS_EXTENSIONS_ENABLED` is turned on. Enabling it allows for deployment of SNS extensions.

# 2025-09-05: Proposal 138373

http://dashboard.internetcomputer.org/proposal/138373

## Added

* Added extension_operations to list_topics, which exposes the operations of each registered extension underneath the
  topic which allows voters to correctly understand the impact of following on particular topics. Extensions are
  canisters that add additional functionality to an SNS through a privileged integration.


# 2025-08-11: Proposal 137819

http://dashboard.internetcomputer.org/proposal/137819

## Fixed

* Fixed a bug with the topic follower index.


# 2025-08-01: Proposal 137687

http://dashboard.internetcomputer.org/proposal/137687

## Fixed

Fixed multiple issues in `disburse_neuron` functionality:

- Fixed a bug that could allow an SNS Neuron to burn fees that would have been refunded after proposal acceptance.
- Fees are now only recorded as burned when they exceed the transaction fee threshold and are actually burned.
- Added comprehensive tests to ensure the correct behavior in the future.


# 2025-07-25: Proposal 137584

http://dashboard.internetcomputer.org/proposal/137584

## Added

RegisterExtension proposals can now be used in the test version of SNS Governance; submitting
these proposals on mainnet is still disabled until further notice.


## Fixed

Fixed a bug due to which governance cached metrics could be recomputed once every 10 seconds
rather than with the intended rate of once per hour.


# 2025-07-08: Proposal 137282

http://dashboard.internetcomputer.org/proposal/137282

## Added

* Added `SnsGovernance.get_metrics_replicated`, enabling other canisters to fetch SNS metrics.
  `SnsGovernance.get_metrics` is a replicated query and thus cannot be called by canisters.

* Extended SNS metrics with treasury metrics.

* Extended SNS metrics with voting power metrics.

* Extended SNS metrics with the genesis timestamp.


# 2025-06-27: Proposal 137172

http://dashboard.internetcomputer.org/proposal/137172

## Added

The `get_metrics` function response now includes the number of *executed* proposal (in addition
to the number of submitted proposals).

## Fixed

Fixed a bug in the decoder of Candid `Nat` values as `u64`.


# 2025-06-20: Proposal 137082

http://dashboard.internetcomputer.org/proposal/137082

## Added

### New `RegisterExtension` proposal type

A new proposal type, `RegisterExtension`, is added for registering SNS extensions.
Extensions are a new class of SNS canisters that (unlike SNS-controlled dapp canisters)
can operate on behalf of the DAO, e.g., by managing a portion of the treasury funds.

Note that while `RegisterExtension` proposals are already recognized, they are not enabled yet.


# 2025-06-13: Proposal 136989

http://dashboard.internetcomputer.org/proposal/136989

## Added

### New `get_metrics` function for SNS Governance

A new function, `get_metrics`, has been added to the SNS Governance canister. This allows front-end clients and SNS aggregators to query for activity metrics of an SNS over a specified time period. Currently, the metrics include the number of most-recent proposals and the timestamp of the latest SNS ledger transaction.


# 2025-06-06: Proposal 136896

http://dashboard.internetcomputer.org/proposal/136896

## Added

### Set the principal of the index canister when installing the ledger ([ICRC-106](https://github.com/dfinity/ICRC-1/pull/196/files/7f9b4739d9b3ec2cf549bf468e3a1731c31eecbf))

When installing the ledger canister for a new SNS, the index canister's principal is now set in the ledger.
This allows a ledger client to query the ledger using the `icrc106_get_index_principal` endpoint to figure out where the
ledger index canister is running.


# 2025-05-10: Proposal 136582

http://dashboard.internetcomputer.org/proposal/136582

## Changed

SNS neuron baskets created for swap participants are now set up using topic-based following.
Within each basket, there is still a root neuron with the largest dissolve delay (which does not
follow anyone), and all other neurons in the same basket will now follow the root on all topics,
including the critical ones (beforehand only non-critical following was set up within each basket).
Read more details in the [forum thread](https://forum.dfinity.org/t/topic-based-following-for-swap-neuron-baskets/43649).


# 2025-05-06: Proposal 136455

http://dashboard.internetcomputer.org/proposal/136455

## Changed

The DAO community settings topic is promoted to being critical. For context, please refer to
the [forum thread](https://forum.dfinity.org/t/make-sns-topic-dao-community-settings-critical/46689).


# 2025-04-25: Proposal 136373

http://dashboard.internetcomputer.org/proposal/136373

## Deprecated

* Custom proposals that were not yet assigned to a topic are no longer allowed to be submitted.


# 2025-04-11: Proposal 136227

http://dashboard.internetcomputer.org/proposal/136227

## Added

### Topic-based following

The new `SetFollowing` neuron command allows following voting decisions based on proposal topics.

This command can be used to set or change following for any number of topics at once. Users
are encouraged to set following based on topics, although _legacy following_ (based on
individual proposal types) will still work until further notice. However, this command may clear
some legacy following if it becomes redundant, specifically, in the following cases:

1. Following on proposal types within the topics explicitly mentioned by `SetFollowing`.
2. Legacy catch-all following, if a neuron has topic-based following for all non-critical
    topics, or if the `SetFollowing` command mentions each non-critical topic.

For example:

```bash
dfx canister --ic call SNS_GOVERNANCE manage_neuron '(record {
  subaccount = FOLLOWER_NEURON_ID_BLOB;
  command = opt variant {
    SetFollowing = record {
      topic_following = vec {
        record {
          topic = opt variant { ApplicationBusinessLogic };
          followees = vec {
            record {
              alias = opt "Giuseppe Arcimboldo";
              neuron_id = opt record { id = FOLLOWEE_NEURON_ID_BLOB };
            };
          };
        };
        record {
          topic = opt variant { CriticalDappOperations };
          followees = vec {};
  }}}}})'
```

In this example, following on the `ApplicationBusinessLogic` topic is changed (from whatever has
been there before) to a single neuron, and following on `CriticalDappOperations` is being
removed.

Followee _aliases_ are option; they are currently used only when listing neurons being followed
(a.k.a. followees), which helps remember why a particular one has been added in the first place.

**Backward compatibility.**
Legacy following still works for proposal types and for neurons that do not have any topic-based
following for covering that proposal type. For example, after executing the following command,
the modified neuron would still follow on, e.g., `DeregisterDappCanisters` proposals, assuming
it had followed some neuron on this proposal type.

Topic-based following takes precedence over legacy following, e.g., regardless of which
legacy following has been set up for the neuron modified in the above example, that neuron will
now only follow Giuseppe Arcimboldo on proposals within the `ApplicationBusinessLogic` topic.

Legacy _catch-all_ following is also still supported for neurons that follow on the respective
special proposal type `0`, but only for neurons that do not already follow on the specific topic
in question (nor follow on the specific proposal type being voted on). In other words, catch-all
has the lowest precedence, and topic-based following now has the highest.

### Filtering proposals by topic

`SnsGov.list_proposals` now supports filtering by proposal topic. For example, the following
command can be used to list proposals that are either under the `Governance` topic or do not specify
a topic:

```sh
dfx canister SNS_GOVERNANCE call list_proposals '(
  record {
    include_reward_status = vec {};
    limit = 0 : nat32;
    exclude_type = vec {};
    include_status = vec {};
    include_topic = opt vec {
      record { topic = null };
      record { topic = opt variant { Governance } };
    };
  },
)'
```

If `include_topic` is not mentioned or `null`, then proposals are listed regardless of their topic.


# 2025-03-21: Proposal 135935

http://dashboard.internetcomputer.org/proposal/135935

## Added

* Added `Neuron.topic_followees` to support the upcoming [SNS topics](https://forum.dfinity.org/t/sns-topics-design) feature.

## Changed

- `SetTopcisForCustomProposals` proposal is now under the `CriticalDappOperations` topic.

# 2025-03-17: Proposal 135852

https://dashboard.internetcomputer.org/proposal/135852

## Changed

* Proposal criticality is now defined based on topics. This makes the following two native proposal
  types critical:
    * `AddGenericNervousSystemFunction`
    * `RemoveGenericNervousSystemFunction`

    For more details, please refer to
    [PSA(SNS): Proposal criticality to be defined based on proposal topics](https://forum.dfinity.org/t/psa-sns-proposal-criticality-to-be-defined-based-on-proposal-topics/41685).


# 2025-03-08: Proposal 135703

http://dashboard.internetcomputer.org/proposal/135703

## Added

* Added `ProposalData.topic : opt Topic`.

## Fixed

* `AddGenericNervousSystemFunction` can be used to add custom proposals under _critical_ topics.


# 2025-03-01: Proposal 135615

http://dashboard.internetcomputer.org/proposal/135615

## Added

* New type of SNS proposals `SetTopicsForCustomProposals` can be used to batch-set topics for all custom proposals (or any non-empty subset thereof) at once.

    Example usage:

    ```bash
    dfx canister --ic call ${SNS_GOVERNANCE_CANISTER_ID} manage_neuron '(
        record {
            subaccount = blob "'${PROPOSER_SNS_NEURON_SUBACCOUNT}'";
            command = opt variant {
                MakeProposal = record {
                    url = "https://forum.dfinity.org/t/sns-topics-plan";
                    title = "Set topics for custom SNS proposals";
                    action = opt variant {
                        SetTopicsForCustomProposals = record {
                            custom_function_id_to_topic = vec {
                                record {
                                    42; variant { ApplicationBusinessLogic }
                                }
                                record {
                                    123; variant { DaoCommunitySettings }
                                }
                            };
                        }
                    };
                    summary = "Set topics ApplicationBusinessLogic and \
                            DaoCommunitySettings for SNS proposals with \
                            IDs 42 and 123 resp.";
                }
            };
        },
    )'
    ```

## Changed

* Enable
[automatic target version advancement](https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement/39874)
for newly deployed SNSs. To opt out, please submit a `ManageNervousSystemParameters` proposal, e.g.:

    ```bash
    dfx canister --ic call ${SNS_GOVERNANCE_CANISTER_ID} manage_neuron '(
        record {
            subaccount = blob "'${PROPOSER_SNS_NEURON_SUBACCOUNT}'";
            command = opt variant {
                MakeProposal = record {
                    url = "https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement";
                    title = "Opt out from automatic advancement of SNS target versions";
                    action = opt variant {
                        ManageNervousSystemParameters = record {
                            automatically_advance_target_version = opt false;
                        }
                    };
                    summary = "Disable automatically advancing the target version \
                            of this SNS to have full control over the delivery of SNS framework \
                            upgrades blessed by the NNS.";
                }
            };
        },
    )'
    ```

## Fixed

* `ManageNervousSystemParameters` proposals now enforce that at least one field is set.

* Errors caused by trying to submit proposals restricted in pre-initialization mode should no
  longer overflow.


# 2025-02-15: Proposal 135315

http://dashboard.internetcomputer.org/proposal/135315

## Added

The concept of topics has now been introduced to the SNS. This means that when custom function is added via an `AddGenericNervousSystemFunction` proposal, a topic can be specified for that custom function. This can be used for organizing the following page, and could be used for more in the future.

A `list_topics` API has been added, which returns a list of topics and all the functions categorized in those topics. 

## Changed

The new `topic` field is required when submitting an `AddGenericNervousSystemFunction` proposal.


# 2025-02-07: Proposal 135208

http://dashboard.internetcomputer.org/proposal/135208

## Added

* Added the `query_stats` field for `get_root_canister_status` methods.
* Fix a bug due to which SNS ledger logos were sometimes unset after changing unrelated
  SNS ledger metadata fields.


# 2025-02-03: Proposal 135067

http://dashboard.internetcomputer.org/proposal/135067

# 2025-01-27: Proposal 134989

https://dashboard.internetcomputer.org/proposal/134989

## Added

* Enable SNSs to opt in for
[automatically advancing its target version](https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement/39874)
to the newest version blessed by the NNS. To do so, please submit a `ManageNervousSystemParameters` 
proposal, e.g.:

    ```bash
    dfx canister --ic call ${SNS_GOVERNANCE_CANISTER_ID} manage_neuron '(
        record {
            subaccount = blob "'${PROPOSER_SNS_NEURON_SUBACCOUNT}'";
            command = opt variant {
                MakeProposal = record {
                    url = "https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement";
                    title = "Opt for automatic advancement of SNS target versions";
                    action = opt variant {
                        ManageNervousSystemParameters = record {
                            automatically_advance_target_version = opt true;
                        }
                    };
                    summary = "Enable automatically advancing the target version \
                            of this SNS to speed up the delivery of SNS framework \
                            upgrades that were already blessed by the NNS.";
                }
            };
        },
    )'
    ```

* Do not redact chunked Wasm data in `ProposalInfo` served from `SnsGov.list_proposals`.

* https://nns.ic0.app/proposal/?proposal=134906

    Enable upgrading SNS-controlled canisters using chunked WASMs. This is implemented as an extension
of the existing `UpgradeSnsControllerCanister` proposal type with new field `chunked_canister_wasm`.
This field can be used for specifying an upgrade of an SNS-controlled *target* canister using
a potentially large WASM module (over 2 MiB) uploaded to some *store* canister, which:
    * must be installed on the same subnet as target.
    * must have SNS Root as one of its controllers.
    * must have enough cycles for performing the upgrade.


# 2025-01-20: Proposal 134906

http://dashboard.internetcomputer.org/proposal/134906

## Added

Enable upgrading SNS-controlled canisters using chunked WASMs. This is implemented as an extension
of the existing `UpgradeSnsControllerCanister` proposal type with new field `chunked_canister_wasm`.
This field can be used for specifying an upgrade of an SNS-controlled *target* canister using
a potentially large WASM module (over 2 MiB) uploaded to some *store* canister, which:
* must be installed on the same subnet as target.
* must have SNS Root as one of its controllers.
* must have enough cycles for performing the upgrade.


END
