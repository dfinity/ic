# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


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
