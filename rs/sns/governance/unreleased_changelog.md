# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

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

## Deprecated

## Removed

## Fixed

* `ManageNervousSystemParameters` proposals now enforce that at least one field is set.

* Errors caused by trying to submit proposals restricted in pre-initialization mode should no
  longer overflow.

## Security
