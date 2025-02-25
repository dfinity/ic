# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

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

`ManageNervousSystemParameters` proposals now enforce that at least one field is set.

## Security
