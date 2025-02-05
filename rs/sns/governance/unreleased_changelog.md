# How This File Is Used

In general, upcoming/unreleased behavior changes are described here. For details
on the process that this file is part of, see
`rs/nervous_system/changelog_process.md`.


# Next Upgrade Proposal

## Added

* Enable SNSs to opt in for
[automatically advancing its target version](https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement/39874)
to the newest version blessed by the NNS. To do so, please submit a `ManageNervousSystemParameters` 
proposal, e.g.:

    ```bash
    dfx canister --network ic call $SNS_GOVERNANCE_CANISTER_ID manage_neuron '(
    record {
        subaccount = blob "'${PROPOSER_SNS_NEURON_SUBACCOUNT}'";
        command = opt variant {
        MakeProposal = record {
            url = "https://forum.dfinity.org/t/proposal-opt-in-mechanism-for-automatic-sns-target-version-advancement/39874";
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
* Added the `query_stats` field for `canister_status`/`get_sns_canisters_summary` methods.
* Fix a bug due to which SNS ledger logos were sometimes unset after changing unrelated
  SNS ledger metadata fields.

## Changed

## Deprecated

## Removed

## Fixed

## Security
