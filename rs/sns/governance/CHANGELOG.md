# Changelog

Proposals before 2025 are NOT listed in here, because this process was
introduced later. (We could back fill those later though.)

The process that populates this file is described in
`rs/nervous_system/changelog_process.md`. In general though, the entries you see
here were moved from the adjacent `unreleased_changelog.md` file.


INSERT NEW RELEASES HERE


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

* https://nns.ic0.app/proposal/?proposal=134906

    Enable upgrading SNS-controlled canisters using chunked WASMs. This is implemented as an extension
of the existing `UpgradeSnsControllerCanister` proposal type with new field `chunked_canister_wasm`.
This field can be used for specifying an upgrade of an SNS-controlled *target* canister using
a potentially large WASM module (over 2 MiB) uploaded to some *store* canister, which:
    * must be installed on the same subnet as target.
    * must have SNS Root as one of its controllers.
    * must have enough cycles for performing the upgrade.


# 2025-01-20: Proposal 134906

http://dashboard.internetcomputer.org/proposals/134906

## Added

Enable upgrading SNS-controlled canisters using chunked WASMs. This is implemented as an extension
of the existing `UpgradeSnsControllerCanister` proposal type with new field `chunked_canister_wasm`.
This field can be used for specifying an upgrade of an SNS-controlled *target* canister using
a potentially large WASM module (over 2 MiB) uploaded to some *store* canister, which:
* must be installed on the same subnet as target.
* must have SNS Root as one of its controllers.
* must have enough cycles for performing the upgrade.


END
