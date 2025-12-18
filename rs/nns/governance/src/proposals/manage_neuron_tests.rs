use super::*;

use crate::{
    pb::v1::{
        Account, Vote,
        manage_neuron::{claim_or_refresh, configure::Operation, disburse::Amount, set_following},
    },
    proposals::self_describing::LocallyDescribableProposalAction,
};

use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance_api::SelfDescribingValue::{self, Array, Blob, Map, Nat, Text};
use icp_ledger::protobuf::AccountIdentifier;
use maplit::hashmap;

#[track_caller]
fn assert_manage_neuron_self_describing_value_is(
    manage_neuron: ManageNeuron,
    expected: SelfDescribingValue,
) {
    let value = manage_neuron.to_self_describing_value();
    let value = SelfDescribingValue::from(value);
    assert_eq!(value, expected);
}

#[track_caller]
fn assert_command_self_describing_value_is(command: Command, expected: SelfDescribingValue) {
    let value = crate::pb::v1::SelfDescribingValue::from(command);
    let value = SelfDescribingValue::from(value);
    assert_eq!(value, expected);
}

#[test]
fn test_manage_neuron_to_self_describing_with_neuron_id() {
    assert_manage_neuron_self_describing_value_is(
        ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 123 })),
            command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
        },
        Map(hashmap! {
            "neuron_id".to_string() => Nat(candid::Nat::from(123_u64)),
            "command".to_string() => Map(hashmap! {
                "RefreshVotingPower".to_string() => Array(vec![]),
            }),
        }),
    );
}

#[test]
fn test_manage_neuron_to_self_describing_with_subaccount() {
    let subaccount = vec![1_u8; 32];
    assert_manage_neuron_self_describing_value_is(
        ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(subaccount.clone())),
            command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
        },
        Map(hashmap! {
            "subaccount".to_string() => Blob(subaccount),
            "command".to_string() => Map(hashmap! {
                "RefreshVotingPower".to_string() => Array(vec![]),
            }),
        }),
    );
}

#[test]
fn test_manage_neuron_to_self_describing_with_legacy_id() {
    assert_manage_neuron_self_describing_value_is(
        ManageNeuron {
            id: Some(NeuronId { id: 456 }),
            neuron_id_or_subaccount: None,
            command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
        },
        Map(hashmap! {
            "neuron_id".to_string() => Nat(candid::Nat::from(456_u64)),
            "command".to_string() => Map(hashmap! {
                "RefreshVotingPower".to_string() => Array(vec![]),
            }),
        }),
    );
}

#[test]
fn test_command_refresh_voting_power_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::RefreshVotingPower(RefreshVotingPower {}),
        Map(hashmap! {
            "RefreshVotingPower".to_string() => Array(vec![]),
        }),
    );
}

#[test]
fn test_command_configure_increase_dissolve_delay_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                additional_dissolve_delay_seconds: 86_400,
            })),
        }),
        Map(hashmap! {
            "IncreaseDissolveDelay".to_string() => Map(hashmap! {
                "additional_dissolve_delay_seconds".to_string() => Nat(candid::Nat::from(86_400_u32)),
            }),
        }),
    );
}

#[test]
fn test_command_configure_start_dissolving_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::StartDissolving(StartDissolving {})),
        }),
        Map(hashmap! {
            "StartDissolving".to_string() => Array(vec![]),
        }),
    );
}

#[test]
fn test_command_configure_stop_dissolving_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::StopDissolving(StopDissolving {})),
        }),
        Map(hashmap! {
            "StopDissolving".to_string() => Array(vec![]),
        }),
    );
}

#[test]
fn test_command_configure_add_hot_key_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(42);
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::AddHotKey(AddHotKey {
                new_hot_key: Some(principal),
            })),
        }),
        Map(hashmap! {
            "AddHotKey".to_string() => Map(hashmap! {
                "new_hot_key".to_string() => Array(vec![
                    Text(principal.to_string()),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_disburse_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Disburse(Disburse {
            amount: Some(Amount { e8s: 100_000_000 }),
            to_account: Some(AccountIdentifier {
                hash: vec![1_u8; 28],
            }),
        }),
        Map(hashmap! {
            "Disburse".to_string() => Map(hashmap! {
                "amount_e8s".to_string() => Array(vec![
                    Nat(candid::Nat::from(100_000_000_u64)),
                ]),
                "to_account".to_string() => Array(vec![
                    Blob(vec![1_u8; 28]),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_split_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Split(Split {
            amount_e8s: 50_000_000,
            memo: Some(12_345),
        }),
        Map(hashmap! {
            "Split".to_string() => Map(hashmap! {
                "amount_e8s".to_string() => Nat(candid::Nat::from(50_000_000_u64)),
                "memo".to_string() => Array(vec![
                    Nat(candid::Nat::from(12_345_u64)),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_follow_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Follow(Follow {
            topic: Topic::Governance as i32,
            followees: vec![NeuronId { id: 1 }, NeuronId { id: 2 }],
        }),
        Map(hashmap! {
            "Follow".to_string() => Map(hashmap! {
                "topic".to_string() => Text("Governance".to_string()),
                "followees".to_string() => Array(vec![
                    Nat(candid::Nat::from(1_u64)),
                    Nat(candid::Nat::from(2_u64)),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_register_vote_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::RegisterVote(RegisterVote {
            proposal: Some(ProposalId { id: 42 }),
            vote: Vote::Yes as i32,
        }),
        Map(hashmap! {
            "RegisterVote".to_string() => Map(hashmap! {
                "proposal".to_string() => Array(vec![
                    Nat(candid::Nat::from(42_u64)),
                ]),
                "vote".to_string() => Text("Yes".to_string()),
            }),
        }),
    );
}

#[test]
fn test_command_disburse_maturity_with_to_account_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::DisburseMaturity(DisburseMaturity {
            percentage_to_disburse: 25,
            to_account: Some(Account {
                owner: Some(PrincipalId::new_user_test_id(1)),
                subaccount: None,
            }),
            to_account_identifier: None,
        }),
        Map(hashmap! {
            "DisburseMaturity".to_string() => Map(hashmap! {
                "percentage_to_disburse".to_string() => Nat(candid::Nat::from(25_u32)),
                "to_account".to_string() => Array(vec![
                    Map(hashmap! {
                        "owner".to_string() => Text(PrincipalId::new_user_test_id(1).to_string()),
                        "subaccount".to_string() => Array(vec![]),
                    }),
                ]),
                "to_account_identifier".to_string() => Array(vec![]),
            }),
        }),
    );
}

#[test]
fn test_command_disburse_maturity_with_to_account_identifier_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::DisburseMaturity(DisburseMaturity {
            percentage_to_disburse: 50,
            to_account: None,
            to_account_identifier: Some(AccountIdentifier {
                hash: vec![2_u8; 28],
            }),
        }),
        Map(hashmap! {
            "DisburseMaturity".to_string() => Map(hashmap! {
                "percentage_to_disburse".to_string() => Nat(candid::Nat::from(50_u32)),
                "to_account".to_string() => Array(vec![]),
                "to_account_identifier".to_string() => Array(vec![
                    Blob(vec![2_u8; 28]),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_configure_remove_hot_key_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(99);
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::RemoveHotKey(RemoveHotKey {
                hot_key_to_remove: Some(principal),
            })),
        }),
        Map(hashmap! {
            "RemoveHotKey".to_string() => Map(hashmap! {
                "hot_key_to_remove".to_string() => Array(vec![
                    Text(principal.to_string()),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_configure_set_dissolve_timestamp_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                dissolve_timestamp_seconds: 1_700_000_000,
            })),
        }),
        Map(hashmap! {
            "SetDissolveTimestamp".to_string() => Map(hashmap! {
                "dissolve_timestamp_seconds".to_string() => Nat(candid::Nat::from(1_700_000_000_u64)),
            }),
        }),
    );
}

#[test]
fn test_command_configure_join_community_fund_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
        }),
        Map(hashmap! {
            "JoinCommunityFund".to_string() => Array(vec![]),
        }),
    );
}

#[test]
fn test_command_configure_leave_community_fund_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::LeaveCommunityFund(LeaveCommunityFund {})),
        }),
        Map(hashmap! {
            "LeaveCommunityFund".to_string() => Array(vec![]),
        }),
    );
}

#[test]
fn test_command_configure_change_auto_stake_maturity_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::ChangeAutoStakeMaturity(
                ChangeAutoStakeMaturity {
                    requested_setting_for_auto_stake_maturity: true,
                },
            )),
        }),
        Map(hashmap! {
            "ChangeAutoStakeMaturity".to_string() => Map(hashmap! {
                "requested_setting_for_auto_stake_maturity".to_string() => Nat(candid::Nat::from(1_u8)),
            }),
        }),
    );
}

#[test]
fn test_command_configure_set_visibility_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Configure(Configure {
            operation: Some(Operation::SetVisibility(SetVisibility {
                visibility: Some(Visibility::Public as i32),
            })),
        }),
        Map(hashmap! {
            "SetVisibility".to_string() => Map(hashmap! {
                "visibility".to_string() => Array(vec![
                    Text("Public".to_string()),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_spawn_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(555);
    assert_command_self_describing_value_is(
        Command::Spawn(Spawn {
            new_controller: Some(principal),
            nonce: Some(999),
            percentage_to_spawn: Some(50),
        }),
        Map(hashmap! {
            "Spawn".to_string() => Map(hashmap! {
                "new_controller".to_string() => Array(vec![
                    Text(principal.to_string()),
                ]),
                "nonce".to_string() => Array(vec![
                    Nat(candid::Nat::from(999_u64)),
                ]),
                "percentage_to_spawn".to_string() => Array(vec![
                    Nat(candid::Nat::from(50_u32)),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_disburse_to_neuron_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(888);
    assert_command_self_describing_value_is(
        Command::DisburseToNeuron(DisburseToNeuron {
            new_controller: Some(principal),
            amount_e8s: 200_000_000,
            dissolve_delay_seconds: 31_536_000,
            kyc_verified: true,
            nonce: 7_777,
        }),
        Map(hashmap! {
            "DisburseToNeuron".to_string() => Map(hashmap! {
                "new_controller".to_string() => Array(vec![
                    Text(principal.to_string()),
                ]),
                "amount_e8s".to_string() => Nat(candid::Nat::from(200_000_000_u64)),
                "dissolve_delay_seconds".to_string() => Nat(candid::Nat::from(31536000_u64)),
                "kyc_verified".to_string() => Nat(candid::Nat::from(1_u8)),
                "nonce".to_string() => Nat(candid::Nat::from(7_777_u64)),
            }),
        }),
    );
}

#[test]
fn test_command_claim_or_refresh_memo_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(claim_or_refresh::By::Memo(54321)),
        }),
        Map(hashmap! {
            "ClaimOrRefresh".to_string() => Map(hashmap! {
                "By".to_string() => Text("Memo".to_string()),
                "memo".to_string() => Nat(candid::Nat::from(54_321_u64)),
            }),
        }),
    );
}

#[test]
fn test_command_claim_or_refresh_memo_and_controller_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(777);
    assert_command_self_describing_value_is(
        Command::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(claim_or_refresh::By::MemoAndController(
                claim_or_refresh::MemoAndController {
                    memo: 98765,
                    controller: Some(principal),
                },
            )),
        }),
        Map(hashmap! {
            "ClaimOrRefresh".to_string() => Map(hashmap! {
                "By".to_string() => Text("MemoAndController".to_string()),
                "memo".to_string() => Nat(candid::Nat::from(98_765_u32)),
                "controller".to_string() => Array(vec![
                    Text(principal.to_string()),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_claim_or_refresh_neuron_id_or_subaccount_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::ClaimOrRefresh(ClaimOrRefresh {
            by: Some(claim_or_refresh::By::NeuronIdOrSubaccount(Empty {})),
        }),
        Map(hashmap! {
            "ClaimOrRefresh".to_string() => Map(hashmap! {
                "By".to_string() => Text("NeuronIdOrSubaccount".to_string()),
            }),
        }),
    );
}

#[test]
fn test_command_merge_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::Merge(Merge {
            source_neuron_id: Some(NeuronId { id: 1700 }),
        }),
        Map(hashmap! {
            "Merge".to_string() => Map(hashmap! {
                "source_neuron_id".to_string() => Array(vec![
                    Nat(candid::Nat::from(1_700_u64)),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_stake_maturity_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::StakeMaturity(StakeMaturity {
            percentage_to_stake: Some(100),
        }),
        Map(hashmap! {
            "StakeMaturity".to_string() => Map(hashmap! {
                "percentage_to_stake".to_string() => Array(vec![
                    Nat(candid::Nat::from(100_u32)),
                ]),
            }),
        }),
    );
}

#[test]
fn test_command_set_following_to_self_describing() {
    assert_command_self_describing_value_is(
        Command::SetFollowing(SetFollowing {
            topic_following: vec![
                set_following::FolloweesForTopic {
                    followees: vec![NeuronId { id: 3 }, NeuronId { id: 4 }],
                    topic: Some(Topic::Governance as i32),
                },
                set_following::FolloweesForTopic {
                    followees: vec![NeuronId { id: 5 }],
                    topic: Some(Topic::SnsAndCommunityFund as i32),
                },
            ],
        }),
        Map(hashmap! {
            "SetFollowing".to_string() => Array(vec![
                Map(hashmap! {
                    "topic".to_string() => Array(vec![
                        Text("Governance".to_string()),
                    ]),
                    "followees".to_string() => Array(vec![
                        Nat(candid::Nat::from(3_u64)),
                        Nat(candid::Nat::from(4_u64)),
                    ]),
                }),
                Map(hashmap! {
                    "topic".to_string() => Array(vec![
                        Text("SnsAndCommunityFund".to_string()),
                    ]),
                    "followees".to_string() => Array(vec![
                        Nat(candid::Nat::from(5_u64)),
                    ]),
                }),
            ]),
        }),
    );
}
