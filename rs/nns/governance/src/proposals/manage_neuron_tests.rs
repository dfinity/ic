use super::*;

use crate::{
    pb::v1::{
        Account, SelfDescribingValue as SelfDescribingValuePb, Vote,
        manage_neuron::{claim_or_refresh, disburse::Amount, set_following},
    },
    proposals::self_describing::LocallyDescribableProposalAction,
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance_api::SelfDescribingValue;
use icp_ledger::protobuf::AccountIdentifier;
use maplit::hashmap;

// ========== ManageNeuron to SelfDescribingValue tests with different id cases ==========

#[test]
fn test_manage_neuron_to_self_describing_with_neuron_id() {
    let manage_neuron = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 123 })),
        command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
    };

    let value = SelfDescribingValue::from(manage_neuron.to_self_describing_action().value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "neuron_id_or_subaccount".to_string() => SelfDescribingValue::Map(hashmap! {
                "NeuronId".to_string() => SelfDescribingValue::Nat(candid::Nat::from(123u64)),
            }),
            "command".to_string() => SelfDescribingValue::Map(hashmap! {
                "RefreshVotingPower".to_string() => SelfDescribingValue::Array(vec![]),
            }),
        })
    );
}

#[test]
fn test_manage_neuron_to_self_describing_with_subaccount() {
    let subaccount = vec![1u8; 32];
    let manage_neuron = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(subaccount.clone())),
        command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
    };

    let value = SelfDescribingValue::from(manage_neuron.to_self_describing_action().value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "neuron_id_or_subaccount".to_string() => SelfDescribingValue::Map(hashmap! {
                "Subaccount".to_string() => SelfDescribingValue::Blob(subaccount),
            }),
            "command".to_string() => SelfDescribingValue::Map(hashmap! {
                "RefreshVotingPower".to_string() => SelfDescribingValue::Array(vec![]),
            }),
        })
    );
}

#[test]
fn test_manage_neuron_to_self_describing_with_legacy_id() {
    let manage_neuron = ManageNeuron {
        id: Some(NeuronId { id: 456 }),
        neuron_id_or_subaccount: None,
        command: Some(Command::RefreshVotingPower(RefreshVotingPower {})),
    };

    let value = SelfDescribingValue::from(manage_neuron.to_self_describing_action().value.unwrap());

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "neuron_id_or_subaccount".to_string() => SelfDescribingValue::Map(hashmap! {
                "NeuronId".to_string() => SelfDescribingValue::Nat(candid::Nat::from(456u64)),
            }),
            "command".to_string() => SelfDescribingValue::Map(hashmap! {
                "RefreshVotingPower".to_string() => SelfDescribingValue::Array(vec![]),
            }),
        })
    );
}

// ========== Command to SelfDescribingValue tests ==========

#[test]
fn test_command_refresh_voting_power_to_self_describing() {
    let command = Command::RefreshVotingPower(RefreshVotingPower {});
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "RefreshVotingPower".to_string() => SelfDescribingValue::Array(vec![]),
        })
    );
}

#[test]
fn test_command_configure_increase_dissolve_delay_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::IncreaseDissolveDelay(
            IncreaseDissolveDelay {
                additional_dissolve_delay_seconds: 86400,
            },
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "IncreaseDissolveDelay".to_string() => SelfDescribingValue::Map(hashmap! {
                            "additional_dissolve_delay_seconds".to_string() => SelfDescribingValue::Nat(candid::Nat::from(86400u32)),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_start_dissolving_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::StartDissolving(StartDissolving {})),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "StartDissolving".to_string() => SelfDescribingValue::Array(vec![]),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_stop_dissolving_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::StopDissolving(StopDissolving {})),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "StopDissolving".to_string() => SelfDescribingValue::Array(vec![]),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_add_hot_key_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(42);
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::AddHotKey(AddHotKey {
            new_hot_key: Some(principal),
        })),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "AddHotKey".to_string() => SelfDescribingValue::Map(hashmap! {
                            "new_hot_key".to_string() => SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Text(principal.to_string()),
                            ]),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_disburse_to_self_describing() {
    let account_id = AccountIdentifier {
        hash: vec![1u8; 28],
    };
    let command = Command::Disburse(Disburse {
        amount: Some(Amount { e8s: 100_000_000 }),
        to_account: Some(account_id.clone()),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    let expected_account_hex = account_id
        .hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Disburse".to_string() => SelfDescribingValue::Map(hashmap! {
                "amount".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "e8s".to_string() => SelfDescribingValue::Nat(candid::Nat::from(100_000_000u64)),
                    }),
                ]),
                "to_account".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Text(expected_account_hex),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_split_to_self_describing() {
    let command = Command::Split(Split {
        amount_e8s: 50_000_000,
        memo: Some(12345),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Split".to_string() => SelfDescribingValue::Map(hashmap! {
                "amount_e8s".to_string() => SelfDescribingValue::Nat(candid::Nat::from(50_000_000u64)),
                "memo".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(12345u64)),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_follow_to_self_describing() {
    let command = Command::Follow(Follow {
        topic: Topic::Governance as i32,
        followees: vec![NeuronId { id: 1 }, NeuronId { id: 2 }],
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Follow".to_string() => SelfDescribingValue::Map(hashmap! {
                "topic".to_string() => SelfDescribingValue::Text("Governance".to_string()),
                "followees".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(1u64)),
                    SelfDescribingValue::Nat(candid::Nat::from(2u64)),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_register_vote_to_self_describing() {
    let command = Command::RegisterVote(RegisterVote {
        proposal: Some(ProposalId { id: 42 }),
        vote: Vote::Yes as i32,
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "RegisterVote".to_string() => SelfDescribingValue::Map(hashmap! {
                "proposal".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(42u64)),
                ]),
                "vote".to_string() => SelfDescribingValue::Text("Yes".to_string()),
            }),
        })
    );
}

#[test]
fn test_command_merge_maturity_to_self_describing() {
    let command = Command::MergeMaturity(MergeMaturity {
        percentage_to_merge: 75,
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "MergeMaturity".to_string() => SelfDescribingValue::Map(hashmap! {
                "percentage_to_merge".to_string() => SelfDescribingValue::Nat(candid::Nat::from(75u32)),
            }),
        })
    );
}

#[test]
fn test_command_disburse_maturity_with_to_account_to_self_describing() {
    let command = Command::DisburseMaturity(DisburseMaturity {
        percentage_to_disburse: 25,
        to_account: Some(Account {
            owner: Some(PrincipalId::new_user_test_id(1)),
            subaccount: None,
        }),
        to_account_identifier: None,
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "DisburseMaturity".to_string() => SelfDescribingValue::Map(hashmap! {
                "percentage_to_disburse".to_string() => SelfDescribingValue::Nat(candid::Nat::from(25u32)),
                "to_account".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "owner".to_string() => SelfDescribingValue::Array(vec![
                            SelfDescribingValue::Text(PrincipalId::new_user_test_id(1).to_string()),
                        ]),
                        "subaccount".to_string() => SelfDescribingValue::Array(vec![]),
                    }),
                ]),
                "to_account_identifier".to_string() => SelfDescribingValue::Array(vec![]),
            }),
        })
    );
}

#[test]
fn test_command_disburse_maturity_with_to_account_identifier_to_self_describing() {
    let account_id = AccountIdentifier {
        hash: vec![2u8; 28],
    };
    let command = Command::DisburseMaturity(DisburseMaturity {
        percentage_to_disburse: 50,
        to_account: None,
        to_account_identifier: Some(account_id.clone()),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    let expected_account_hex = account_id
        .hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "DisburseMaturity".to_string() => SelfDescribingValue::Map(hashmap! {
                "percentage_to_disburse".to_string() => SelfDescribingValue::Nat(candid::Nat::from(50u32)),
                "to_account".to_string() => SelfDescribingValue::Array(vec![]),
                "to_account_identifier".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Text(expected_account_hex),
                ]),
            }),
        })
    );
}

// ========== Additional Configure operations ==========

#[test]
fn test_command_configure_remove_hot_key_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(99);
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::RemoveHotKey(RemoveHotKey {
            hot_key_to_remove: Some(principal),
        })),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "RemoveHotKey".to_string() => SelfDescribingValue::Map(hashmap! {
                            "hot_key_to_remove".to_string() => SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Text(principal.to_string()),
                            ]),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_set_dissolve_timestamp_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::SetDissolveTimestamp(
            SetDissolveTimestamp {
                dissolve_timestamp_seconds: 1700000000,
            },
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "SetDissolveTimestamp".to_string() => SelfDescribingValue::Map(hashmap! {
                            "dissolve_timestamp_seconds".to_string() => SelfDescribingValue::Nat(candid::Nat::from(1700000000u64)),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_join_community_fund_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::JoinCommunityFund(
            JoinCommunityFund {},
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "JoinCommunityFund".to_string() => SelfDescribingValue::Array(vec![]),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_leave_community_fund_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::LeaveCommunityFund(
            LeaveCommunityFund {},
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "LeaveCommunityFund".to_string() => SelfDescribingValue::Array(vec![]),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_change_auto_stake_maturity_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::ChangeAutoStakeMaturity(
            ChangeAutoStakeMaturity {
                requested_setting_for_auto_stake_maturity: true,
            },
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "ChangeAutoStakeMaturity".to_string() => SelfDescribingValue::Map(hashmap! {
                            "requested_setting_for_auto_stake_maturity".to_string() => SelfDescribingValue::Nat(candid::Nat::from(1u8)),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_configure_set_visibility_to_self_describing() {
    let command = Command::Configure(Configure {
        operation: Some(configure::Operation::SetVisibility(SetVisibility {
            visibility: Some(Visibility::Public as i32),
        })),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Configure".to_string() => SelfDescribingValue::Map(hashmap! {
                "operation".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "SetVisibility".to_string() => SelfDescribingValue::Map(hashmap! {
                            "visibility".to_string() => SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Text("Public".to_string()),
                            ]),
                        }),
                    }),
                ]),
            }),
        })
    );
}

// ========== Additional Commands ==========

#[test]
fn test_command_spawn_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(555);
    let command = Command::Spawn(Spawn {
        new_controller: Some(principal),
        nonce: Some(999),
        percentage_to_spawn: Some(50),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Spawn".to_string() => SelfDescribingValue::Map(hashmap! {
                "new_controller".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Text(principal.to_string()),
                ]),
                "nonce".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(999u64)),
                ]),
                "percentage_to_spawn".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(50u32)),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_disburse_to_neuron_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(888);
    let command = Command::DisburseToNeuron(DisburseToNeuron {
        new_controller: Some(principal),
        amount_e8s: 200_000_000,
        dissolve_delay_seconds: 31536000,
        kyc_verified: true,
        nonce: 7777,
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "DisburseToNeuron".to_string() => SelfDescribingValue::Map(hashmap! {
                "new_controller".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Text(principal.to_string()),
                ]),
                "amount_e8s".to_string() => SelfDescribingValue::Nat(candid::Nat::from(200_000_000u64)),
                "dissolve_delay_seconds".to_string() => SelfDescribingValue::Nat(candid::Nat::from(31536000u64)),
                "kyc_verified".to_string() => SelfDescribingValue::Nat(candid::Nat::from(1u8)),
                "nonce".to_string() => SelfDescribingValue::Nat(candid::Nat::from(7777u64)),
            }),
        })
    );
}

#[test]
fn test_command_claim_or_refresh_memo_to_self_describing() {
    let command = Command::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(claim_or_refresh::By::Memo(54321)),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "ClaimOrRefresh".to_string() => SelfDescribingValue::Map(hashmap! {
                "by".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "Memo".to_string() => SelfDescribingValue::Nat(candid::Nat::from(54321u64)),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_claim_or_refresh_memo_and_controller_to_self_describing() {
    let principal = PrincipalId::new_user_test_id(777);
    let command = Command::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(claim_or_refresh::By::MemoAndController(
            claim_or_refresh::MemoAndController {
                memo: 98765,
                controller: Some(principal),
            },
        )),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "ClaimOrRefresh".to_string() => SelfDescribingValue::Map(hashmap! {
                "by".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "MemoAndController".to_string() => SelfDescribingValue::Map(hashmap! {
                            "memo".to_string() => SelfDescribingValue::Nat(candid::Nat::from(98765u64)),
                            "controller".to_string() => SelfDescribingValue::Array(vec![
                                SelfDescribingValue::Text(principal.to_string()),
                            ]),
                        }),
                    }),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_merge_to_self_describing() {
    let command = Command::Merge(Merge {
        source_neuron_id: Some(NeuronId { id: 1700 }),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "Merge".to_string() => SelfDescribingValue::Map(hashmap! {
                "source_neuron_id".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(1700u64)),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_stake_maturity_to_self_describing() {
    let command = Command::StakeMaturity(StakeMaturity {
        percentage_to_stake: Some(100),
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "StakeMaturity".to_string() => SelfDescribingValue::Map(hashmap! {
                "percentage_to_stake".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Nat(candid::Nat::from(100u32)),
                ]),
            }),
        })
    );
}

#[test]
fn test_command_set_following_to_self_describing() {
    let command = Command::SetFollowing(SetFollowing {
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
    });
    let value = SelfDescribingValue::from(SelfDescribingValuePb::from(command));

    assert_eq!(
        value,
        SelfDescribingValue::Map(hashmap! {
            "SetFollowing".to_string() => SelfDescribingValue::Map(hashmap! {
                "topic_following".to_string() => SelfDescribingValue::Array(vec![
                    SelfDescribingValue::Map(hashmap! {
                        "topic".to_string() => SelfDescribingValue::Array(vec![
                            SelfDescribingValue::Text("Governance".to_string()),
                        ]),
                        "followees".to_string() => SelfDescribingValue::Array(vec![
                            SelfDescribingValue::Nat(candid::Nat::from(3u64)),
                            SelfDescribingValue::Nat(candid::Nat::from(4u64)),
                        ]),
                    }),
                    SelfDescribingValue::Map(hashmap! {
                        "topic".to_string() => SelfDescribingValue::Array(vec![
                            SelfDescribingValue::Text("SnsAndCommunityFund".to_string()),
                        ]),
                        "followees".to_string() => SelfDescribingValue::Array(vec![
                            SelfDescribingValue::Nat(candid::Nat::from(5u64)),
                        ]),
                    }),
                ]),
            }),
        })
    );
}
