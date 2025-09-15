use candid::{Nat, Principal};
use futures::future::join_all;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ClaimOrRefreshNeuronFromAccountResponse, GovernanceError,
    Neuron,
    claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshNeuronFromAccountResponseResult,
    neuron::DissolveState,
};
use icp_ledger::Tokens;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use pocket_ic::nonblocking::{PocketIc, update_candid_as};

use crate::utils::{ALL_SNS_TESTING_CANISTER_IDS, check_canister_installed};

async fn validate_subnet_setup(pocket_ic: &PocketIc) {
    let topology = pocket_ic.topology().await;
    let _nns_subnet_id = topology.get_nns().expect("NNS subnet not found");
    let _sns_subnet_id = topology.get_nns().expect("SNS subnet not found");
    let _ii_subnet_id = topology.get_ii().expect("II subnet not found");
    let app_subnet_ids = topology.get_app_subnets();
    assert!(!app_subnet_ids.is_empty(), "No application subnets found");
}

pub async fn bootstrap_nns(
    pocket_ic: &PocketIc,
    ledger_balances: Vec<(PrincipalId, Tokens)>,
    neuron_controller: PrincipalId,
) -> NeuronId {
    const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

    // Ensure that all required subnets are present before proceeding to install NNS canisters
    // At the moment this check doesn't make a lot of sense since we are always creating the new PocketIC instance
    // with all the required subnets. However, in the future, we might want to be able to check externally provided
    // networks.
    validate_subnet_setup(pocket_ic).await;
    // Check if all NNS canisters are already installed
    let canisters_installed = join_all(
        ALL_SNS_TESTING_CANISTER_IDS
            .iter()
            .map(|canister_id| async { check_canister_installed(pocket_ic, canister_id).await }),
    )
    .await;

    if !canisters_installed.iter().all(|exists| *exists) {
        panic!("Some NNS canisters are missing, we cannot fix this automatically at the moment");
    }

    let governance_id = GOVERNANCE_CANISTER_ID.get().0;
    let icp_ledger_id = LEDGER_CANISTER_ID.get().0;

    // Set up initial ICP ledger balances.
    for (owner, amount) in ledger_balances {
        let fee: Nat = 10_000_u64.into();
        let to = Account {
            owner: owner.into(),
            subaccount: None,
        };
        let transfer_arg = TransferArg {
            from_subaccount: None,
            to,
            fee: Some(fee),
            created_at_time: None,
            memo: None,
            amount: amount.get_e8s().into(),
        };
        update_candid_as::<_, (Result<Nat, TransferError>,)>(
            pocket_ic,
            icp_ledger_id,
            Principal::anonymous(),
            "icrc1_transfer",
            (transfer_arg,),
        )
        .await
        .unwrap()
        .0
        .unwrap();
    }

    // Transfer the neuron stake of 1,000,000 ICP to the corresponding NNS governance subaccount.
    let nonce = 42_u64;
    let neuron_subaccount = compute_neuron_staking_subaccount_bytes(neuron_controller, nonce);
    let neuron_account = Account {
        owner: governance_id,
        subaccount: Some(neuron_subaccount),
    };
    let fee: Nat = 10_000_u64.into();
    let neuron_stake_e8s = Tokens::from_tokens(1_000_000).unwrap().get_e8s();
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: neuron_account,
        fee: Some(fee),
        created_at_time: None,
        memo: None,
        amount: neuron_stake_e8s.into(),
    };
    update_candid_as::<_, (Result<Nat, TransferError>,)>(
        pocket_ic,
        icp_ledger_id,
        Principal::anonymous(),
        "icrc1_transfer",
        (transfer_arg,),
    )
    .await
    .unwrap()
    .0
    .unwrap();

    // Claim the neuron.
    let claim_neuron_arg = ClaimOrRefreshNeuronFromAccount {
        controller: Some(neuron_controller),
        memo: nonce,
    };
    let res = update_candid_as::<_, (ClaimOrRefreshNeuronFromAccountResponse,)>(
        pocket_ic,
        governance_id,
        neuron_controller.into(),
        "claim_or_refresh_neuron_from_account",
        (claim_neuron_arg,),
    )
    .await
    .unwrap()
    .0
    .result
    .unwrap();
    let deciding_neuron_id = match res {
        ClaimOrRefreshNeuronFromAccountResponseResult::NeuronId(neuron_id) => neuron_id,
        _ => panic!("Unexpected result of claiming NNS neuron: {res:?}"),
    };

    // And finally update the neuron.
    let voting_power_refreshed_timestamp_seconds =
        Some(pocket_ic.get_time().await.as_nanos_since_unix_epoch() / 1_000_000_000);
    let deciding_neuron = Neuron {
        id: Some(deciding_neuron_id),
        account: neuron_subaccount.into(),
        controller: Some(neuron_controller),
        cached_neuron_stake_e8s: neuron_stake_e8s,
        maturity_e8s_equivalent: 1_500_000 * 1_00000000,
        auto_stake_maturity: Some(true),
        joined_community_fund_timestamp_seconds: Some(1),
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
        not_for_profit: true,
        hot_keys: vec![],
        voting_power_refreshed_timestamp_seconds,
        ..Default::default()
    };
    let res = update_candid_as::<_, (Option<GovernanceError>,)>(
        pocket_ic,
        governance_id,
        neuron_controller.into(),
        "update_neuron",
        (deciding_neuron,),
    )
    .await
    .unwrap()
    .0;
    assert!(res.is_none());

    deciding_neuron_id
}
