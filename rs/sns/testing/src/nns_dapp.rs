use candid::{CandidType, Encode, Nat, Principal};
use canister_test::Wasm;
use futures::future::join_all;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_with_controllers;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID, LEDGER_CANISTER_ID,
    LEDGER_INDEX_CANISTER_ID, NNS_UI_CANISTER_ID, ROOT_CANISTER_ID, SNS_AGGREGATOR_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
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
        _ => panic!("Unexpected result of claiming NNS neuron: {:?}", res),
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

    install_frontend_nns_canisters(pocket_ic).await;

    deciding_neuron_id
}

#[derive(CandidType)]
struct NnsDappPayload {
    args: Vec<(String, String)>,
}

async fn install_frontend_nns_canisters(pocket_ic: &PocketIc) {
    let features = &[];

    let nns_dapp_wasm = Wasm::from_location_specified_by_env_var("nns_dapp", features).unwrap();

    if !check_canister_installed(pocket_ic, &NNS_UI_CANISTER_ID).await {
        // TODO @rvem: perhaps, we may start using configurable endpoint for the IC http interface
        // which should be considered in NNS dapp configuration.
        let gateway_port = 8080;
        let localhost_url = format!("http://localhost:{}", gateway_port);
        let args = vec![
              ("API_HOST".to_string(), localhost_url.clone()),
              ("CYCLES_MINTING_CANISTER_ID".to_string(), CYCLES_MINTING_CANISTER_ID.to_string()),
              ("DFX_NETWORK".to_string(), "local".to_string()),
              ("FEATURE_FLAGS".to_string(), "{\"DISABLE_CKTOKENS\":true,\"DISABLE_IMPORT_TOKEN_VALIDATION_FOR_TESTING\":false,\"ENABLE_APY_PORTFOLIO\":true,\"ENABLE_CKTESTBTC\":false,\"ENABLE_DISBURSE_MATURITY\":true,\"ENABLE_LAUNCHPAD_REDESIGN\":true,\"ENABLE_NEW_TABLES\":true,\"ENABLE_NNS_TOPICS\":false,\"ENABLE_SNS_TOPICS\":true}".to_string()),
              ("FETCH_ROOT_KEY".to_string(), "true".to_string()),
              ("GOVERNANCE_CANISTER_ID".to_string(), GOVERNANCE_CANISTER_ID.to_string()),
              ("HOST".to_string(), localhost_url.clone()),
              /* ICP swap canister is not deployed by sns-testing! */
              ("ICP_SWAP_URL".to_string(), format!("http://uvevg-iyaaa-aaaak-ac27q-cai.raw.localhost:{}/", gateway_port)),
              ("IDENTITY_SERVICE_URL".to_string(), format!("http://{}.localhost:{}", IDENTITY_CANISTER_ID, gateway_port)),
              ("INDEX_CANISTER_ID".to_string(), LEDGER_INDEX_CANISTER_ID.to_string()),
              ("LEDGER_CANISTER_ID".to_string(), LEDGER_CANISTER_ID.to_string()),
              ("OWN_CANISTER_ID".to_string(), NNS_UI_CANISTER_ID.to_string()),
              /* plausible.io API might not work anyway so the value of `PLAUSIBLE_DOMAIN` is pretty much arbitrary */
              ("PLAUSIBLE_DOMAIN".to_string(), format!("{}.localhost", NNS_UI_CANISTER_ID)),
              ("ROBOTS".to_string(), "".to_string()),
              ("SNS_AGGREGATOR_URL".to_string(), format!("http://{}.localhost:{}", SNS_AGGREGATOR_CANISTER_ID, gateway_port)),
              ("STATIC_HOST".to_string(), localhost_url.clone()),
              ("TVL_CANISTER_ID".to_string(), NNS_UI_CANISTER_ID.to_string()),
              ("WASM_CANISTER_ID".to_string(), SNS_WASM_CANISTER_ID.to_string()),
            ];
        let nns_dapp_payload = NnsDappPayload { args };
        install_canister_with_controllers(
            pocket_ic,
            "nns-dapp",
            NNS_UI_CANISTER_ID,
            Encode!(&nns_dapp_payload).unwrap(),
            nns_dapp_wasm,
            vec![ROOT_CANISTER_ID.get()],
        )
        .await;
    };
}
