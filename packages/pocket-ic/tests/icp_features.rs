use crate::common::frontend_canister;
use candid::{CandidType, Encode, Nat, Principal};
use cycles_minting_canister::{
    IcpXdrConversionRate, IcpXdrConversionRateCertifiedResponse, SubnetTypesToSubnetsResponse,
};
use flate2::read::GzDecoder;
use ic_base_types::PrincipalId;
use ic_migration_canister::{
    MigrateCanisterArgs, MigrationStatus, ValidationError as MigrationValidatonError,
};
use ic_nns_governance_api::{
    ClaimOrRefreshNeuronFromAccount, ClaimOrRefreshNeuronFromAccountResponse, GovernanceError,
    InstallCodeRequest, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, Neuron, ProposalActionRequest,
    claim_or_refresh_neuron_from_account_response::Result as ClaimNeuronResult,
    neuron::DissolveState,
};
use ic_sns_wasm::pb::v1::{GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};
use pocket_ic::common::rest::{
    ExtendedSubnetConfigSet, IcpFeatures, IcpFeaturesConfig, InstanceConfig,
    InstanceHttpGatewayConfig, SubnetSpec,
};
use pocket_ic::{
    PocketIc, PocketIcBuilder, PocketIcState, StartServerParams, start_server, update_candid,
    update_candid_as,
};
use registry_canister::pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister};
use reqwest::StatusCode;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
use tempfile::TempDir;
#[cfg(windows)]
use wslpath::windows_to_wsl;

mod common;

const T: u128 = 1_000_000_000_000;

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

// Ungzips `data`, if possible, and returns `data` otherwise.
fn decode_gzipped_bytes(data: Vec<u8>) -> Vec<u8> {
    let mut decoder = GzDecoder::new(&data[..]);

    let mut ungzipped = Vec::new();
    if decoder.read_to_end(&mut ungzipped).is_ok() {
        ungzipped
    } else {
        data
    }
}

fn all_icp_features() -> IcpFeatures {
    IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        icp_token: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_token: Some(IcpFeaturesConfig::DefaultConfig),
        nns_governance: Some(IcpFeaturesConfig::DefaultConfig),
        sns: Some(IcpFeaturesConfig::DefaultConfig),
        ii: Some(IcpFeaturesConfig::DefaultConfig),
        nns_ui: Some(IcpFeaturesConfig::DefaultConfig),
        bitcoin: Some(IcpFeaturesConfig::DefaultConfig),
        dogecoin: Some(IcpFeaturesConfig::DefaultConfig),
        canister_migration: Some(IcpFeaturesConfig::DefaultConfig),
    }
}

#[test]
fn test_canister_migration() {
    let icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        canister_migration: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .with_application_subnet()
        .with_application_subnet()
        .build();

    let canister_migration_orchestrator =
        Principal::from_text("sbzkb-zqaaa-aaaaa-aaaiq-cai").unwrap();

    let topology = pic.topology();
    let subnet_1 = topology.get_app_subnets()[0];
    let subnet_2 = topology.get_app_subnets()[1];

    let create_canister_on_subnet = |subnet: Principal| {
        let canister_id = pic.create_canister_on_subnet(None, None, subnet);
        pic.add_cycles(canister_id, 100 * T);
        pic.set_controllers(
            canister_id,
            None,
            vec![Principal::anonymous(), canister_migration_orchestrator],
        )
        .unwrap();
        pic.install_canister(canister_id, test_canister_wasm(), vec![], None);
        pic.stop_canister(canister_id, None).unwrap();
        canister_id
    };

    let migrated_canister = create_canister_on_subnet(subnet_1);
    let replaced_canister = create_canister_on_subnet(subnet_2);

    assert_eq!(pic.get_subnet(migrated_canister).unwrap(), subnet_1);
    assert_eq!(pic.get_subnet(replaced_canister).unwrap(), subnet_2);

    let migrate_canister_args = MigrateCanisterArgs {
        migrated_canister_id: migrated_canister,
        replaced_canister_id: replaced_canister,
    };
    let res = update_candid::<_, (Result<(), Option<MigrationValidatonError>>,)>(
        &pic,
        canister_migration_orchestrator,
        "migrate_canister",
        (migrate_canister_args.clone(),),
    )
    .unwrap();
    res.0.unwrap();

    let status = || {
        let res = update_candid::<_, (Option<MigrationStatus>,)>(
            &pic,
            canister_migration_orchestrator,
            "migration_status",
            (migrate_canister_args.clone(),),
        )
        .unwrap();
        res.0.unwrap()
    };
    loop {
        pic.advance_time(Duration::from_secs(10));
        if let MigrationStatus::Succeeded { .. } = status() {
            break;
        }
    }

    pic.start_canister(migrated_canister, None).unwrap();

    assert_eq!(pic.get_subnet(migrated_canister).unwrap(), subnet_2);
    assert!(pic.get_subnet(replaced_canister).is_none());

    let res = update_candid::<_, (String,)>(&pic, migrated_canister, "whoami", ()).unwrap();
    assert_eq!(res.0, migrated_canister.to_string());
}

#[test]
#[should_panic(
    expected = "The `nns_ui` feature requires an HTTP gateway to be created via `http_gateway_config`."
)]
fn nns_ui_requires_http_gateway() {
    let _pic = PocketIcBuilder::new()
        .with_icp_features(all_icp_features())
        .build();
}

#[test]
#[should_panic(
    expected = "The `nns_ui` feature requires the `cycles_minting` feature to be enabled, too."
)]
fn nns_ui_requires_other_icp_features() {
    let instance_http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let icp_features = IcpFeatures {
        nns_ui: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let _pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .with_auto_progress()
        .with_http_gateway(instance_http_gateway_config)
        .build();
}

#[test]
fn test_ii_nns_ui() {
    let instance_http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(all_icp_features())
        .with_auto_progress()
        .with_http_gateway(instance_http_gateway_config)
        .build();

    // A basic smoke test.
    let nns_dapp_canister_id = Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap();
    let nns_dapp_title = "Network Nervous System";
    let internet_identity_canister_id =
        Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
    let internet_identity_title = "Internet Identity";
    for (canister_id, expected_title) in [
        (nns_dapp_canister_id.to_string(), nns_dapp_title),
        (
            internet_identity_canister_id.to_string(),
            internet_identity_title,
        ),
    ] {
        let (client, url) =
            frontend_canister(&pic, Principal::from_text(canister_id).unwrap(), false, "/");
        let resp = client.get(url).send().unwrap();
        let body = String::from_utf8(decode_gzipped_bytes(resp.bytes().unwrap().to_vec())).unwrap();
        assert!(body.contains(&format!("<title>{}</title>", expected_title)));
    }
}

#[test]
fn test_no_canister_http_without_auto_progress() {
    let instance_http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(all_icp_features())
        .with_http_gateway(instance_http_gateway_config)
        .build();

    // No canister http outcalls should be made
    // (because we did not enable auto progress when creating the PocketIC instance
    // and system canisters should be configured to make no canister http outcalls
    // in this case).
    // We advance time and execute a few more rounds in case they were only made on timers.
    for _ in 0..10 {
        pic.advance_time(Duration::from_secs(1));
        pic.tick();
    }
    assert!(pic.get_canister_http().is_empty());
}

#[test]
fn test_sns() {
    let icp_features = IcpFeatures {
        sns: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .build();

    // Test that the SNS subnet ID has been set properly.
    let sns_wasm_canister_id = Principal::from_text("qaa6y-5yaaa-aaaaa-aaafa-cai").unwrap();
    let sns_subnet_ids = update_candid::<_, (GetSnsSubnetIdsResponse,)>(
        &pic,
        sns_wasm_canister_id,
        "get_sns_subnet_ids",
        (GetSnsSubnetIdsRequest {},),
    )
    .unwrap()
    .0
    .sns_subnet_ids;
    assert_eq!(
        sns_subnet_ids,
        vec![PrincipalId(pic.topology().get_sns().unwrap())]
    );

    // Test that all SNS canister types have been uploaded (we don't check the actual WASM in this test).
    let latest_sns_version_pretty = update_candid::<_, (Vec<(String, String)>,)>(
        &pic,
        sns_wasm_canister_id,
        "get_latest_sns_version_pretty",
        ((),),
    )
    .unwrap()
    .0;
    let uploaded_sns_wasms: Vec<String> = latest_sns_version_pretty
        .into_iter()
        .map(|(canister_type, _)| canister_type)
        .collect();
    for expected_canister_type in [
        "Root",
        "Governance",
        "Swap",
        "Ledger",
        "Ledger Archive",
        "Ledger Index",
    ] {
        assert!(uploaded_sns_wasms.contains(&expected_canister_type.to_string()));
    }

    // Perform health check on the SNS aggregator.
    let sns_aggregator_canister_id = Principal::from_text("3r4gx-wqaaa-aaaaq-aaaia-cai").unwrap();
    let health_status =
        update_candid::<_, (String,)>(&pic, sns_aggregator_canister_id, "health_check", ())
            .unwrap()
            .0;
    let pic_time_seconds = pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000;
    assert!(health_status.contains(&format!(
        "The last partial update was at: {pic_time_seconds}.  Last update cycle started at {pic_time_seconds}"
    )));
}

#[test]
fn test_nns_governance() {
    fn compute_neuron_domain_subaccount_bytes(
        controller: Principal,
        domain: &[u8],
        nonce: u64,
    ) -> [u8; 32] {
        let domain_length: [u8; 1] = [domain.len() as u8];
        let mut hasher = Sha256::new();
        hasher.update(domain_length);
        hasher.update(domain);
        hasher.update(controller.as_slice());
        hasher.update(nonce.to_be_bytes());
        hasher.finalize().to_vec().try_into().unwrap()
    }

    let icp_features = IcpFeatures {
        icp_token: Some(IcpFeaturesConfig::DefaultConfig),
        nns_governance: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .build();

    let user_id = Principal::from_slice(&[42; 29]); // arbitrary test user id
    let icp_ledger_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    let governance_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
    let root_canister_id = Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap();

    // The following fixed principal has a high ICP balance in test environments.
    let rich_principal =
        Principal::from_text("hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe")
            .unwrap();

    // Transfer the neuron stake of 1 ICP from the "rich" principal to the corresponding NNS governance subaccount.
    let nonce = 42_u64;
    let neuron_subaccount = compute_neuron_domain_subaccount_bytes(user_id, b"neuron-stake", nonce);
    let neuron_account = Account {
        owner: governance_id,
        subaccount: Some(neuron_subaccount),
    };
    let fee: Nat = 10_000_u64.into();
    let memo: Memo = nonce.into();
    let neuron_stake_e8s: Nat = 100_000_000_u64.into(); // 1 ICP
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: neuron_account,
        fee: Some(fee),
        created_at_time: None,
        memo: Some(memo),
        amount: neuron_stake_e8s.clone(),
    };
    update_candid_as::<_, (Result<Nat, TransferError>,)>(
        &pic,
        icp_ledger_id,
        rich_principal,
        "icrc1_transfer",
        (transfer_arg,),
    )
    .unwrap()
    .0
    .unwrap();

    // Claim the neuron.
    let claim_neuron_arg = ClaimOrRefreshNeuronFromAccount {
        controller: Some(PrincipalId(user_id)),
        memo: nonce,
    };
    let res = update_candid_as::<_, (ClaimOrRefreshNeuronFromAccountResponse,)>(
        &pic,
        governance_id,
        user_id,
        "claim_or_refresh_neuron_from_account",
        (claim_neuron_arg,),
    )
    .unwrap()
    .0
    .result
    .unwrap();
    let neuron_id = match res {
        ClaimNeuronResult::NeuronId(neuron_id) => neuron_id,
        ClaimNeuronResult::Error(error) => panic!("Unexpected error: {}", error),
    };

    // Check neuron info.
    let mut neuron = update_candid_as::<_, (Result<Neuron, GovernanceError>,)>(
        &pic,
        governance_id,
        user_id,
        "get_full_neuron",
        (neuron_id.id,),
    )
    .unwrap()
    .0
    .unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, neuron_stake_e8s);
    assert_eq!(
        neuron.dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(604800))
    ); // the default dissolve delay is 7 days

    // Force update the neuron stake (without actually staking any ICP) and dissolve delay (test feature).
    let new_neuron_stake_e8s = 2_500_000_000; // 25 ICP are required to submit a proposal later
    neuron.cached_neuron_stake_e8s = new_neuron_stake_e8s;
    let new_dissolve_state = Some(DissolveState::DissolveDelaySeconds(183 * 86400)); // need a minimum dissolve delay of 6 months to submit a proposal later
    neuron.dissolve_state = new_dissolve_state.clone();
    let res = update_candid_as::<_, (Option<GovernanceError>,)>(
        &pic,
        governance_id,
        user_id,
        "update_neuron",
        (neuron,),
    )
    .unwrap()
    .0;
    assert!(res.is_none());

    // Check neuron info again and ensure the neuron has been updated.
    let updated_neuron = update_candid_as::<_, (Result<Neuron, GovernanceError>,)>(
        &pic,
        governance_id,
        user_id,
        "get_full_neuron",
        (neuron_id.id,),
    )
    .unwrap()
    .0
    .unwrap();
    assert_eq!(updated_neuron.cached_neuron_stake_e8s, new_neuron_stake_e8s);
    assert_eq!(updated_neuron.dissolve_state, new_dissolve_state);

    // Create a new canister controller by NNS (root).
    let canister_id = pic.create_canister();
    pic.set_controllers(
        canister_id,
        None,
        vec![Principal::anonymous(), root_canister_id],
    )
    .unwrap();

    // The canister is initially empty.
    let status = pic.canister_status(canister_id, None).unwrap();
    assert_eq!(status.module_hash, None);

    // Make proposal to install the canister controlled by NNS (root).
    let install_code = InstallCodeRequest {
        arg: Some(Encode!(&()).unwrap()),
        wasm_module: Some(test_canister_wasm()),
        skip_stopping_before_installing: None,
        canister_id: Some(PrincipalId(canister_id)),
        install_mode: Some(1), // Install
    };
    let proposal_action = ProposalActionRequest::InstallCode(install_code);
    let proposal = MakeProposalRequest {
        url: "https://forum.dfinity.org".to_string(),
        title: Some("My test canister upgrade proposal.".to_string()),
        action: Some(proposal_action),
        summary: "".to_string(),
    };
    let command = ManageNeuronCommandRequest::MakeProposal(Box::new(proposal));
    let manage_neuron_request = ManageNeuronRequest {
        id: Some(neuron_id),
        neuron_id_or_subaccount: None,
        command: Some(command),
    };
    update_candid_as::<_, (ManageNeuronResponse,)>(
        &pic,
        governance_id,
        user_id,
        "manage_neuron",
        (manage_neuron_request,),
    )
    .unwrap()
    .0
    .command
    .unwrap();

    // Execute a few rounds to make sure the proposal has been successfully executed.
    for _ in 0..10 {
        pic.tick();
    }

    // The canister has been successfully installed.
    let status = pic.canister_status(canister_id, None).unwrap();
    let test_canister_wasm_sha256 = Sha256::digest(test_canister_wasm()).to_vec();
    assert_eq!(status.module_hash, Some(test_canister_wasm_sha256));
}

#[test]
fn test_icp_ledger() {
    let icp_features = IcpFeatures {
        icp_token: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .build();
    let user_id = Principal::from_slice(&[42; 29]); // arbitrary test user id

    let icp_ledger_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    let icp_index_id = Principal::from_text("qhbym-qaaaa-aaaaa-aaafq-cai").unwrap();

    let check_balance = |owner: Principal, expected_balance| {
        // Check balance via ICP ledger.
        let account = Account {
            owner,
            subaccount: None,
        };
        let balance =
            update_candid::<_, (Nat,)>(&pic, icp_ledger_id, "icrc1_balance_of", (account,))
                .unwrap()
                .0;
        assert_eq!(balance, expected_balance);

        // The ICP index only syncs with the ICP ledger at least every two seconds.
        pic.advance_time(Duration::from_secs(2));
        pic.tick();

        // Check balance via ICP index.
        let balance =
            update_candid::<_, (u64,)>(&pic, icp_index_id, "icrc1_balance_of", (account,))
                .unwrap()
                .0;
        assert_eq!(balance, expected_balance);
    };

    // The following fixed principal has a high ICP balance in test environments.
    let rich_principal =
        Principal::from_text("hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe")
            .unwrap();

    let mut user_balance = 0;
    for owner in [Principal::anonymous(), rich_principal] {
        const E8S_PER_ICP: u64 = 100_000_000;
        let expected_balance = 1_000_000_000 * E8S_PER_ICP;
        check_balance(owner, expected_balance);

        // transfer 1 ICP to an account controlled by `user_id`
        let user_account = Account {
            owner: user_id,
            subaccount: None,
        };
        let fee_e8s = 10_000_u64;
        let amount_e8s = 100_000_000_u64; // 1 ICP
        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: user_account,
            fee: Some(fee_e8s.into()),
            created_at_time: None,
            memo: None,
            amount: amount_e8s.into(),
        };
        update_candid_as::<_, (Result<Nat, TransferError>,)>(
            &pic,
            icp_ledger_id,
            owner,
            "icrc1_transfer",
            (transfer_arg,),
        )
        .unwrap()
        .0
        .unwrap();

        check_balance(owner, expected_balance - amount_e8s - fee_e8s);
        user_balance += amount_e8s;
        check_balance(user_id, user_balance);
    }
}

#[test]
fn test_cycles_ledger() {
    #[derive(CandidType)]
    struct WithdrawArgs {
        from_subaccount: Option<Subaccount>,
        to: Principal,
        created_at_time: Option<u64>,
        amount: Nat,
    }

    #[derive(CandidType, Deserialize, Debug)]
    enum WithdrawError {
        InsufficientFunds { balance: Nat },
    }

    const B: u128 = 1_000_000_000;
    const CYCLES_LEDGER_FEE: u128 = 100_000_000;

    let test_identity = Principal::from_slice(&[42; 29]);
    let cycles_ledger_id = Principal::from_text("um5iw-rqaaa-aaaaq-qaaba-cai").unwrap();

    let icp_features = IcpFeatures {
        cycles_token: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_icp_features(icp_features)
        .with_application_subnet()
        .build();

    let canister_id = pic.create_canister();
    assert_eq!(
        pic.get_subnet(canister_id).unwrap(),
        pic.topology().get_app_subnets()[0]
    );
    let init_cycles = u128::MAX / 2;
    pic.add_cycles(canister_id, init_cycles);
    pic.install_canister(canister_id, test_canister_wasm(), vec![], None);

    let check_balance = |owner: Principal, expected_balance: u128| {
        // Check balance via cycles ledger.
        let account = Account {
            owner,
            subaccount: None,
        };
        let balance =
            update_candid::<_, (Nat,)>(&pic, cycles_ledger_id, "icrc1_balance_of", (account,))
                .unwrap()
                .0;
        assert_eq!(balance, expected_balance);

        // The cycles ledger index only syncs with the cycles ledger once per second.
        pic.advance_time(Duration::from_secs(1));
        pic.tick();

        // Check balance via cycles ledger index.
        let cycles_ledger_index_id = Principal::from_text("ul4oc-4iaaa-aaaaq-qaabq-cai").unwrap();
        let balance = update_candid::<_, (Nat,)>(
            &pic,
            cycles_ledger_index_id,
            "icrc1_balance_of",
            (account,),
        )
        .unwrap()
        .0;
        assert!(balance == expected_balance);
    };
    let check_cycles = |expected: u128| {
        let actual = pic.cycle_balance(canister_id);
        // Allow the actual ICP cycles balance to be less than the expected cycles balance by 10B cycles
        // due to resource consumption and cycles ledger fees.
        assert!(
            expected <= actual.saturating_add(10 * B) && actual <= expected,
            "actual: {actual}; expected: {expected}"
        );
    };

    check_balance(test_identity, 0);
    check_cycles(init_cycles);

    // Deposit cycles to the cycles ledger.
    let cycles = init_cycles / 2;
    let cycles_nat: Nat = cycles.into();
    update_candid::<_, ()>(
        &pic,
        canister_id,
        "deposit_cycles_to_cycles_ledger",
        (test_identity, cycles_nat),
    )
    .unwrap();

    // The fee has been deducted from the deposit.
    check_balance(test_identity, cycles - CYCLES_LEDGER_FEE);
    check_cycles(init_cycles - cycles);

    // Withdraw cycles from the cycles ledger.
    // One more fee is charged for the withdrawal.
    let amount = cycles - 2 * CYCLES_LEDGER_FEE;
    let withdraw_args = WithdrawArgs {
        from_subaccount: None,
        to: canister_id,
        created_at_time: None,
        amount: amount.into(),
    };
    update_candid_as::<_, (Result<Nat, WithdrawError>,)>(
        &pic,
        cycles_ledger_id,
        test_identity,
        "withdraw",
        (withdraw_args,),
    )
    .unwrap()
    .0
    .unwrap();

    check_balance(test_identity, 0);
    check_cycles(init_cycles);

    // Withdraw cycles from the anonymous account on the cycles ledger.
    let anonymous_balance = u128::MAX / 2; // hard-coded in PocketIC server
    check_balance(Principal::anonymous(), anonymous_balance);
    let amount = anonymous_balance - CYCLES_LEDGER_FEE;
    let withdraw_args = WithdrawArgs {
        from_subaccount: None,
        to: canister_id,
        created_at_time: None,
        amount: amount.into(),
    };
    update_candid_as::<_, (Result<Nat, WithdrawError>,)>(
        &pic,
        cycles_ledger_id,
        Principal::anonymous(),
        "withdraw",
        (withdraw_args,),
    )
    .unwrap()
    .0
    .unwrap();

    check_balance(Principal::anonymous(), 0);
    check_cycles(init_cycles + anonymous_balance);
}

enum ExchangeRateMode {
    Recent,
    Average,
}

fn get_icp_exchange_rate(pic: &PocketIc, mode: ExchangeRateMode) -> IcpXdrConversionRate {
    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    let method_name = match mode {
        ExchangeRateMode::Recent => "get_icp_xdr_conversion_rate",
        ExchangeRateMode::Average => "get_average_icp_xdr_conversion_rate",
    };
    update_candid::<_, (IcpXdrConversionRateCertifiedResponse,)>(pic, cmc_id, method_name, ())
        .unwrap()
        .0
        .data
}

fn get_authorized_subnets(pic: &PocketIc) -> Vec<Principal> {
    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    update_candid::<_, (Vec<Principal>,)>(pic, cmc_id, "get_default_subnets", ())
        .unwrap()
        .0
}

fn get_subnet_types(pic: &PocketIc) -> BTreeMap<String, Vec<Principal>> {
    let cmc_id = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    update_candid::<_, (SubnetTypesToSubnetsResponse,)>(
        pic,
        cmc_id,
        "get_subnet_types_to_subnets",
        (),
    )
    .unwrap()
    .0
    .data
    .into_iter()
    .map(|(subnet_type, subnet_ids)| {
        (
            subnet_type,
            subnet_ids
                .iter()
                .map(|subnet_id| subnet_id.get().0)
                .collect(),
        )
    })
    .collect()
}

fn check_cmc_state(pic: &PocketIc, expect_fiduciary: bool) {
    // check XDR exchange rate
    // the value is hard-coded in the PocketIC server implementation
    // including steps how it was obtained
    let hardcoded_icp_exchange_rate = 35_200;
    let icp_exchange_rate = get_icp_exchange_rate(pic, ExchangeRateMode::Recent);
    assert_eq!(
        icp_exchange_rate.xdr_permyriad_per_icp,
        hardcoded_icp_exchange_rate
    );
    let average_icp_exchange_rate = get_icp_exchange_rate(pic, ExchangeRateMode::Average);
    assert_eq!(
        average_icp_exchange_rate.xdr_permyriad_per_icp,
        hardcoded_icp_exchange_rate
    );

    // check authorized (application) subnets
    let mut authorized_subnets = get_authorized_subnets(pic);
    authorized_subnets.sort();
    let mut app_subnets = pic.topology().get_app_subnets();
    app_subnets.sort();
    assert_eq!(authorized_subnets, app_subnets);

    // check fiduciary subnet
    assert_eq!(pic.topology().get_fiduciary().is_some(), expect_fiduciary);
    let subnet_types = get_subnet_types(pic);
    let subnet_types_len = if expect_fiduciary { 1 } else { 0 };
    assert_eq!(subnet_types.len(), subnet_types_len);
    let fiduciary_subnet_ids = pic
        .topology()
        .get_fiduciary()
        .map(|subnet_id| vec![subnet_id]);
    assert_eq!(subnet_types.get("fiduciary").cloned(), fiduciary_subnet_ids);
}

#[test]
fn test_cmc_fiduciary_subnet() {
    let icp_features = IcpFeatures {
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_fiduciary_subnet()
        .with_icp_features(icp_features)
        .build();

    check_cmc_state(&pic, true);
}

#[test]
fn test_cmc_fiduciary_subnet_creation() {
    let icp_features = IcpFeatures {
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_icp_features(icp_features)
        .build();

    check_cmc_state(&pic, false);

    create_mainnet_subnet(&pic, 0x23); // fiduciary subnet

    check_cmc_state(&pic, true);
}

#[test]
fn test_cmc_state() {
    let icp_features = IcpFeatures {
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_fiduciary_subnet()
        .with_icp_features(icp_features)
        .with_state(state)
        .build();

    check_cmc_state(&pic, true);

    for i in 1..3 {
        create_mainnet_subnet(&pic, i);
        check_cmc_state(&pic, true);
    }

    // Restart the instance from its state.
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    check_cmc_state(&pic, true);

    for i in 3..5 {
        create_mainnet_subnet(&pic, i);
        check_cmc_state(&pic, true);
    }
}

fn create_mainnet_subnet(pic: &PocketIc, i: u64) {
    // We derive a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    // That "specified" canister ID has the form: <i> 00000 01 01,
    // i.e., it is the first canister ID on the <i>-th subnet.
    let mut slice = [0_u8; 10];
    slice[..8].copy_from_slice(&(i << 20).to_be_bytes());
    slice[8] = 0x01;
    slice[9] = 0x01;
    let specified_id = Principal::from_slice(&slice);
    assert!(pic.get_subnet(specified_id).is_none());

    let num_subnets = pic.topology().subnet_configs.len();

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(canister_id, specified_id);
    pic.get_subnet(specified_id).unwrap();

    assert_eq!(pic.topology().subnet_configs.len(), num_subnets + 1);
}

#[test]
fn registry_after_instance_restart() {
    // Create a PocketIC instance with NNS, SNS, II, fiduciary, bitcoin,
    // 5 application, and 5 system subnets
    // (a sufficiently high number so that the order of their creation
    // is different from the order of their subnet IDs and
    // other hash-based footprints).
    let state = PocketIcState::new();
    let mut builder = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_fiduciary_subnet()
        .with_bitcoin_subnet();
    for _ in 0..5 {
        builder = builder.with_application_subnet();
        builder = builder.with_system_subnet();
    }
    let pic = builder.with_state(state).build();

    // Create 10 more application subnets dynamically after the instance has already been created.
    for i in 1..=10_u64 {
        create_mainnet_subnet(&pic, i);
    }

    // Restart the instance (failures to restore the registry
    // would result in a panic when restarting the instance).
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    // Create 10 more application subnets dynamically after the instance has already been restarted.
    for i in 11..=20_u64 {
        create_mainnet_subnet(&pic, i);
    }

    // Restart the instance (failures to restore the registry
    // would result in a panic when restarting the instance).
    let state = pic.drop_and_take_state().unwrap();
    let _pic = PocketIcBuilder::new().with_state(state).build();
}

fn get_subnet_from_registry(pic: &PocketIc, canister_id: Principal) -> Principal {
    let registry_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    update_candid::<_, (Result<SubnetForCanister, String>,)>(
        pic,
        registry_canister_id,
        "get_subnet_for_canister",
        (GetSubnetForCanisterRequest {
            principal: Some(PrincipalId(canister_id)),
        },),
    )
    .unwrap()
    .0
    .unwrap()
    .subnet_id
    .unwrap()
    .0
}

#[test]
fn read_registry() {
    let icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let state = PocketIcState::new();
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_icp_features(icp_features)
        .with_state(state)
        .build();

    let subnet_0 = pic.topology().get_app_subnets()[0];
    let canister_0 = pic.create_canister_on_subnet(None, None, subnet_0);
    assert_eq!(get_subnet_from_registry(&pic, canister_0), subnet_0);

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_1 = Principal::from_text("v7pvf-xyaaa-aaaao-aaaaa-cai").unwrap();
    assert!(pic.get_subnet(specified_1).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_1 = pic
        .create_canister_with_id(None, None, specified_1)
        .unwrap();
    assert_eq!(canister_1, specified_1);
    let subnet_1 = pic.get_subnet(specified_1).unwrap();
    assert_ne!(subnet_0, subnet_1);

    // Check that the subnet from the registry matches
    // the subnet from the PocketIC topology.
    assert_eq!(get_subnet_from_registry(&pic, canister_1), subnet_1);

    // Restart the instance from its state.
    let state = pic.drop_and_take_state().unwrap();
    let pic = PocketIcBuilder::new().with_state(state).build();

    // Check that the registry contains the expected associations of canisters to subnets.
    assert_eq!(get_subnet_from_registry(&pic, canister_0), subnet_0);
    assert_eq!(get_subnet_from_registry(&pic, canister_1), subnet_1);

    // We define another "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_2 = Principal::from_text("z474k-xiaaa-aaaao-qaaaa-cai").unwrap();

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let canister_2 = pic
        .create_canister_with_id(None, None, specified_2)
        .unwrap();
    assert_eq!(canister_2, specified_2);
    let subnet_2 = pic.get_subnet(specified_2).unwrap();
    assert_ne!(subnet_0, subnet_2);
    assert_ne!(subnet_1, subnet_2);

    // Check that the subnet from the registry matches
    // the subnet from the PocketIC topology.
    assert_eq!(get_subnet_from_registry(&pic, canister_2), subnet_2);
}

#[test]
#[should_panic(
    expected = "The NNS subnet must be empty when specifying the `registry` ICP feature."
)]
fn with_all_icp_features_and_nns_state() {
    let state_dir = TempDir::new().unwrap();
    #[cfg(not(windows))]
    let state_dir_path_buf = state_dir.path().to_path_buf();
    #[cfg(windows)]
    let state_dir_path_buf = windows_to_wsl(state_dir.path().as_os_str().to_str().unwrap())
        .unwrap()
        .into();

    let _pic = PocketIcBuilder::new()
        .with_icp_features(all_icp_features())
        .with_nns_state(state_dir_path_buf)
        .build();
}

#[tokio::test]
async fn with_all_icp_features_and_nns_subnet_state() {
    let state_dir = TempDir::new().unwrap();
    #[cfg(not(windows))]
    let state_dir_path_buf = state_dir.path().to_path_buf();
    #[cfg(windows)]
    let state_dir_path_buf = windows_to_wsl(state_dir.path().as_os_str().to_str().unwrap())
        .unwrap()
        .into();

    let (_, url) = start_server(StartServerParams::default()).await;
    let client = reqwest::Client::new();
    let instance_config = InstanceConfig {
        subnet_config_set: ExtendedSubnetConfigSet {
            nns: Some(SubnetSpec::default().with_state_dir(state_dir_path_buf)),
            ..Default::default()
        },
        http_gateway_config: None,
        state_dir: None,
        icp_config: None,
        log_level: None,
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: Some(all_icp_features()),
        incomplete_state: None,
        initial_time: None,
    };
    let response = client
        .post(url.join("instances").unwrap())
        .json(&instance_config)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.text().await.unwrap().contains("Subnet config failed to validate: The NNS subnet must be empty when specifying the `registry` ICP feature."));
}
