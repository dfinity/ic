use std::path::PathBuf;

use candid::{CandidType, Decode, Encode, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::CanisterSettings;
use ic_nervous_system_agent::pocketic_impl::PocketIcAgent;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    STARTING_CYCLES_PER_CANISTER, install_canister_on_subnet,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{LEDGER_INDEX_CANISTER_ID, ROOT_CANISTER_ID};
use ic_sns_testing::bootstrap::bootstrap_nns;
use ic_sns_testing::sns::pocket_ic::{create_sns, propose_sns_controlled_canister_upgrade};
use ic_sns_testing::sns::{await_sns_controlled_canister_upgrade, sns_proposal_upvote};
use ic_sns_testing::utils::{
    SnsTestingCanisterValidationError, SnsTestingNetworkValidationError, TREASURY_PRINCIPAL_ID,
    validate_network, validate_target_canister,
};
use icp_ledger::Tokens;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig, InstanceHttpGatewayConfig};
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::{PocketIcBuilder, Time};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const DEV_PARTICIPANT_ID: PrincipalId = PrincipalId::new_user_test_id(1000);

// TODO @rvem: I don't like the fact that this struct definition is copy-pasted from 'canister/canister.rs'.
// We should extract it into a separate crate and reuse in both canister and this crates.
#[derive(CandidType)]
pub struct TestCanisterInitArgs {
    pub greeting: Option<String>,
}

async fn install_test_canister(pocket_ic: &PocketIc, args: TestCanisterInitArgs) -> CanisterId {
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let features = &[];
    let test_canister_wasm =
        Wasm::from_location_specified_by_env_var("sns_testing_canister", features).unwrap();
    install_canister_on_subnet(
        pocket_ic,
        application_subnet_id,
        Encode!(&args).unwrap(),
        Some(test_canister_wasm),
        vec![ROOT_CANISTER_ID.get()],
    )
    .await
}

async fn prepare_network_for_test(
    dev_participant_id: PrincipalId,
    state_dir: PathBuf,
) -> (PocketIc, NeuronId) {
    // Preparing the PocketIC-based network
    let all_icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_minting: Some(IcpFeaturesConfig::DefaultConfig),
        icp_token: Some(IcpFeaturesConfig::DefaultConfig),
        cycles_token: Some(IcpFeaturesConfig::DefaultConfig),
        nns_governance: Some(IcpFeaturesConfig::DefaultConfig),
        sns: Some(IcpFeaturesConfig::DefaultConfig),
        ii: Some(IcpFeaturesConfig::DefaultConfig),
        nns_ui: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir)
        .with_icp_features(all_icp_features)
        .with_initial_time(Time::from_nanos_since_unix_epoch(current_time))
        .with_http_gateway(http_gateway_config)
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let treasury_principal_id = *TREASURY_PRINCIPAL_ID;

    let dev_nns_neuron_id = bootstrap_nns(
        &pocket_ic,
        vec![
            (
                treasury_principal_id,
                Tokens::from_tokens(10_000_000).unwrap(),
            ),
            (dev_participant_id, Tokens::from_tokens(100).unwrap()),
        ],
        dev_participant_id,
    )
    .await;
    assert!(validate_network(&pocket_ic).await.is_empty());
    (pocket_ic, dev_nns_neuron_id)
}

async fn test_canister_query(pocket_ic: &PocketIc, test_canister_id: CanisterId, greeting: String) {
    let test_call_arg = "General Kenobi".to_string();
    let test_canister_response = pocket_ic
        .query_call(
            test_canister_id.into(),
            Principal::anonymous(),
            "greet",
            Encode!(&test_call_arg).unwrap(),
        )
        .await
        .expect("Call to a test canister failed");
    assert_eq!(
        Decode!(&test_canister_response, String).expect("Failed to decode test canister response"),
        format!("{}, {}!", greeting, test_call_arg.clone()),
    );
}

async fn prepare_test_canister(pocket_ic: &PocketIc) -> CanisterId {
    // Installing a test canister
    let greeting = "Hello there".to_string();
    let test_canister_id = install_test_canister(
        pocket_ic,
        TestCanisterInitArgs {
            greeting: Some(greeting.clone()),
        },
    )
    .await;
    assert!(
        validate_target_canister(pocket_ic, test_canister_id)
            .await
            .is_empty()
    );
    test_canister_query(pocket_ic, test_canister_id, greeting).await;
    test_canister_id
}

#[tokio::test]
async fn test_sns_testing_dev_nns_neuron_id() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let dev_participant_id = DEV_PARTICIPANT_ID;

    let (_pocket_ic, dev_nns_neuron_id) =
        prepare_network_for_test(dev_participant_id, state_dir).await;

    // The following NNS neuron ID is hard-coded in sns-testing README.
    // If the test fails, then the README must be updated.
    assert_eq!(dev_nns_neuron_id.id, 3912484856864073044);
}

#[tokio::test]
async fn test_sns_testing_basic_scenario_with_sns_neuron_following() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let dev_participant_id = DEV_PARTICIPANT_ID;

    let (pocket_ic, dev_nns_neuron_id) =
        prepare_network_for_test(dev_participant_id, state_dir).await;

    let test_canister_id = prepare_test_canister(&pocket_ic).await;

    // Creating an SNS
    let (sns, dev_sns_neuron_id) = create_sns(
        &pocket_ic,
        dev_participant_id,
        dev_nns_neuron_id,
        vec![test_canister_id],
        true,
    )
    .await;
    let new_greeting = "Hi".to_string();
    // Upgrading the test canister via SNS voting
    let proposal_id = propose_sns_controlled_canister_upgrade(
        &pocket_ic,
        dev_participant_id,
        dev_sns_neuron_id,
        sns.clone(),
        test_canister_id,
        Wasm::from_location_specified_by_env_var("sns_testing_canister", &[])
            .unwrap()
            .bytes(),
        Some(
            Encode!(&TestCanisterInitArgs {
                greeting: Some(new_greeting.clone()),
            })
            .unwrap(),
        ),
    )
    .await;
    await_sns_controlled_canister_upgrade(&pocket_ic, proposal_id, test_canister_id, sns).await;

    test_canister_query(&pocket_ic, test_canister_id, new_greeting).await;
}

#[tokio::test]
async fn test_sns_testing_basic_scenario_without_sns_neuron_following() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let dev_participant_id = DEV_PARTICIPANT_ID;

    let (pocket_ic, dev_nns_neuron_id) =
        prepare_network_for_test(dev_participant_id, state_dir).await;

    let test_canister_id = prepare_test_canister(&pocket_ic).await;

    // Creating an SNS
    let (sns, dev_sns_neuron_id) = create_sns(
        &pocket_ic,
        dev_participant_id,
        dev_nns_neuron_id,
        vec![test_canister_id],
        false,
    )
    .await;

    let new_greeting = "Hi".to_string();
    // Upgrading the test canister via SNS voting
    let proposal_id = propose_sns_controlled_canister_upgrade(
        &pocket_ic,
        dev_participant_id,
        dev_sns_neuron_id,
        sns.clone(),
        test_canister_id,
        Wasm::from_location_specified_by_env_var("sns_testing_canister", &[])
            .unwrap()
            .bytes(),
        Some(
            Encode!(&TestCanisterInitArgs {
                greeting: Some(new_greeting.clone()),
            })
            .unwrap(),
        ),
    )
    .await;

    sns_proposal_upvote(
        &PocketIcAgent::new(&pocket_ic, Principal::anonymous()),
        sns.governance,
        sns.swap,
        proposal_id.id,
        true,
    )
    .await
    .unwrap();

    await_sns_controlled_canister_upgrade(&pocket_ic, proposal_id, test_canister_id, sns).await;

    test_canister_query(&pocket_ic, test_canister_id, new_greeting).await;
}

#[tokio::test]
pub async fn test_missing_nns_canisters() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let dev_participant_id = PrincipalId::new_user_test_id(1000);

    let (pocket_ic, _dev_nns_neuron_id) =
        prepare_network_for_test(dev_participant_id, state_dir).await;

    // Deleting the ledger-index canister
    pocket_ic
        .stop_canister(
            LEDGER_INDEX_CANISTER_ID.get().into(),
            Some(ROOT_CANISTER_ID.get().into()),
        )
        .await
        .unwrap();
    pocket_ic
        .delete_canister(
            LEDGER_INDEX_CANISTER_ID.get().into(),
            Some(ROOT_CANISTER_ID.get().into()),
        )
        .await
        .unwrap();

    // Assert that the ledger-index canister is missing
    assert_eq!(
        validate_network(&pocket_ic).await,
        vec![SnsTestingNetworkValidationError::MissingNnsCanister(
            "ledger-index".to_string(),
        )]
    )
}

#[tokio::test]
pub async fn test_non_installed_target_canister() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let canister_id = pocket_ic
        .create_canister_on_subnet(
            None,
            Some(CanisterSettings {
                controllers: Some(vec![ROOT_CANISTER_ID.get().into()]),
                ..Default::default()
            }),
            application_subnet_id,
        )
        .await;
    pocket_ic
        .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    let canister_id = CanisterId::unchecked_from_principal(canister_id.into());
    assert_eq!(
        validate_target_canister(&pocket_ic, canister_id).await,
        vec![SnsTestingCanisterValidationError::CanisterNotInstalled(
            canister_id
        )],
    )
}

#[tokio::test]
pub async fn test_nonexisting_target_canister() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let canister_id = CanisterId::unchecked_from_principal(PrincipalId::new_user_test_id(1000));
    assert!(match validate_target_canister(&pocket_ic, canister_id)
        .await
        .as_slice()
    {
        [SnsTestingCanisterValidationError::FailedToGetCanisterInfo(err_canister_id, _)] => {
            err_canister_id == &canister_id
        }
        _ => false,
    })
}

#[tokio::test]
pub async fn test_target_canister_not_controlled_by_nns_root() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids[0];
    let test_canister_wasm = Wasm::from_bytes([0, 0x61, 0x73, 0x6D, 1, 0, 0, 0]);
    let canister_controller = PrincipalId::new_user_test_id(1000);
    let canister_id = install_canister_on_subnet(
        &pocket_ic,
        application_subnet_id,
        vec![],
        Some(test_canister_wasm),
        vec![canister_controller],
    )
    .await;
    assert_eq!(
        validate_target_canister(&pocket_ic, canister_id).await,
        vec![SnsTestingCanisterValidationError::CanisterNotControlledByNnsRoot(canister_id)]
    )
}
