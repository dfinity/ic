use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::E8;
use ic_nns_governance::{
    governance::{test_data::CREATE_SERVICE_NERVOUS_SYSTEM, ONE_DAY_SECONDS, ONE_YEAR_SECONDS},
    pb::v1::{proposal::Action, OpenSnsTokenSwap, Proposal},
};
use ic_sns_root::{CanisterSummary, GetSnsCanistersSummaryResponse};
use ic_sns_swap::pb::v1::{
    GetStateResponse, Init, NeuronBasketConstructionParameters, Params, Swap,
};
use ic_sns_wasm::pb::v1::{
    DeployNewSnsResponse, DeployedSns, ListDeployedSnsesResponse, SnsCanisterIds,
};
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref SNS_SWAP_CANISTER_ID: CanisterId = CanisterId::from_u64(42);
    pub(crate) static ref SNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(43);
    pub(crate) static ref SNS_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(44);
    pub(crate) static ref SNS_ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(45);
    pub(crate) static ref SNS_INDEX_CANISTER_ID: CanisterId = CanisterId::from_u64(46);
    pub(crate) static ref FALLBACK_CONTROLLER_ID: PrincipalId = PrincipalId::new_user_test_id(1);
    pub(crate) static ref LIST_DEPLOYED_SNSES_RESPONSE: ListDeployedSnsesResponse =
        ListDeployedSnsesResponse {
            instances: vec![DeployedSns {
                root_canister_id: Some(SNS_ROOT_CANISTER_ID.get()),
                governance_canister_id: Some(SNS_GOVERNANCE_CANISTER_ID.get()),
                ledger_canister_id: Some(SNS_LEDGER_CANISTER_ID.get()),
                swap_canister_id: Some(SNS_SWAP_CANISTER_ID.get()),
                index_canister_id: Some(SNS_INDEX_CANISTER_ID.get()),
            }],
        };
    pub(crate) static ref GET_STATE_RESPONSE: GetStateResponse = GetStateResponse {
        swap: Some(Swap {
            init: Some(Init {
                sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.get().to_string(),
                sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.get().to_string(),
                sns_root_canister_id: SNS_ROOT_CANISTER_ID.get().to_string(),
                fallback_controller_principal_ids: vec![FALLBACK_CONTROLLER_ID.to_string()],
                transaction_fee_e8s: Some(10_000),
                neuron_minimum_stake_e8s: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    pub(crate) static ref GET_SNS_CANISTERS_SUMMARY_RESPONSE: GetSnsCanistersSummaryResponse =
        GetSnsCanistersSummaryResponse {
            root: Some(CanisterSummary {
                canister_id: Some(SNS_ROOT_CANISTER_ID.get()),
                ..Default::default()
            }),
            governance: Some(CanisterSummary {
                canister_id: Some(SNS_GOVERNANCE_CANISTER_ID.get()),
                ..Default::default()
            }),
            ledger: Some(CanisterSummary {
                canister_id: Some(SNS_LEDGER_CANISTER_ID.get()),
                ..Default::default()
            }),
            swap: Some(CanisterSummary {
                canister_id: Some(SNS_SWAP_CANISTER_ID.get()),
                ..Default::default()
            }),
            index: Some(CanisterSummary {
                canister_id: Some(SNS_INDEX_CANISTER_ID.get()),
                ..Default::default()
            }),
            ..Default::default()
        };
    pub(crate) static ref OPEN_SNS_TOKEN_SWAP_PROPOSAL: Proposal = Proposal {
        title: Some("OSTS Proposal".to_string()),
        summary: "Summary of the proposal".to_string(),
        url: "".to_string(),
        action: Some(Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
            target_swap_canister_id: Some(SNS_SWAP_CANISTER_ID.get()),
            params: Some(Params {
                min_participants: 5,
                min_icp_e8s: 100 * E8,
                max_icp_e8s: 1_000 * E8,
                min_participant_icp_e8s: E8,
                max_participant_icp_e8s: 10 * E8,
                swap_due_timestamp_seconds: ONE_DAY_SECONDS,
                sns_token_e8s: 1_000 * E8,
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 3,
                    dissolve_delay_interval_seconds: ONE_YEAR_SECONDS,
                },),
                sale_delay_seconds: None,
            }),
            community_fund_investment_e8s: Some(0),
        })),
    };
    pub(crate) static ref CREATE_SERVICE_NERVOUS_SYSYEM_PROPOSAL: Proposal = Proposal {
        title: Some("CSNS Proposal".to_string()),
        summary: "Summary of the proposal".to_string(),
        url: "".to_string(),
        action: Some(Action::CreateServiceNervousSystem(
            CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
        ))
    };
    pub static ref DEPLOY_NEW_SNS_REPONSE: DeployNewSnsResponse = DeployNewSnsResponse {
        canisters: Some(SnsCanisterIds {
            root: Some(SNS_ROOT_CANISTER_ID.get()),
            ledger: Some(SNS_LEDGER_CANISTER_ID.get()),
            governance: Some(SNS_GOVERNANCE_CANISTER_ID.get()),
            swap: Some(SNS_SWAP_CANISTER_ID.get()),
            index: Some(SNS_INDEX_CANISTER_ID.get()),
        }),
        ..Default::default()
    };
}
