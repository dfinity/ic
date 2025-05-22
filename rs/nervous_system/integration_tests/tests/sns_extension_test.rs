use candid::{CandidType, Nat, Principal};
use canister_test::{Project, Wasm};
use ic_base_types::CanisterId;
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_nervous_system_agent::{
    helpers::await_with_timeout, nns::{
        governance::{add_sns_wasm, insert_sns_wasm_upgrade_path_entries},
        sns_wasm::get_next_sns_version,
    }, pocketic_impl::PocketIcAgent, CallCanisters, Request
};
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_canister_on_subnet, sns::{
    self,
    governance::{
        redact_human_readable, set_automatically_advance_target_version_flag,
        EXPECTED_UPGRADE_DURATION_MAX_SECONDS, EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS,
    },
}};
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{add_wasms_to_sns_wasm, nns},
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_test_utils::sns_wasm::{
    build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm, create_modified_sns_wasm, ensure_sns_wasm_gzipped,
};
use ic_sns_governance::governance::{
    UPGRADE_PERIODIC_TASK_LOCK_TIMEOUT_SECONDS, UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS,
};
use ic_sns_governance_api::pb::v1::upgrade_journal_entry::Event;
use ic_sns_governance_api::{
    pb::v1::{governance::Version, upgrade_journal_entry::TargetVersionReset},
    serialize_journal_entries,
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_wasm::pb::v1::{SnsCanisterType, SnsUpgrade, SnsVersion, SnsWasm};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_base_types::PrincipalId;
use icp_ledger::{AccountIdentifier, Tokens, TransferArgs, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::{icrc1::{account::Account, transfer::TransferArg}, icrc2::approve::ApproveArgs};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use serde::{Deserialize, Serialize};

/// Wraps `pocket_ic` into an agent to use when more authority is required (e.g., making proposals).
///
/// Returns the agent and ID of a neuron controlled by this agent.
fn nns_agent(pocket_ic: &PocketIc) -> (PocketIcAgent, NeuronId) {
    let nns_neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };

    let sender = Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL);
    (PocketIcAgent { pocket_ic, sender }, nns_neuron_id)
}

const DUMMY_URL_FOR_PROPOSALS: &str = "https://forum.dfinity.org";

#[tokio::test]
async fn test() {
    test_custom_upgrade_path_for_sns().await
}

/// This test demonstrates how an SNS can be recovered if, for some reason, an upgrade along
/// the path of blessed SNS framework canister versions is failing. In that case, it should be
/// possible to create a *custom path* that is applicable only to that SNS to recover it.
///
/// Example:
///
/// Normal path: (Deployed) ---> +root (broken) ---> +root (fixed)  ---> +ledger ---> +swap (Last)
///                        \                                                   /
/// Custom path:             ------> +ledger ------> +root (fixed) -----------
///
/// Note that only Wasms published via `NnsFunction::AddSnsWasm` can be referred to from the custom
/// upgrade path, which leaves us with only two possible customizations:
/// 1. Hop over some upgrade.
/// 2. Switch the order of upgrades.
///
/// We use this fairly complex custom upgrade path in this test to illustrate both of these cases.
async fn test_custom_upgrade_path_for_sns() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    let fiduciary_subnet_id = topology.get_fiduciary().unwrap();
    let sns_subnet_id = topology.get_sns().unwrap();

    // Step 0: Prepare the world.

    // Step 0.0: Install the NNS WASMs built from the working copy.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.install(&pocket_ic).await;

    // Step 0.1: Publish (master) SNS Wasms to SNS-W.
    // let with_mainnet_sns_canisters = false;
    // add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
    //     .await
    //     .unwrap();
    // let initial_sns_version = nns::sns_wasm::get_latest_sns_version(&pocket_ic).await;

    // Step 0.2: Deploy an SNS instance via proposal.
    // let sns = {
    //     let create_service_nervous_system = CreateServiceNervousSystemBuilder::default().build();
    //     let swap_parameters = create_service_nervous_system
    //         .swap_parameters
    //         .clone()
    //         .unwrap();

    //     let sns_instance_label = "1";
    //     let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
    //         &pocket_ic,
    //         create_service_nervous_system,
    //         sns_instance_label,
    //     )
    //     .await;

    //     sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
    //         .await
    //         .unwrap();
    //     sns::swap::smoke_test_participate_and_finalize(
    //         &pocket_ic,
    //         sns.swap.canister_id,
    //         swap_parameters,
    //     )
    //     .await;

    //     sns
    // };

    let lp_adaptor_canister_id = PrincipalId::new_user_test_id(444);
    let lp_adaptor_agent = PocketIcAgent {
        pocket_ic: &pocket_ic,
        sender: lp_adaptor_canister_id.0,
    };

    let sns_root_canister_id = PrincipalId::new_user_test_id(123);

    // Install the SNS ledger (normally, this is part of the SNS deployment).
    let sns_ledger_canister_id = {
        let wasm_path = std::env::var("IC_ICRC1_LEDGER_WASM_PATH")
            .expect("IC_ICRC1_LEDGER_WASM_PATH must be set.");

        let icrc1_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![sns_root_canister_id];

        let arg = InitArgsBuilder::with_symbol_and_name("SNS", "My DAO Token")
            .with_minting_account(Account {
                owner: sns_root_canister_id.0,
                subaccount: None,
            })
            .build();

        let arg = LedgerArgument::Init(arg);

        let arg = candid::encode_one(&arg).unwrap();

        install_canister_on_subnet(
            &pocket_ic,
            sns_subnet_id,
            arg,
            Some(icrc1_wasm),
            controllers,
        ).await
    };

    // Install KongSwap
    let kong_backend_canister_id = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");

        let kong_backend_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![
            PrincipalId::new_user_test_id(42)
        ];

        install_canister_on_subnet(
            &pocket_ic,
            fiduciary_subnet_id,
            vec![],
            Some(kong_backend_wasm),
            controllers,
        ).await
    };

    

    // Step 1: Add the ICP token to the KongSwap canister.
    {
        let response = lp_adaptor_agent.call(
            kong_backend_canister_id,
            AddTokenArgs {
                token: "IC.ryjl3-tyaaa-aaaaa-aaaba-cai".to_string(),
            },
        ).await
        .unwrap()
        .unwrap();

        println!("add_token(ICP) response = {:#?}", response);
    }

    // Add the SNS token.
    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            AddTokenArgs {
                token: format!("IC.{}", sns_ledger_canister_id),
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("add_token(SNS) response = {:#?}", response);

    // Approve some ICP from the LP Adaptor.
    let starting_icp_amount = Tokens::from_tokens(100).unwrap();

    nns::ledger::mint_icp(
        &pocket_ic,
        AccountIdentifier::new(lp_adaptor_canister_id, None),
        starting_icp_amount.saturating_add(DEFAULT_TRANSFER_FEE),
        None,
    )
    .await;

    // Approve some SNS tokens from the LP Adaptor.
    let response = sns::ledger::icrc1_transfer(&pocket_ic, sns_ledger_canister_id.get(), sns_root_canister_id, TransferArg {
        from_subaccount: None,
        to: Account {
            owner: lp_adaptor_canister_id.0,
            subaccount: None,
        },
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(350 * E8),
    }).await;
    println!("sns_ledger mint response = {:#?}", response);

    // Set up the ICP allowance.
    lp_adaptor_agent
        .call(
            LEDGER_CANISTER_ID,
            ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: kong_backend_canister_id.get().0,
                    subaccount: None,
                },
                amount: Nat::from(600 * E8),
                expected_allowance: Some(Nat::from(0u8)),
                expires_at: Some(u64::MAX),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    // Set up the SNS allowance.
    lp_adaptor_agent
        .call(
            sns_ledger_canister_id,
            ApproveArgs {
                from_subaccount: None,
                spender: Account {
                    owner: kong_backend_canister_id.get().0,
                    subaccount: None,
                },
                amount: Nat::from(3500 * E8),
                expected_allowance: Some(Nat::from(0u8)),
                expires_at: Some(u64::MAX),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                memo: None,
                created_at_time: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    // Add the ICP:SNS pool with some initial liquidity.
    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            AddPoolArgs {
                token_0: "SNS".to_string(),
                amount_0: Nat::from(200 * E8),
                tx_id_0: None,
                token_1: "ksICP".to_string(),
                amount_1: Nat::from(50 * E8),
                tx_id_1: None,
                lp_fee_bps: Some(10),
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("add_pool response = {:#?}", response);

    // Step 2: Double the liquidity
    let response = lp_adaptor_agent.call(
        kong_backend_canister_id,
        AddLiquidityArgs {
            token_0: "SNS".to_string(),
            amount_0: Nat::from(200 * E8),
            tx_id_0: None,
            token_1: "ksICP".to_string(),
            amount_1: Nat::from(50 * E8),
            tx_id_1: None,
        },
    )
    .await
    .unwrap()
    .unwrap();
    println!("add liquidity response = {:#?}", response);

    panic!();
}

/// ----------------- begin:add_liquidity -----------------
impl Request for AddLiquidityArgs {    
    fn method(&self) -> &'static str {
        "add_liquidity"
    }
    
    fn update(&self) -> bool {
        true
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }
    
    type Response = Result<AddLiquidityReply, String>;    
}

#[derive(CandidType, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxId {
    BlockIndex(Nat),
    TransactionHash(String),
}

/// Data structure for the arguments of the `add_liquidity` function.
/// Used in StableRequest
#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityArgs {
    pub token_0: String,
    pub amount_0: Nat,
    pub tx_id_0: Option<TxId>,
    pub token_1: String,
    pub amount_1: Nat,
    pub tx_id_1: Option<TxId>,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityReply {
    pub tx_id: u64,
    pub request_id: u64,
    pub status: String,
    pub symbol: String,
    pub chain_0: String,
    pub address_0: String,
    pub symbol_0: String,
    pub amount_0: Nat,
    pub chain_1: String,
    pub address_1: String,
    pub symbol_1: String,
    pub amount_1: Nat,
    pub add_lp_token_amount: Nat,
    pub transfer_ids: Vec<TransferIdReply>,
    pub claim_ids: Vec<u64>,
    pub ts: u64,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct TransferIdReply {
    pub transfer_id: u64,
    pub transfer: TransferReply,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub enum TransferReply {
    IC(ICTransferReply),
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct ICTransferReply {
    pub chain: String,
    pub symbol: String,
    pub is_send: bool, // from user's perspective. so if is_send is true, it means the user is sending the token
    pub amount: Nat,
    pub canister_id: String,
    pub block_index: Nat,
}
/// ----------------- end:add_liquidity -----------------

/// ----------------- begin:add_token -----------------
impl Request for AddTokenArgs {    
    fn method(&self) -> &'static str {
        "add_token"
    }
    
    fn update(&self) -> bool {
        true
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }
    
    type Response = Result<AddTokenReply, String>;
}

/// Arguments for adding a token.
#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddTokenArgs {
    pub token: String,
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub enum AddTokenReply {
    IC(ICReply),
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub struct ICReply {
    pub token_id: u32,
    pub chain: String,
    pub canister_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub fee: Nat,
    pub icrc1: bool,
    pub icrc2: bool,
    pub icrc3: bool,
    pub is_removed: bool,
}
/// ----------------- end:add_token -----------------

/// ----------------- begin:add_pool -----------------
impl Request for AddPoolArgs {    
    fn method(&self) -> &'static str {
        "add_pool"
    }
    
    fn update(&self) -> bool {
        true
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }
    
    type Response = Result<AddPoolReply, String>;
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddPoolReply {
    pub tx_id: u64,
    pub pool_id: u32,
    pub request_id: u64,
    pub status: String,
    pub name: String,
    pub symbol: String,
    pub chain_0: String,
    pub address_0: String,
    pub symbol_0: String,
    pub amount_0: Nat,
    pub balance_0: Nat,
    pub chain_1: String,
    pub address_1: String,
    pub symbol_1: String,
    pub amount_1: Nat,
    pub balance_1: Nat,
    pub lp_fee_bps: u8,
    pub lp_token_symbol: String,
    pub add_lp_token_amount: Nat,
    pub transfer_ids: Vec<TransferIdReply>,
    pub claim_ids: Vec<u64>,
    pub is_removed: bool,
    pub ts: u64,
}

/// Data structure for the arguments of the `add_pool` function.
/// Used in StableRequest
#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddPoolArgs {
    pub token_0: String,
    pub amount_0: Nat,
    pub tx_id_0: Option<TxId>,
    pub token_1: String,
    pub amount_1: Nat,
    pub tx_id_1: Option<TxId>,
    pub lp_fee_bps: Option<u8>,
}
// ----------------- end:add_pool -----------------
