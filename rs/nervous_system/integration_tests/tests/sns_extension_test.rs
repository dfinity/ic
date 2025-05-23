use candid::{CandidType, Nat, Principal};
use canister_test::Wasm;
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
use ic_nns_governance::pb::v1::RewardEvent;
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

    // Step 1. Add the SNS token.
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

    // Step 2: Add the ICP token to the KongSwap canister.
    // Notes on why we first add SNS and then ICP:
    // - KongSwap starts indexing the tokens from 1.
    // - The ICP token is assumed to have index 2.
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

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            TokensArgs { symbol: None },
        )
        .await
        .unwrap()
        .unwrap();
    println!("first tokens response = {:#?}", response);

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            PoolsArgs { symbol: None },
        )
        .await
        .unwrap()
        .unwrap();
    println!("first pools response = {:#?}", response);

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
    sns::ledger::icrc1_transfer(&pocket_ic, sns_ledger_canister_id.get(), sns_root_canister_id, TransferArg {
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

                token_1: "ICP".to_string(),
                amount_1: Nat::from(50 * E8),
                tx_id_1: None,

                lp_fee_bps: Some(10),
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("add_pool response = {:#?}", response);

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            TokensArgs { symbol: None },
        )
        .await
        .unwrap()
        .unwrap();
    println!("second tokens response = {:#?}", response);

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            PoolsArgs { symbol: None },
        )
        .await
        .unwrap()
        .unwrap();
    println!("second pools response = {:#?}", response);

    // Step 2: Increase the liquidity allocation.
    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            AddLiquidityAmountsArgs {
                token_0: "SNS".to_string(),
                amount: Nat::from(140 * E8),
                token_1: "ICP".to_string(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("add_liquidity_amounts response = {:#?}", response);

    let response = lp_adaptor_agent.call(
        kong_backend_canister_id,
        AddLiquidityArgs {
            token_0: "SNS".to_string(),
            amount_0: Nat::from(140 * E8),
            tx_id_0: None,

            token_1: "ICP".to_string(),
            amount_1: response.amount_1,
            tx_id_1: None,
        },
    )
    .await
    .unwrap()
    .unwrap();
    println!("add liquidity response = {:#?}", response);

    // Attempt to withdraw all the liquidity.

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            UserBalancesArgs {
                principal_id: lp_adaptor_canister_id.0.to_string(),
            },
        )
        .await
        .unwrap()
        .unwrap()
        [0]
        .clone();

    println!("user balances response = {:#?}", response);

    let remove_lp_token_amount = match response {
        UserBalancesReply::LP(response) => {
            kong_lp_balance_to_demilams(response.balance).unwrap()
        },
        _ => panic!("Unexpected response type"),
    };

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            RemoveLiquidityAmountsArgs {
                token_0: "SNS".to_string(),
                token_1: "ICP".to_string(),
                remove_lp_token_amount,
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("remove_liquidity_amounts response = {:#?}", response);

    let response = lp_adaptor_agent
        .call(
            kong_backend_canister_id,
            RemoveLiquidityArgs {
                token_0: "SNS".to_string(),
                token_1: "ICP".to_string(),
                remove_lp_token_amount: response.remove_lp_token_amount,
            },
        )
        .await
        .unwrap()
        .unwrap();
    println!("remove liquidity response = {:#?}", response);

    panic!();
}

// ----------------- begin:add_liquidity_amounts -----------------
impl Request for AddLiquidityAmountsArgs {
    fn method(&self) -> &'static str {
        "add_liquidity_amounts"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        let Self {
            token_0,
            amount,
            token_1,
        } = self.clone();

        candid::encode_args((token_0, amount, token_1))
    }

    type Response = Result<AddLiquidityAmountsReply, String>;
}

fn kong_lp_balance_to_demilams(
    lp_balance: f64,
) -> Result<Nat, String> {
    // Check that lp_balance is valid before conversion
    if !lp_balance.is_finite() || lp_balance < 0.0 {
        return Err("Invalid LP balance value".to_string());
    }

    // Calculate with overflow checking
    let e8_value = E8 as f64;
    let result_f64 = lp_balance * e8_value;

    // Ensure the result fits in u64 range
    if result_f64 > u64::MAX as f64 {
        return Err("LP balance conversion exceeds u64 maximum".to_string());
    }

    // Convert to Nat (safe because we've checked the bounds)
    Ok(Nat::from(result_f64.round() as u64))
}

#[derive(CandidType, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AddLiquidityAmountsArgs {
    pub token_0: String,
    pub amount: Nat,
    pub token_1: String,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityAmountsReply {
    pub symbol: String,
    pub chain_0: String,
    pub address_0: String,
    pub symbol_0: String,
    pub amount_0: Nat,
    pub fee_0: Nat,
    pub chain_1: String,
    pub address_1: String,
    pub symbol_1: String,
    pub amount_1: Nat,
    pub fee_1: Nat,
    pub add_lp_token_amount: Nat,
}
// ----------------- end:add_liquidity_amounts -----------------

// ----------------- begin:add_liquidity -----------------
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
// ----------------- end:add_liquidity -----------------

// ----------------- begin:add_token -----------------
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

// Arguments for adding a token.
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
// ----------------- end:add_token -----------------

// ----------------- begin:add_pool -----------------
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

// ----------------- begin:tokens -----------------
impl Request for TokensArgs {    
    fn method(&self) -> &'static str {
        "tokens"
    }
    
    fn update(&self) -> bool {
        false
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self.symbol.clone())
    }
    
    type Response = Result<Vec<TokensReply>, String>;
}

struct TokensArgs {
    pub symbol: Option<String>,
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub enum TokensReply {
    LP(LPReply),
    IC(ICReply),
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub struct LPReply {
    pub token_id: u32,
    pub chain: String,
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub pool_id_of: u32,
    pub decimals: u8,
    pub fee: Nat,
    pub total_supply: Nat,
    pub is_removed: bool,
}
// ----------------- end:tokens -----------------

// ----------------- begin:tokens -----------------
impl Request for PoolsArgs {    
    fn method(&self) -> &'static str {
        "pools"
    }
    
    fn update(&self) -> bool {
        false
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self.symbol.clone())
    }
    
    type Response = Result<Vec<PoolReply>, String>;
}

struct PoolsArgs {
    pub symbol: Option<String>,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct PoolReply {
    pub pool_id: u32,
    pub name: String,
    pub symbol: String,
    pub chain_0: String,
    pub symbol_0: String,
    pub address_0: String,
    pub balance_0: Nat,
    pub lp_fee_0: Nat,
    pub chain_1: String,
    pub symbol_1: String,
    pub address_1: String,
    pub balance_1: Nat,
    pub lp_fee_1: Nat,
    pub price: f64,
    pub lp_fee_bps: u8,
    pub lp_token_symbol: String,
    pub is_removed: bool,
}
// ----------------- end:tokens -----------------

// ----------------- begin:remove_liquidity_amounts -----------------
impl Request for RemoveLiquidityAmountsArgs {    
    fn method(&self) -> &'static str {
        "remove_liquidity_amounts"
    }
    
    fn update(&self) -> bool {
        false
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        let Self {
            token_0,
            token_1,
            remove_lp_token_amount,
        } = self;

        candid::encode_args((token_0, token_1, remove_lp_token_amount))
    }
    
    type Response = Result<RemoveLiquidityAmountsReply, String>;
}

struct RemoveLiquidityAmountsArgs {
    pub token_0: String,
    pub token_1: String,
    pub remove_lp_token_amount: Nat,
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub struct RemoveLiquidityAmountsReply {
    pub symbol: String,
    pub chain_0: String,
    pub address_0: String,
    pub symbol_0: String,
    pub amount_0: Nat,
    pub lp_fee_0: Nat,
    pub chain_1: String,
    pub address_1: String,
    pub symbol_1: String,
    pub amount_1: Nat,
    pub lp_fee_1: Nat,
    pub remove_lp_token_amount: Nat,
}
// ----------------- end:remove_liquidity_amounts -----------------

// ----------------- begin:liquidity_amounts -----------------
impl Request for RemoveLiquidityArgs {    
    fn method(&self) -> &'static str {
        "remove_liquidity"
    }
    
    fn update(&self) -> bool {
        true
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }
    
    type Response = Result<RemoveLiquidityReply, String>;
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct RemoveLiquidityReply {
    pub tx_id: u64,
    pub request_id: u64,
    pub status: String,
    pub symbol: String,
    pub chain_0: String,
    pub address_0: String,
    pub symbol_0: String,
    pub amount_0: Nat,
    pub lp_fee_0: Nat,
    pub chain_1: String,
    pub address_1: String,
    pub symbol_1: String,
    pub amount_1: Nat,
    pub lp_fee_1: Nat,
    pub remove_lp_token_amount: Nat,
    pub transfer_ids: Vec<TransferIdReply>,
    pub claim_ids: Vec<u64>,
    pub ts: u64,
}

#[derive(CandidType, Debug, Clone, Serialize, Deserialize)]
pub struct RemoveLiquidityArgs {
    pub token_0: String,
    pub token_1: String,
    pub remove_lp_token_amount: Nat,
}
// ----------------- end:liquidity_amounts -----------------

// ----------------- begin:user_balances -----------------
impl Request for UserBalancesArgs {    
    fn method(&self) -> &'static str {
        "user_balances"
    }
    
    fn update(&self) -> bool {
        false
    }
    
    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self.principal_id.clone())
    }
    
    type Response = Result<Vec<UserBalancesReply>, String>;
}

struct UserBalancesArgs {
    pub principal_id: String,
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub enum UserBalancesReply {
    LP(UserBalanceLPReply),
}

#[derive(CandidType, Clone, Debug, Serialize, Deserialize)]
pub struct UserBalanceLPReply {
    pub symbol: String,
    pub name: String,
    pub lp_token_id: u64,
    pub balance: f64,
    pub usd_balance: f64,
    pub chain_0: String,
    pub symbol_0: String,
    pub address_0: String,
    pub amount_0: f64,
    pub usd_amount_0: f64,
    pub chain_1: String,
    pub symbol_1: String,
    pub address_1: String,
    pub amount_1: f64,
    pub usd_amount_1: f64,
    pub ts: u64,
}

// ----------------- end:user_balances -----------------