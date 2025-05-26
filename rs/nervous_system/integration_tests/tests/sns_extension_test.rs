use std::collections::BTreeMap;

use candid::{CandidType, Nat, Principal};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_nervous_system_agent::{
    pocketic_impl::PocketIcAgent,
    CallCanisters, Request,
};
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_canister_on_subnet, sns};
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::LEDGER_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Tokens, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::approve::ApproveArgs,
};
use itertools::{Either, Itertools};
use maplit::btreemap;
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use serde::{Deserialize, Serialize};

// TODO
// use thiserror::Error

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

pub struct Allowance {
    pub amount_decimals: Nat,
    pub ledger_canister_id: CanisterId,
}

pub trait LpAdaptor {
    fn balances(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeMap<String, Nat>, String>> + Send;

    fn withdraw(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send;

    fn deposit(
        &mut self,
        allowances: Vec<Allowance>,
    ) -> impl std::future::Future<Output = Result<Vec<Allowance>, String>> + Send;

    fn audit_trail(&self) -> AuditTrail;
}

#[derive(Clone, Debug)]
pub enum TransactionError {
    CallFailed(String),
    BackendError(String),
}

#[derive(Clone, Debug)]
pub struct Transaction {
    ledger_canister_id: CanisterId,
    /// Ok result contains block indices of the relevant ledger transactions.
    result: Result<Vec<Nat>, TransactionError>,
    human_readable: String,
    timestamp_seconds: u64,
    treasury_operation_phase: TreasuryOperationPhase,
}

#[derive(Clone, Debug)]
pub enum TreasuryOperationPhase {
    Deposit,
    Balances,
    IssueReward,
    Withdraw,
}

#[derive(Clone, Debug)]
pub struct AuditTrail {
    events: Vec<Transaction>,
}

impl AuditTrail {
    pub fn new() -> Self {
        AuditTrail { events: vec![] }
    }

    fn record_event(&mut self, event: Transaction) {
        self.events.push(event);
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.events
    }
}

pub struct KongSwapAdaptor<'a> {
    agent: &'a PocketIcAgent<'a>,
    kong_backend_canister_id: CanisterId,

    token_0: String,
    token_1: String,

    audit_trail: AuditTrail,
}

pub trait WithBlockIndices {
    fn block_indices(&self) -> Vec<Nat>;
}

impl<'a> KongSwapAdaptor<'a> {
    fn new(
        agent: &'a PocketIcAgent<'a>,
        kong_backend_canister_id: CanisterId,
        token_0: String,
        token_1: String,
    ) -> Result<Self, String> {
        if token_0 == token_1 {
            return Err("token_0 and token_1 must be different".to_string());
        }

        if token_1 != "ICP" {
            return Err("token_1 must be ICP".to_string());
        }

        let audit_trail = AuditTrail::new();

        Ok(KongSwapAdaptor {
            agent,
            kong_backend_canister_id,
            token_0,
            token_1,
            audit_trail,
        })
    }

    async fn emit_transaction<R, Ok>(
        &mut self,
        ledger_canister_id: CanisterId,
        request: R,
        phase: TreasuryOperationPhase,
        human_readable: String,
        now_seconds_fn: impl Fn() -> u64,
    ) -> Result<Ok, TransactionError>
    where
        R: Request,
        Ok: WithBlockIndices + Clone,
        Result<Ok, String>: From<R::Response>,
    {
        let response = self.agent
            .call(ledger_canister_id, request)
            .await;

        let result = match response {
            Err(err) => Err(TransactionError::CallFailed(err.to_string())),
            Ok(response) => {
                Result::<Ok, String>::from(response)
                    .map_err(|err| TransactionError::BackendError(err.to_string()))
            }
        };
        
        let transaction = Transaction {
            ledger_canister_id,
            result: result.clone().map(|ok| ok.block_index()),
            human_readable,
            timestamp_seconds: now_seconds_fn(),
            treasury_operation_phase: phase,
        };

        self.audit_trail.record_event(transaction);

        result
    }

    async fn maybe_add_token(&self, ledger_canister_id: CanisterId) -> Result<(), String> {
        let token = format!("IC.{}", ledger_canister_id);

        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                AddTokenArgs {
                    token: token.clone(),
                },
            )
            .await;

        let Ok(response) = response else {
            return Err(format!("Failed to add token: {:?}", response));
        };

        match response {
            Ok(_) => Ok(()),
            Err(err) if err == format!("Token {} already exists", token) => Ok(()),
            Err(err) => Err(err),
        }
    }

    async fn lp_balance(&self) -> Result<Nat, String> {
        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                UserBalancesArgs {
                    principal_id: self.agent.sender.to_string(),
                },
            )
            .await;

        let Ok(Ok(user_balance_replies)) = response else {
            return Err(format!("Failed to get balances: {:?}", response));
        };

        let (balances, errors): (BTreeMap<_, _>, Vec<_>) =
            user_balance_replies.into_iter().partition_map(
                |UserBalancesReply::LP(UserBalanceLPReply {
                     symbol, balance, ..
                 })| {
                    match kong_lp_balance_to_demilams(balance) {
                        Ok(balance) => Either::Left((symbol, balance)),
                        Err(err) => Either::Right(format!(
                            "Failed to convert balance for {}: {}",
                            symbol, err
                        )),
                    }
                },
            );

        if !errors.is_empty() {
            return Err(format!(
                "Failed to convert balances: {:?}",
                errors.join(", ")
            ));
        }

        let lp_token = format!("{}_{}", self.token_0, self.token_1);

        let Some((_, balance)) = balances.into_iter().find(|(token, _)| *token == lp_token) else {
            return Err(format!("Failed to get LP balance for {}.", lp_token));
        };

        Ok(balance)
    }
}

impl<'a> LpAdaptor for KongSwapAdaptor<'a> {
    async fn deposit(
        &mut self,
        mut allowances: Vec<Allowance>,
    ) -> Result<Vec<Allowance>, String> {
        // Check preconditions.
        let Some(Allowance {
            amount_decimals: amount_1,
            ledger_canister_id: ledger_1,
        }) = allowances.pop()
        else {
            return Err(format!("KongSwapAdaptor requires some allowances."));
        };

        if ledger_1 != LEDGER_CANISTER_ID {
            return Err("KongSwapAdaptor only supports ICP as token_1".to_string());
        }

        let Some(Allowance {
            amount_decimals: amount_0,
            ledger_canister_id: ledger_0,
        }) = allowances.pop()
        else {
            return Err(format!(
                "KongSwapAdaptor requires two allowances (got {})",
                allowances.len()
            ));
        };

        if !allowances.is_empty() {
            return Err(format!(
                "KongSwapAdaptor requires exactly two allowances (got {})",
                allowances.len()
            ));
        }

        // Notes on why we first add SNS and then ICP:
        // - KongSwap starts indexing the tokens from 1.
        // - The ICP token is assumed to have index 2.
        self.maybe_add_token(ledger_0).await?;
        self.maybe_add_token(ledger_1).await?;

        let token_0 = format!("IC.{}", ledger_0);
        let token_1 = format!("IC.{}", ledger_1);

        let original_amount_1 = amount_1.clone();

        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                AddPoolArgs {
                    token_0: token_0.clone(),
                    amount_0: amount_0.clone(),
                    token_1: token_1.clone(),
                    amount_1,

                    // Liquidity provider fee in basis points 30=0.3%.
                    lp_fee_bps: Some(30),

                    // Not needed for the ICRC2 flow.
                    tx_id_0: None,
                    tx_id_1: None,
                },
            )
            .await;

        let Ok(response) = response else {
            return Err(format!("Failed to add pool: {:?}", response));
        };

        let lp_token = format!("{}_{}", self.token_0, self.token_1);

        let pool_already_exists = format!("Pool {} already exists", lp_token);

        match &response {
            Ok(_) => {
                // All used up, since the pool is brand new.
                return Ok(vec![
                    Allowance {
                        amount_decimals: Nat::from(0_u64),
                        ledger_canister_id: ledger_0,
                    },
                    Allowance {
                        amount_decimals: Nat::from(0_u64),
                        ledger_canister_id: ledger_1,
                    },
                ]);
            }
            Err(err) if *err != pool_already_exists => {
                return Err(format!("Failed to add pool: {:?}", err));
            }
            Err(_) => (),
        }

        // This is a top-up operation for a pre-existing pool.
        // A top-up requires computing amount_1 as a function of amount_0.
        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                AddLiquidityAmountsArgs {
                    token_0: token_0.clone(),
                    amount: amount_0.clone(),
                    token_1: token_1.clone(),
                },
            )
            .await;

        let Ok(Ok(AddLiquidityAmountsReply { amount_1, .. })) = response else {
            return Err(format!(
                "Failed to estimate how much liquidity can be added: {:?}",
                response
            ));
        };

        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                AddLiquidityArgs {
                    token_0,
                    amount_0,
                    token_1,
                    amount_1,

                    // Not needed for the ICRC2 flow.
                    tx_id_0: None,
                    tx_id_1: None,
                },
            )
            .await;

        let Ok(Ok(AddLiquidityReply {
            amount_0, amount_1, ..
        })) = response
        else {
            return Err(format!("Failed to top up liquidity: {:?}", response));
        };

        if original_amount_1 < amount_1 {
            return Err(format!(
                "Got top-up amount_1 = {} (must be at least {})",
                original_amount_1, amount_1
            ));
        }

        Ok(vec![
            Allowance {
                amount_decimals: amount_0,
                ledger_canister_id: ledger_0,
            },
            Allowance {
                // TODO: Use safe arithmetic to avoid overflow.
                amount_decimals: original_amount_1 - amount_1,
                ledger_canister_id: ledger_1,
            },
        ])
    }

    async fn balances(&self) -> Result<BTreeMap<String, Nat>, String> {
        let remove_lp_token_amount = self.lp_balance().await?;

        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                RemoveLiquidityAmountsArgs {
                    token_0: self.token_0.clone(),
                    token_1: self.token_1.clone(),
                    remove_lp_token_amount,
                },
            )
            .await;

        let Ok(Ok(RemoveLiquidityAmountsReply {
            amount_0,
            amount_1,
            symbol_0,
            symbol_1,
            ..
        })) = response
        else {
            return Err(format!(
                "Failed to estimate how much liquidity can be removed: {:?}",
                response
            ));
        };

        Ok(btreemap! {
            symbol_0 => amount_0,
            symbol_1 => amount_1,
        })
    }

    async fn withdraw(&mut self) -> Result<(), String> {
        let remove_lp_token_amount = self.lp_balance().await?;

        let response = self
            .agent
            .call(
                self.kong_backend_canister_id,
                RemoveLiquidityArgs {
                    token_0: self.token_0.clone(),
                    token_1: self.token_1.clone(),
                    remove_lp_token_amount,
                },
            )
            .await;

        let Ok(Ok(RemoveLiquidityReply { status, .. })) = response else {
            return Err(format!("Failed to request to withdraw: {:?}", response));
        };

        if status != "Success" {
            return Err(format!("Failed to withdraw, status: {:?}", status));
        }

        Ok(())
    }
    
    fn audit_trail(&self) -> AuditTrail {
        self.audit_trail.clone()
    }
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
        )
        .await
    };

    // Install KongSwap
    let kong_backend_canister_id = {
        let wasm_path = std::env::var("KONG_BACKEND_CANISTER_WASM_PATH")
            .expect("KONG_BACKEND_CANISTER_WASM_PATH must be set.");

        let kong_backend_wasm = Wasm::from_file(wasm_path);

        let controllers = vec![PrincipalId::new_user_test_id(42)];

        install_canister_on_subnet(
            &pocket_ic,
            fiduciary_subnet_id,
            vec![],
            Some(kong_backend_wasm),
            controllers,
        )
        .await
    };

    // Approve some ICP from the LP Adaptor.
    nns::ledger::mint_icp(
        &pocket_ic,
        AccountIdentifier::new(lp_adaptor_canister_id, None),
        Tokens::from_tokens(100).unwrap(),
        None,
    )
    .await;

    // Approve some SNS tokens from the LP Adaptor.
    sns::ledger::icrc1_transfer(
        &pocket_ic,
        sns_ledger_canister_id.get(),
        sns_root_canister_id,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: lp_adaptor_canister_id.0,
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(350 * E8),
        },
    )
    .await;

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
                amount: Nat::from(600 * E8 + DEFAULT_TRANSFER_FEE.get_e8s()),
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
                amount: Nat::from(3500 * E8 + DEFAULT_TRANSFER_FEE.get_e8s()),
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

    let mut kong_swap_adaptor = KongSwapAdaptor::new(
         &lp_adaptor_agent,
        kong_backend_canister_id,
        "SNS".to_string(),
        "ICP".to_string(),
    ).unwrap();

    let balances = kong_swap_adaptor.balances().await.unwrap_err();
    println!("1. user balances = {:#?}", balances);

    kong_swap_adaptor
        .deposit(vec![
            Allowance {
                amount_decimals: Nat::from(200 * E8),
                ledger_canister_id: sns_ledger_canister_id,
            },
            Allowance {
                amount_decimals: Nat::from(50 * E8),
                ledger_canister_id: LEDGER_CANISTER_ID,
            },
        ])
        .await
        .unwrap();

    let balances = kong_swap_adaptor.balances().await.unwrap();

    println!("2. user balances = {:#?}", balances);

    let response = lp_adaptor_agent
        .call(kong_backend_canister_id, TokensArgs { symbol: None })
        .await
        .unwrap()
        .unwrap();
    println!("second tokens response = {:#?}", response);

    let response = lp_adaptor_agent
        .call(kong_backend_canister_id, PoolsArgs { symbol: None })
        .await
        .unwrap()
        .unwrap();
    println!("second pools response = {:#?}", response);

    // Step 2: Increase the liquidity allocation.
    kong_swap_adaptor
        .deposit(vec![
            Allowance {
                amount_decimals: Nat::from(140 * E8),
                ledger_canister_id: sns_ledger_canister_id,
            },
            Allowance {
                amount_decimals: Nat::from(35 * E8),
                ledger_canister_id: LEDGER_CANISTER_ID,
            },
        ])
        .await
        .unwrap();

    let balances = kong_swap_adaptor.balances().await.unwrap();

    println!("3. user balances = {:#?}", balances);

    kong_swap_adaptor.withdraw().await.unwrap();

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

fn kong_lp_balance_to_demilams(lp_balance: f64) -> Result<Nat, String> {
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

impl WithBlockIndices for AddPoolReply {
    fn block_indices(&self) -> Nat {
        self.transfer_ids.iter().map(|TransferIdReply {
            transfer: TransferReply::IC(ICTransferReply {
                chain,
                symbol,
                is_send,
                amount,
                canister_id,
                block_index,
            }),
            ..
        }| ).collect()
    }
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
