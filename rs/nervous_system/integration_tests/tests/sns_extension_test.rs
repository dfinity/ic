use std::collections::BTreeMap;
use std::str::FromStr;

use candid::{CandidType, Nat};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_nervous_system_agent::{pocketic_impl::PocketIcAgent, CallCanisters, Request};
use ic_nervous_system_common::E8;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_with_controllers;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns;
use ic_nervous_system_integration_tests::pocket_ic_helpers::NnsInstaller;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_canister_on_subnet, sns};
use ic_nns_constants::LEDGER_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Tokens, DEFAULT_TRANSFER_FEE};
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::approve::ApproveArgs,
};
use itertools::{Either, Itertools};
use maplit::btreemap;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use serde::{Deserialize, Serialize};

// TODO
// use thiserror::Error

#[tokio::test]
async fn test() {
    test_custom_upgrade_path_for_sns().await
}

pub struct Allowance {
    pub amount_decimals: Nat,
    pub ledger_canister_id: CanisterId,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransactionError {
    Precondition(String),
    /// An error that occurred while calling a canister.
    Call(String),
    /// Backend refers to, e.g., the DEX canister that this asset manager talks to.
    Backend(String),
}

pub trait TreasuryManager {
    fn balances(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeMap<String, Nat>, TransactionError>> + Send;

    fn withdraw(
        &mut self,
    ) -> impl std::future::Future<Output = Result<BTreeMap<String, Nat>, TransactionError>> + Send;

    fn deposit(
        &mut self,
        allowances: Vec<Allowance>,
    ) -> impl std::future::Future<Output = Result<(), TransactionError>> + Send;

    fn audit_trail(&self) -> AuditTrail;
}

#[derive(Clone, Debug)]
pub struct Transfer {
    ledger_canister_id: String,
    amount_deimals: Nat,
    block_index: Nat,
}

#[derive(Clone, Debug)]
pub enum TransactionWitness {
    Ledger(Vec<Transfer>),

    /// Represents a transaction that is not related to the ledger, e.g., DEX operations.
    /// The argument is a (best-effort) JSON encoding of the response (for human inspection).
    NonLedger(String),
}

/// Helper trait to extract transaction witness from a response.
pub trait WithTransactionWitness {
    fn witness(&self) -> TransactionWitness;
}

/// TreasuryManagerPhase
/// - Transaction
///     - Transfer
#[derive(Clone, Debug)]
pub struct Transaction {
    canister_id: CanisterId,

    result: Result<TransactionWitness, TransactionError>,
    human_readable: String,
    timestamp_seconds: u64,
    treasury_operation_phase: TreasuryManagerPhase,
}

#[derive(Clone, Copy, Debug)]
pub enum TreasuryManagerPhase {
    Deposit,
    Balances,
    IssueReward,
    Withdraw,
}

#[derive(Clone, Debug)]
pub struct AuditTrail {
    transactions: Vec<Transaction>,
}

impl AuditTrail {
    pub fn new() -> Self {
        AuditTrail {
            transactions: vec![],
        }
    }

    fn record_event(&mut self, event: Transaction) {
        self.transactions.push(event);
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

pub struct KongSwapAdaptor<'a> {
    agent: &'a PocketIcAgent<'a>,
    kong_backend_canister_id: CanisterId,

    token_0: String,
    token_1: String,

    balance_0_decimals: Nat,
    balance_1_decimals: Nat,

    audit_trail: AuditTrail,
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
            balance_0_decimals: Nat::from(0_u64),
            balance_1_decimals: Nat::from(0_u64),
        })
    }

    fn get_cached_balances(&self) -> BTreeMap<String, Nat> {
        btreemap! {
            self.token_0.clone() => self.balance_0_decimals.clone(),
            self.token_1.clone() => self.balance_1_decimals.clone(),
        }
    }

    /// Performs the request call and records the transaction in the audit trail.
    async fn emit_transaction<R, Ok>(
        &mut self,
        canister_id: CanisterId,
        request: R,
        phase: TreasuryManagerPhase,
        human_readable: String,
    ) -> Result<Ok, TransactionError>
    where
        R: Request,
        Ok: WithTransactionWitness + Clone,
        Result<Ok, String>: From<R::Response>,
    {
        let result = self
            .agent
            .call(canister_id, request)
            .await
            .map_err(|err| TransactionError::Call(err.to_string()))
            .and_then(|response| {
                Result::<Ok, String>::from(response)
                    .map_err(|err| TransactionError::Backend(err.to_string()))
            });

        let transaction = Transaction {
            canister_id,
            result: result.clone().map(|ok| ok.witness()),
            human_readable,
            // TODO: use ic_cdk::time::now_seconds
            timestamp_seconds: 1234567,
            treasury_operation_phase: phase,
        };

        self.audit_trail.record_event(transaction);

        result
    }

    async fn maybe_add_token(
        &mut self,
        ledger_canister_id: CanisterId,
        phase: TreasuryManagerPhase,
    ) -> Result<(), TransactionError> {
        let token = format!("IC.{}", ledger_canister_id);

        let human_readable = format!(
            "Calling KongSwapBackend.add_token to attempt to add {}.",
            token
        );

        let request = AddTokenArgs {
            token: token.clone(),
        };

        let response = self
            .emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await;

        match response {
            Ok(_) => Ok(()),
            Err(TransactionError::Backend(err))
                if err == format!("Token {} already exists", token) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn lp_balance(&mut self, phase: TreasuryManagerPhase) -> Result<Nat, TransactionError> {
        let request = UserBalancesArgs {
            principal_id: self.agent.sender.to_string(),
        };

        let human_readable =
            "Calling KongSwapBackend.user_balances to get LP balances.".to_string();

        let user_balance_replies = self
            .emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await?;

        if user_balance_replies.is_empty() {
            return Ok(Nat::from(0_u8));
        }

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
            return Err(TransactionError::Backend(format!(
                "Failed to convert balances: {:?}",
                errors.join(", ")
            )));
        }

        let lp_token = format!("{}_{}", self.token_0, self.token_1);

        let Some((_, balance)) = balances.into_iter().find(|(token, _)| *token == lp_token) else {
            return Err(TransactionError::Backend(format!(
                "Failed to get LP balance for {}.",
                lp_token
            )));
        };

        Ok(balance)
    }

    // TODO: Make this method private once it is periodically called from canister timers.
    pub async fn refresh_balances(&mut self) -> Result<BTreeMap<String, Nat>, TransactionError> {
        let phase = TreasuryManagerPhase::Balances;

        let remove_lp_token_amount = self.lp_balance(phase).await?;

        let human_readable = format!(
            "Calling KongSwapBackend.remove_liquidity_amounts to estimate how much liquidity can be removed for LP token amount {}.",
            remove_lp_token_amount
        );

        let request = RemoveLiquidityAmountsArgs {
            token_0: self.token_0.clone(),
            token_1: self.token_1.clone(),
            remove_lp_token_amount,
        };

        let reply = self
            .emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await?;

        println!("remove_liquidity_amounts reply = {:#?}", reply);

        let RemoveLiquidityAmountsReply {
            amount_0, amount_1, ..
        } = reply;

        self.balance_0_decimals = amount_0.clone();
        self.balance_1_decimals = amount_1.clone();

        Ok(self.get_cached_balances())
    }
}

impl<'a> TreasuryManager for KongSwapAdaptor<'a> {
    async fn deposit(&mut self, mut allowances: Vec<Allowance>) -> Result<(), TransactionError> {
        let phase = TreasuryManagerPhase::Deposit;

        // Check preconditions.

        let Some(Allowance {
            amount_decimals: amount_1,
            ledger_canister_id: ledger_1,
        }) = allowances.pop()
        else {
            return Err(TransactionError::Precondition(
                "KongSwapAdaptor requires some allowances.".to_string(),
            ));
        };

        if ledger_1 != LEDGER_CANISTER_ID {
            return Err(TransactionError::Precondition(
                "KongSwapAdaptor only supports ICP as token_1.".to_string(),
            ));
        }

        let Some(Allowance {
            amount_decimals: amount_0,
            ledger_canister_id: ledger_0,
        }) = allowances.pop()
        else {
            return Err(TransactionError::Precondition(format!(
                "KongSwapAdaptor requires two allowances (got {}).",
                allowances.len()
            )));
        };

        if !allowances.is_empty() {
            return Err(TransactionError::Precondition(format!(
                "KongSwapAdaptor requires exactly two allowances (got {}).",
                allowances.len()
            )));
        }

        // Notes on why we first add SNS and then ICP:
        // - KongSwap starts indexing the tokens from 1.
        // - The ICP token is assumed to have index 2.
        self.maybe_add_token(ledger_0, phase).await?;
        self.maybe_add_token(ledger_1, phase).await?;

        let token_0 = format!("IC.{}", ledger_0);
        let token_1 = format!("IC.{}", ledger_1);

        let original_amount_1 = amount_1.clone();

        let result = self
            .emit_transaction(
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
                TreasuryManagerPhase::Deposit,
                "Calling KongSwapBackend.add_pool to add a new pool.".to_string(),
            )
            .await;

        let pool_already_exists = {
            let lp_token = format!("{}_{}", self.token_0, self.token_1);
            format!("Pool {} already exists", lp_token)
        };

        match result {
            // All used up, since the pool is brand new.
            Ok(_) => {
                return Ok(());
            }

            // An already-existing pool does not preclude a top-up  =>  Keep going.
            Err(TransactionError::Backend(err)) if *err == pool_already_exists => (),

            Err(err) => {
                return Err(err);
            }
        }

        // This is a top-up operation for a pre-existing pool.
        // A top-up requires computing amount_1 as a function of amount_0.

        let AddLiquidityAmountsReply { amount_1, .. } = {
            let human_readable = format!(
                "Calling KongSwapBackend.add_liquidity_amounts to estimate how much liquidity can \
                 be added for token_1 ={} when adding token_0 = {}, amount_0 = {}.",
                token_1, token_0, amount_0,
            );

            let request = AddLiquidityAmountsArgs {
                token_0: token_0.clone(),
                amount: amount_0.clone(),
                token_1: token_1.clone(),
            };

            self.emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await?
        };

        let reply = {
            let human_readable = format!(
                "Calling KongSwapBackend.add_liquidity to top up liquidity for \
                 token_0 = {}, amount_0 = {}, token_1 = {}, amount_1 = {}.",
                token_0, amount_0, token_1, amount_1
            );

            let request = AddLiquidityArgs {
                token_0,
                amount_0,
                token_1,
                amount_1,

                // Not needed for the ICRC2 flow.
                tx_id_0: None,
                tx_id_1: None,
            };

            self.emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await?
        };

        println!("add_liquidity reply = {:#?}", reply);

        let AddLiquidityReply {
            amount_0: _,
            amount_1,
            ..
        } = reply;

        if original_amount_1 < amount_1 {
            return Err(TransactionError::Backend(format!(
                "Got top-up amount_1 = {} (must be at least {})",
                original_amount_1, amount_1
            )));
        }

        Ok(())
    }

    async fn balances(&self) -> Result<BTreeMap<String, Nat>, TransactionError> {
        Ok(self.get_cached_balances())
    }

    async fn withdraw(&mut self) -> Result<BTreeMap<String, Nat>, TransactionError> {
        let phase = TreasuryManagerPhase::Withdraw;

        let remove_lp_token_amount = self.lp_balance(phase).await?;

        println!(
            "refresh_balances >>> remove_lp_token_amount = {}",
            remove_lp_token_amount
        );

        let human_readable =
            "Calling KongSwapBackend.remove_liquidity to withdraw all allocated tokens."
                .to_string();

        let request = RemoveLiquidityArgs {
            token_0: self.token_0.clone(),
            token_1: self.token_1.clone(),
            remove_lp_token_amount,
        };

        let reply = self
            .emit_transaction(
                self.kong_backend_canister_id,
                request,
                phase,
                human_readable,
            )
            .await?;

        println!("remove_liquidity reply = {:#?}", reply);

        let RemoveLiquidityReply {
            status,
            symbol_0,
            amount_0,
            symbol_1,
            amount_1,
            ..
        } = reply;

        if status != "Success" {
            return Err(TransactionError::Backend(format!(
                "Failed to withdraw liquidity: status = {}",
                status
            )));
        }

        Ok(btreemap! {
            symbol_0 => amount_0,
            symbol_1 => amount_1,
        })
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
#[track_caller]
async fn test_custom_upgrade_path_for_sns() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    let topology = pocket_ic.topology().await;
    // let fiduciary_subnet_id = topology.get_fiduciary().unwrap();
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

        // Canister ID from the mainnet.
        // See https://dashboard.internetcomputer.org/canister/2ipq2-uqaaa-aaaar-qailq-cai
        let canister_id = CanisterId::try_from_principal_id(
            PrincipalId::from_str("2ipq2-uqaaa-aaaar-qailq-cai").unwrap(),
        )
        .unwrap();

        install_canister_with_controllers(
            &pocket_ic,
            "KongSwap Backend Canister",
            canister_id,
            vec![],
            kong_backend_wasm,
            controllers,
        )
        .await;

        canister_id
    };

    let lp_adaptor_icp_account = AccountIdentifier::new(lp_adaptor_canister_id, None);

    let lp_adaptor_sns_account = Account {
        owner: lp_adaptor_canister_id.0,
        subaccount: None,
    };

    let assert_dao_balances = async |pocket_ic: &PocketIc, icp: u64, sns: u64| {
        {
            let observed_icp_tokens =
                nns::ledger::account_balance(pocket_ic, &lp_adaptor_icp_account).await;
            let expected_icp_tokens = Tokens::from_e8s(icp);
            assert_eq!(
                observed_icp_tokens, expected_icp_tokens,
                "Unexpected ICP balance."
            );
        }
        {
            let observed_sns_tokens = sns::ledger::icrc1_balance_of(
                pocket_ic,
                sns_ledger_canister_id.get(),
                lp_adaptor_sns_account,
            )
            .await;
            let expected_sns_tokens = Nat::from(sns);
            assert_eq!(
                observed_sns_tokens, expected_sns_tokens,
                "Unexpected SNS balance."
            );
        }
    };

    // Approve some ICP from the LP Adaptor.
    nns::ledger::mint_icp(
        &pocket_ic,
        lp_adaptor_icp_account,
        Tokens::from_tokens(100).unwrap(),
        None,
    )
    .await;

    assert_dao_balances(&pocket_ic, 100 * E8, 0).await;

    // Approve some SNS tokens from the LP Adaptor.
    sns::ledger::icrc1_transfer(
        &pocket_ic,
        sns_ledger_canister_id.get(),
        sns_root_canister_id,
        TransferArg {
            from_subaccount: None,
            to: lp_adaptor_sns_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(350 * E8),
        },
    )
    .await
    .unwrap();

    assert_dao_balances(&pocket_ic, 100 * E8, 350 * E8).await;

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
                amount: Nat::from(u64::MAX),
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

    assert_dao_balances(
        &pocket_ic,
        100 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
        350 * E8,
    )
    .await;

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

    assert_dao_balances(
        &pocket_ic,
        100 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
        350 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
    )
    .await;

    let mut kong_swap_adaptor = KongSwapAdaptor::new(
        &lp_adaptor_agent,
        kong_backend_canister_id,
        "SNS".to_string(),
        "ICP".to_string(),
    )
    .unwrap();

    let err = kong_swap_adaptor.refresh_balances().await.unwrap_err();
    assert_eq!(err, TransactionError::Backend("User not found".to_string()));

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

    assert_dao_balances(
        &pocket_ic,
        50 * E8 - 2 * DEFAULT_TRANSFER_FEE.get_e8s(),
        150 * E8 - 2 * DEFAULT_TRANSFER_FEE.get_e8s(),
    )
    .await;

    assert_eq!(
        kong_swap_adaptor.refresh_balances().await,
        Ok(btreemap! {
            "SNS".to_string() => Nat::from(200 * E8),
            "ICP".to_string() => Nat::from(50 * E8),
        }),
    );

    // Kong-specific assertion.
    let response = lp_adaptor_agent
        .call(kong_backend_canister_id, TokensArgs { symbol: None })
        .await
        .unwrap()
        .unwrap();
    println!("second tokens response = {:#?}", response);

    // Kong-specific assertion.
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

    assert_dao_balances(
        &pocket_ic,
        15 * E8 - 3 * DEFAULT_TRANSFER_FEE.get_e8s(),
        10 * E8 - 3 * DEFAULT_TRANSFER_FEE.get_e8s(),
    )
    .await;

    // Debugging: Print the SNS Ledger block details.
    dbg_print_block(&pocket_ic, sns_ledger_canister_id, 0).await;
    dbg_print_block(&pocket_ic, sns_ledger_canister_id, 1).await;
    dbg_print_block(&pocket_ic, sns_ledger_canister_id, 2).await;
    dbg_print_block(&pocket_ic, sns_ledger_canister_id, 3).await;

    assert_eq!(
        kong_swap_adaptor.refresh_balances().await,
        Ok(btreemap! {
            "SNS".to_string() => Nat::from(340 * E8),
            "ICP".to_string() => Nat::from(85 * E8),
        }),
    );

    // Kong-specific assertion.
    let response = lp_adaptor_agent
        .call(kong_backend_canister_id, PoolsArgs { symbol: None })
        .await
        .unwrap()
        .unwrap();
    println!("third pools response = {:#?}", response);

    let withdrawn_amounts = kong_swap_adaptor.withdraw().await.unwrap();

    println!("withdrawn_amounts = {:#?}", withdrawn_amounts);

    assert_eq!(
        kong_swap_adaptor.refresh_balances().await,
        Ok(btreemap! {
            "SNS".to_string() => Nat::from(0_u8),
            "ICP".to_string() => Nat::from(0_u8),
        }),
    );

    assert_dao_balances(
        &pocket_ic,
        100 * E8 - 4 * DEFAULT_TRANSFER_FEE.get_e8s(),
        350 * E8 - 4 * DEFAULT_TRANSFER_FEE.get_e8s(),
    )
    .await;

    let audit_trail = kong_swap_adaptor.audit_trail();

    println!("{:#?}", audit_trail.transactions());

    panic!("  Directed by\nROBERT B. WEIDE.");
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

impl WithTransactionWitness for AddLiquidityAmountsReply {
    fn witness(&self) -> TransactionWitness {
        // TODO: Use serde_json::to_string
        TransactionWitness::NonLedger(format!("{:?}", self))
    }
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

impl WithTransactionWitness for AddLiquidityReply {
    fn witness(&self) -> TransactionWitness {
        let transfers = self.transfer_ids.iter().map(Transfer::from).collect();

        TransactionWitness::Ledger(transfers)
    }
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

impl WithTransactionWitness for AddTokenReply {
    fn witness(&self) -> TransactionWitness {
        // TODO: Use serde_json::to_string
        TransactionWitness::NonLedger(format!("{:?}", self))
    }
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

impl From<&TransferIdReply> for Transfer {
    fn from(transfer_id_reply: &TransferIdReply) -> Self {
        let TransferIdReply {
            transfer_id: _,
            transfer:
                TransferReply::IC(ICTransferReply {
                    amount,
                    canister_id,
                    block_index,
                    ..
                }),
        } = transfer_id_reply;

        let ledger_canister_id = canister_id.clone();
        let amount_deimals = amount.clone();
        let block_index = block_index.clone();

        Self {
            ledger_canister_id,
            amount_deimals,
            block_index,
        }
    }
}

impl WithTransactionWitness for AddPoolReply {
    fn witness(&self) -> TransactionWitness {
        let transfers = self.transfer_ids.iter().map(Transfer::from).collect();

        TransactionWitness::Ledger(transfers)
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

impl WithTransactionWitness for RemoveLiquidityAmountsReply {
    fn witness(&self) -> TransactionWitness {
        // TODO: Use serde_json::to_string
        TransactionWitness::NonLedger(format!("{:?}", self))
    }
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

impl WithTransactionWitness for RemoveLiquidityReply {
    fn witness(&self) -> TransactionWitness {
        let transfers = self.transfer_ids.iter().map(Transfer::from).collect();

        TransactionWitness::Ledger(transfers)
    }
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

impl WithTransactionWitness for Vec<UserBalancesReply> {
    fn witness(&self) -> TransactionWitness {
        let witnesses = self
            .iter()
            .map(|UserBalancesReply::LP(user_balance_lp_reply)| {
                // TODO: Use serde_json::to_string
                format!("{:?}", user_balance_lp_reply)
            })
            .collect::<Vec<_>>();

        TransactionWitness::NonLedger(witnesses.join(", "))
    }
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

async fn dbg_print_block(
    pocket_ic: &PocketIc,
    sns_ledger_canister_id: CanisterId,
    block_index: u64,
) {
    let block =
        sns::ledger::get_all_blocks(pocket_ic, sns_ledger_canister_id.get(), block_index, 1).await;

    let Value::Map(block_details) = block.blocks[0].clone() else {
        panic!("Expected a block with details, got: {:?}", block.blocks[0]);
    };

    let Value::Map(tx_details) = block_details.get("tx").clone().unwrap() else {
        panic!(
            "Expected a transaction in the block details, got: {:?}",
            block_details.get("tx")
        );
    };

    let from = tx_details.get("from");
    let to = tx_details.get("to");
    let spender = tx_details.get("spender");
    let amt = tx_details.get("amt").unwrap();
    let op = tx_details.get("op").unwrap();

    println!("SNS Ledger block {} details.", block_index);
    println!("    amt = {:?}", amt);
    println!("     op = {:?}", op);
    println!("   from = {:?}", from);
    println!("     to = {:?}", to);
    println!("spender = {:?}", spender);
}
