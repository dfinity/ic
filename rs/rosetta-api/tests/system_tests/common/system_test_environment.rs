use crate::common::utils::get_custom_agent;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use crate::common::{
    constants::{DEFAULT_INITIAL_BALANCE, STARTING_CYCLES_PER_CANISTER},
    utils::test_identity,
};
use candid::{Encode, Principal};
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaClient;
use ic_icp_rosetta_client::RosettaTransferArgs;
use ic_icp_rosetta_runner::RosettaOptions;
use ic_icp_rosetta_runner::{start_rosetta, RosettaContext, RosettaOptionsBuilder};
use ic_icrc1_test_utils::minter_identity;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_tokens_u256::U256;
use ic_ledger_test_utils::build_ledger_wasm;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use ic_rosetta_test_utils::path_from_env;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, LedgerCanisterInitPayload};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use num_traits::cast::ToPrimitive;
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use rosetta_core::identifiers::NetworkIdentifier;
use std::collections::HashMap;
use tempfile::TempDir;

use super::utils::memo_bytebuf_to_u64;

pub struct RosettaTestingEnvironment {
    pub pocket_ic: PocketIc,
    pub rosetta_context: RosettaContext,
    pub rosetta_client: RosettaClient,
    pub network_identifier: NetworkIdentifier,
    pub minting_account: Account,
}

impl RosettaTestingEnvironment {
    pub fn builder() -> RosettaTestingEnvironmentBuilder {
        RosettaTestingEnvironmentBuilder::new()
    }

    /// This function generates blocks by using ICP Rosetta whenever possible. It falls back to using the ledger agent directly for operations that are not supported by Rosetta.
    pub async fn generate_blocks(&self, args_with_caller: Vec<ArgWithCaller>) {
        let replica_port = self.pocket_ic.url().unwrap().port().unwrap();

        for mut arg_with_caller in args_with_caller.into_iter() {
            let icrc1_transaction: ic_icrc1::Transaction<U256> =
                arg_with_caller.to_transaction(self.minting_account);

            // Rosetta does not support subaccounts
            match arg_with_caller.arg {
                LedgerEndpointArg::TransferArg(mut transfer_args) => {
                    transfer_args.from_subaccount = None;
                    transfer_args.to.subaccount = None;
                    arg_with_caller.arg = LedgerEndpointArg::TransferArg(transfer_args);
                }
                LedgerEndpointArg::ApproveArg(mut approve_arg) => {
                    approve_arg.from_subaccount = None;
                    approve_arg.spender.subaccount = None;
                    arg_with_caller.arg = LedgerEndpointArg::ApproveArg(approve_arg);
                }
            };

            // Rosetta does not support mint, burn or approve operations
            // To keep the balances in sync we need to call the ledger agent directly and then go to the next iteration of args with caller
            if !matches!(
                icrc1_transaction.operation,
                ic_icrc1::Operation::Transfer { .. }
            ) {
                let caller_agent = Icrc1Agent {
                    agent: get_custom_agent(arg_with_caller.caller.clone(), replica_port).await,
                    ledger_canister_id: LEDGER_CANISTER_ID.into(),
                };
                match arg_with_caller.arg {
                    LedgerEndpointArg::ApproveArg(approve_arg) => caller_agent
                        .approve(approve_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                    LedgerEndpointArg::TransferArg(transfer_arg) => caller_agent
                        .transfer(transfer_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                };
                continue;
            }

            let transfer_args = match arg_with_caller.arg {
                LedgerEndpointArg::TransferArg(transfer_args) => transfer_args,
                _ => panic!("Expected TransferArg"),
            };
            let mut args_builder =
                RosettaTransferArgs::builder(transfer_args.to, transfer_args.amount);
            if let Some(from_subaccount) = transfer_args.from_subaccount {
                args_builder = args_builder.with_from_subaccount(from_subaccount);
            }
            if let Some(memo) = transfer_args.memo {
                args_builder = args_builder.with_memo(memo_bytebuf_to_u64(&memo.0).unwrap());
            }
            if let Some(created_at_time) = transfer_args.created_at_time {
                args_builder = args_builder.with_created_at_time(created_at_time);
            }

            self.rosetta_client
                .transfer(
                    args_builder.build(),
                    self.network_identifier.clone(),
                    arg_with_caller.caller,
                )
                .await
                .unwrap();
        }
    }

    pub async fn restart_rosetta_node(mut self, options: RosettaOptions) -> Self {
        let ledger_tip = self
            .rosetta_client
            .network_status(self.network_identifier.clone())
            .await
            .unwrap()
            .current_block_identifier
            .index;

        self.rosetta_context.kill();

        let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");
        let rosetta_state_directory =
            TempDir::new().expect("failed to create a temporary directory");
        self.rosetta_context = start_rosetta(
            &rosetta_bin,
            Some(rosetta_state_directory.path().to_owned()),
            options,
        )
        .await;

        self.rosetta_client =
            RosettaClient::from_str_url(&format!("http://localhost:{}", self.rosetta_context.port))
                .expect("Unable to parse url");
        wait_for_rosetta_to_sync_up_to_block(
            &self.rosetta_client,
            self.network_identifier.clone(),
            ledger_tip,
        )
        .await
        .unwrap();
        self
    }
}

pub struct RosettaTestingEnvironmentBuilder {
    pub transfer_args_for_block_generating: Option<Vec<ArgWithCaller>>,
    pub minting_account: Option<Account>,
    pub initial_balances: Option<HashMap<AccountIdentifier, icp_ledger::Tokens>>,
    pub persistent_storage: bool,
}

impl RosettaTestingEnvironmentBuilder {
    pub fn new() -> Self {
        Self {
            transfer_args_for_block_generating: None,
            minting_account: None,
            initial_balances: None,
            persistent_storage: false,
        }
    }

    pub fn with_transfer_args_for_block_generating(
        mut self,
        transfer_args: Vec<ArgWithCaller>,
    ) -> Self {
        self.transfer_args_for_block_generating = Some(transfer_args);
        self
    }

    pub fn with_minting_account(mut self, minter_account: Account) -> Self {
        self.minting_account = Some(minter_account);
        self
    }

    pub fn with_initial_balances(
        mut self,
        initial_balances: HashMap<AccountIdentifier, icp_ledger::Tokens>,
    ) -> Self {
        self.initial_balances = Some(initial_balances);
        self
    }

    pub fn with_persistent_storage(mut self) -> Self {
        self.persistent_storage = true;
        self
    }

    pub async fn build(self) -> RosettaTestingEnvironment {
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let replica_url = pocket_ic.make_live(None).await;
        let replica_port = replica_url.port().unwrap();

        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let canister_id = pocket_ic
            .create_canister_with_id(None, None, ledger_canister_id)
            .await
            .expect("Unable to create the canister in which the Ledger would be installed");

        let minting_account = self
            .minting_account
            .unwrap_or_else(|| minter_identity().sender().unwrap().into());
        let init_args = LedgerCanisterInitPayload::builder()
            .minting_account(minting_account.into())
            .initial_values(self.initial_balances.unwrap_or_else(|| {
                HashMap::from([(
                    AccountIdentifier::new(PrincipalId(test_identity().sender().unwrap()), None),
                    icp_ledger::Tokens::from_tokens(DEFAULT_INITIAL_BALANCE).unwrap(),
                )])
            }))
            .build()
            .unwrap();
        pocket_ic
            .install_canister(
                canister_id,
                build_ledger_wasm().bytes().to_vec(),
                Encode!(&init_args).unwrap(),
                None,
            )
            .await;

        assert_eq!(
            ledger_canister_id, canister_id,
            "Canister IDs do not match: expected {}, got {}",
            ledger_canister_id, canister_id
        );

        pocket_ic
            .add_cycles(ledger_canister_id, STARTING_CYCLES_PER_CANISTER)
            .await;

        println!(
            "Installed the Ledger canister ({canister_id}) onto {}",
            pocket_ic.get_subnet(ledger_canister_id).await.unwrap()
        );

        let mut block_idxes = vec![];
        if let Some(args) = &self.transfer_args_for_block_generating {
            for ArgWithCaller {
                caller,
                arg,
                principal_to_basic_identity: _,
            } in args.clone().into_iter()
            {
                let caller_agent = Icrc1Agent {
                    agent: get_custom_agent(caller.clone(), replica_port).await,
                    ledger_canister_id: LEDGER_CANISTER_ID.into(),
                };
                block_idxes.push(match arg {
                    LedgerEndpointArg::ApproveArg(approve_arg) => caller_agent
                        .approve(approve_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                    LedgerEndpointArg::TransferArg(transfer_arg) => caller_agent
                        .transfer(transfer_arg.clone())
                        .await
                        .unwrap()
                        .unwrap()
                        .0
                        .to_u64()
                        .unwrap(),
                });
            }
        }

        let rosetta_bin = path_from_env("ROSETTA_BIN_PATH");
        let rosetta_state_directory =
            TempDir::new().expect("failed to create a temporary directory");

        let mut rosetta_options_builder = RosettaOptionsBuilder::new(replica_url.to_string())
            .with_persistent_storage(self.persistent_storage);
        if self.persistent_storage {
            rosetta_options_builder = rosetta_options_builder.with_persistent_storage();
        }
        let rosetta_context = start_rosetta(
            &rosetta_bin,
            Some(rosetta_state_directory.path().to_owned()),
            rosetta_options_builder.build(),
        )
        .await;

        let rosetta_client =
            RosettaClient::from_str_url(&format!("http://localhost:{}", rosetta_context.port))
                .expect("Unable to parse url");

        let network_identifier = rosetta_client
            .network_list()
            .await
            .unwrap()
            .network_identifiers
            .into_iter()
            .next()
            .unwrap();

        // Wait for rosetta to catch up with the ledger
        if let Some(last_block_idx) = block_idxes.last() {
            let rosetta_last_block_idx = wait_for_rosetta_to_sync_up_to_block(
                &rosetta_client,
                network_identifier.clone(),
                *last_block_idx,
            )
            .await;
            assert_eq!(
                Some(*last_block_idx),
                rosetta_last_block_idx,
                "Wait for rosetta sync failed."
            );
        }

        RosettaTestingEnvironment {
            pocket_ic,
            rosetta_context,
            rosetta_client,
            network_identifier,
            minting_account,
        }
    }
}
