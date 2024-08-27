use crate::common::utils::get_custom_agent;
use crate::common::utils::wait_for_rosetta_block;
use crate::common::{
    constants::{DEFAULT_INITIAL_BALANCE, STARTING_CYCLES_PER_CANISTER},
    utils::test_identity,
};
use candid::{Encode, Principal};
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaClient;
use ic_icp_rosetta_runner::{start_rosetta, RosettaContext, RosettaOptionsBuilder};
use ic_icrc1_test_utils::minter_identity;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::LedgerEndpointArg;
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

pub struct RosettaTestingEnvironment {
    pub _pocket_ic: PocketIc,
    pub _rosetta_context: RosettaContext,
    pub rosetta_client: RosettaClient,
    pub network_identifier: NetworkIdentifier,
}

impl RosettaTestingEnvironment {
    pub fn builder() -> RosettaTestingEnviornmentBuilder {
        RosettaTestingEnviornmentBuilder::new()
    }
}

pub struct RosettaTestingEnviornmentBuilder {
    pub persistent_storage: bool,
    pub icp_ledger_init_args: Option<LedgerCanisterInitPayload>,
    pub controller_id: Option<PrincipalId>,
    pub transfer_args_for_block_generating: Option<Vec<ArgWithCaller>>,
    pub minting_account: Option<Account>,
}

impl RosettaTestingEnviornmentBuilder {
    pub fn new() -> Self {
        Self {
            persistent_storage: false,
            icp_ledger_init_args: None,
            controller_id: None,
            transfer_args_for_block_generating: None,
            minting_account: None,
        }
    }

    pub fn with_persistent_storage(mut self) -> Self {
        self.persistent_storage = true;
        self
    }

    pub fn with_icp_ledger_init_args(mut self, args: LedgerCanisterInitPayload) -> Self {
        self.icp_ledger_init_args = Some(args);
        self
    }

    pub fn with_icp_ledger_controller_id(mut self, controller_id: PrincipalId) -> Self {
        self.controller_id = Some(controller_id);
        self
    }

    pub fn with_args_with_caller(mut self, transfer_args: Vec<ArgWithCaller>) -> Self {
        self.transfer_args_for_block_generating = Some(transfer_args);
        self
    }

    pub fn with_minting_account(mut self, minter_account: Account) -> Self {
        self.minting_account = Some(minter_account);
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

        let init_args = self.icp_ledger_init_args.unwrap_or_else(|| {
            LedgerCanisterInitPayload::builder()
                .minting_account(
                    self.minting_account
                        .unwrap_or_else(|| minter_identity().sender().unwrap().into())
                        .into(),
                )
                .initial_values(HashMap::from([(
                    AccountIdentifier::new(PrincipalId(test_identity().sender().unwrap()), None),
                    icp_ledger::Tokens::from_tokens(DEFAULT_INITIAL_BALANCE).unwrap(),
                )]))
                .build()
                .unwrap()
        });

        pocket_ic
            .install_canister(
                canister_id,
                build_ledger_wasm().bytes().to_vec(),
                Encode!(&init_args).unwrap(),
                self.controller_id.map(|id| id.into()),
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
        let rosetta_context = start_rosetta(
            &rosetta_bin,
            Some(rosetta_state_directory.path().to_owned()),
            RosettaOptionsBuilder::new(replica_url.to_string()).build(),
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
            let rosetta_last_block_idx = wait_for_rosetta_block(
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
            _pocket_ic: pocket_ic,
            _rosetta_context: rosetta_context,
            rosetta_client,
            network_identifier,
        }
    }
}
