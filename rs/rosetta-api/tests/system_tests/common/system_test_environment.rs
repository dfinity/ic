use crate::common::{
    constants::{DEFAULT_INITIAL_BALANCE, STARTING_CYCLES_PER_CANISTER},
    utils::test_identity,
};
use candid::{Encode, Principal};
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaClient;
use ic_icp_rosetta_runner::{start_rosetta, RosettaContext, RosettaOptionsBuilder};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_test_utils::build_ledger_wasm;
use ic_ledger_test_utils::pocket_ic_helpers::ledger::LEDGER_CANISTER_ID;
use ic_rosetta_test_utils::path_from_env;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, LedgerCanisterInitPayload};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};
use std::collections::HashMap;
use tempfile::TempDir;

pub struct RosettaTestingEnvironment {
    pub _pocket_ic: PocketIc,
    pub _rosetta_context: RosettaContext,
    pub rosetta_client: RosettaClient,
}

impl RosettaTestingEnvironment {
    pub fn builder() -> RosettaTestingEnviornmentBuilder {
        RosettaTestingEnviornmentBuilder::new()
    }
}

pub struct RosettaTestingEnviornmentBuilder {}

impl RosettaTestingEnviornmentBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn build(self) -> RosettaTestingEnvironment {
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let replica_url = pocket_ic.make_live(None).await;

        let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
        let canister_id = pocket_ic
            .create_canister_with_id(None, None, ledger_canister_id)
            .await
            .expect("Unable to create the canister in which the Ledger would be installed");

        let init_args = LedgerCanisterInitPayload::builder()
            .minting_account(minter_identity().sender().unwrap().into())
            .initial_values(HashMap::from([(
                AccountIdentifier::new(PrincipalId(test_identity().sender().unwrap()), None),
                icp_ledger::Tokens::from_tokens(DEFAULT_INITIAL_BALANCE).unwrap(),
            )]))
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

        RosettaTestingEnvironment {
            _pocket_ic: pocket_ic,
            _rosetta_context: rosetta_context,
            rosetta_client,
        }
    }
}
