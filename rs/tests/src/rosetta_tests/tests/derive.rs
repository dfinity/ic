use crate::rosetta_tests::lib::make_user;
use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::setup;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_rosetta_api::convert::to_model_account_identifier;
use ic_rosetta_api::models::ConstructionDeriveResponse;
use ic_rosetta_api::models::Error as RosettaError;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use icp_ledger::{AccountIdentifier, Subaccount};
use slog::{info, Logger};

const PORT: u32 = 8101;
const VM_NAME: &str = "rosetta-test-derive";

pub fn test(env: TestEnv) {
    let client = setup(&env, PORT, VM_NAME, None, None);
    let logger = env.logger();
    block_on(async {
        test_derive_ledger_address(&client, &logger).await;
        test_derive_neuron_address(&client, &logger).await;
    });
}

async fn test_derive_ledger_address(client: &RosettaApiClient, logger: &Logger) {
    info!(&logger, "Test derive ledger address");
    let (acc, _kp, pk, _pid) = make_user(5);
    let res: Result<Result<ConstructionDeriveResponse, RosettaError>, String> =
        client.construction_derive(pk.clone()).await;
    let derived = res.unwrap().unwrap();
    assert_eq!(
        acc.to_hex(),
        derived.account_identifier.unwrap().address,
        "Account id derived via construction/derive is different than expected"
    );
}

async fn test_derive_neuron_address(client: &RosettaApiClient, logger: &Logger) {
    info!(&logger, "Test derive neuron address");
    let (_acc, _kp, pk, pid) = make_user(6);
    let res: Result<Result<ConstructionDeriveResponse, RosettaError>, String> =
        client.neuron_derive(pk.clone()).await;
    let derived = res.unwrap().unwrap();
    let account_id = derived.account_identifier.unwrap();
    let subaccount_bytes = {
        const DOMAIN: &[u8] = b"neuron-stake";
        let mut hasher = ic_crypto_sha2::Sha256::new();
        hasher.write(&[DOMAIN.len() as u8]);
        hasher.write(DOMAIN);
        hasher.write(pid.as_slice());
        hasher.write(&[0u8; 8]);
        hasher.finish()
    };
    assert_eq!(
        account_id,
        to_model_account_identifier(&AccountIdentifier::new(
            GOVERNANCE_CANISTER_ID.get(),
            Some(Subaccount(subaccount_bytes)),
        ))
    );
}
