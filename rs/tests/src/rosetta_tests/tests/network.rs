use crate::rosetta_tests::rosetta_client::RosettaApiClient;
use crate::rosetta_tests::setup::setup;
use ic_rosetta_api::models::Error;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::util::block_on;
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::response_types::NetworkListResponse;
use slog::{debug, Logger};

const PORT: u32 = 8100;
const VM_NAME: &str = "rosetta-test-network";

pub fn test(env: TestEnv) {
    let client = setup(&env, PORT, VM_NAME, None, None);
    let logger = env.logger();
    block_on(async {
        test_network(&client, &logger).await;
    });
}

pub async fn test_network(client: &RosettaApiClient, logger: &Logger) {
    let res: Result<Result<NetworkListResponse, Error>, String> = client.network_list().await;
    let res = res.unwrap();
    assert_eq!(
        Ok(NetworkListResponse {
            network_identifiers: vec![NetworkIdentifier {
                blockchain: "Internet Computer".to_string(),
                network: "00000000000000020101".to_string(),
                sub_network_identifier: None
            }]
        }),
        res
    );
    debug!(&logger, "Available networks: {:#?}", res.unwrap());
}
