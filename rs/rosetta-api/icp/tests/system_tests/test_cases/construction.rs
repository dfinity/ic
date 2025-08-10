use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::basic_identity_strategy;
use ic_icrc1_test_utils::{minter_identity, DEFAULT_TRANSFER_FEE};
use ic_rosetta_api::models::ConstructionDeriveRequest;
use ic_rosetta_api::models::ConstructionMetadataRequest;
use ic_rosetta_api::models::ConstructionMetadataResponse;
use ic_types::PrincipalId;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::models::CurveType;
use rosetta_core::objects::Amount;
use rosetta_core::objects::Currency;
use rosetta_core::objects::PublicKey;
use std::sync::Arc;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

#[test]
fn test_construction_derive() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(&(basic_identity_strategy().no_shrink()), |identity| {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let rosetta_testing_environment =
                    RosettaTestingEnvironment::builder().build().await;
                let identity = Arc::new(identity);
                let mut public_key: PublicKey = (&identity).into();
                let construction_derive_response = rosetta_testing_environment
                    .rosetta_client
                    .construction_derive(ConstructionDeriveRequest::new(
                        rosetta_testing_environment.network_identifier.clone(),
                        public_key.clone(),
                    ))
                    .await
                    .unwrap();
                assert_eq!(
                    construction_derive_response
                        .account_identifier
                        .unwrap()
                        .address,
                    icp_ledger::AccountIdentifier::new(
                        PrincipalId(identity.sender().unwrap()),
                        None
                    )
                    .to_string()
                );
                // If we provide the wrong curve type, we should get an error
                public_key.curve_type = CurveType::Secp256K1;
                let construction_derive_response = rosetta_testing_environment
                    .rosetta_client
                    .construction_derive(ConstructionDeriveRequest::new(
                        rosetta_testing_environment.network_identifier.clone(),
                        public_key,
                    ))
                    .await;
                assert!(
                    construction_derive_response.is_err(),
                    "This pk should not have been accepted"
                );
            });

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_construction_metadata() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let rosetta_testing_environment = RosettaTestingEnvironment::builder().build().await;
        let res = rosetta_testing_environment
            .rosetta_client
            .construction_metadata(
                ConstructionMetadataRequest::builder(
                    rosetta_testing_environment.network_identifier,
                )
                .build(),
            )
            .await
            .unwrap();
        assert_eq!(
            res,
            ConstructionMetadataResponse {
                metadata: Default::default(),
                suggested_fee: Some(vec![Amount {
                    value: format!("{}", DEFAULT_TRANSFER_FEE),
                    currency: Currency {
                        symbol: "ICP".to_string(),
                        decimals: 8,
                        metadata: None,
                    },
                    metadata: None,
                }]),
            }
        );
    });
}
