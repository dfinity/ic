// Warning: These tests heavily rely on mocks (created by the lovely mockall library). They might
// even be considered "mockeries". This is not a big surprise, since a big (main?) part of what this
// library does is call other canisters.
//
// For higher confidence, integration tests would be good. OTOH, they are slow. Can't have your cake
// and eat it too, it seems.

use super::*;
use candid::{
    de::IDLDeserialize,
    ser::IDLBuilder,
    types::principal::Principal,
    utils::{ArgumentDecoder, ArgumentEncoder},
    Encode,
};
use cycles_minting_canister::IcpXdrConversionRate;
use ic_base_types::PrincipalId;
use ic_sns_swap_proto_library::pb::v1::Init as SwapInit;
use lazy_static::lazy_static;
use maplit::hashmap;
use mockall::predicate;
use std::{cell::RefCell, collections::HashMap, future::Future};

#[tokio::test]
async fn test_try_get_balance_valuation_factors() {
    // Step 1: Prepare the world. This mostly consists of constructing fields of
    // TokenBalanceAssessor.
    let principal = PrincipalId::new_user_test_id(42);

    let account = Account {
        owner: Principal::from(principal),
        subaccount: None,
    };

    let mut icrc1_client = MockIcrc1Client::new();
    icrc1_client
        .expect_icrc1_balance_of()
        .times(1)
        .with(predicate::eq(account))
        .returning(|_account| Ok(Nat::from(0xCAFE * E8)));

    let mut icps_per_token_client = MockIcpsPerTokenClient::new();
    icps_per_token_client
        .expect_get()
        .times(1)
        .returning(|| Ok(Decimal::try_from(3.21_f64).unwrap()));

    let mut xdrs_per_icp_client = MockXdrsPerIcpClient::new();
    xdrs_per_icp_client
        .expect_get()
        .times(1)
        .returning(|| Ok(Decimal::try_from(2.72).unwrap()));

    // Step 2: Call the code under test.
    let observed_valuation_factors = try_get_balance_valuation_factors(
        account,
        &mut icrc1_client,
        &mut icps_per_token_client,
        &mut xdrs_per_icp_client,
    )
    .await
    .unwrap();

    // Step 3: Inspect result.

    let tokens = Decimal::from(0xCAFE);
    let icps_per_token = Decimal::try_from(3.21).unwrap();
    let xdrs_per_icp = Decimal::try_from(2.72).unwrap();

    let expected_valuation_factors = ValuationFactors {
        tokens,
        icps_per_token,
        xdrs_per_icp,
    };
    assert_eq!(observed_valuation_factors, expected_valuation_factors);

    assert_eq!(
        observed_valuation_factors.to_xdr(),
        tokens * icps_per_token * xdrs_per_icp,
    );
}

#[tokio::test]
async fn test_icps_per_sns_token_client() {
    lazy_static! {
        static ref SWAP_CANISTER_ID: CanisterId =
            CanisterId::try_from(PrincipalId::new_user_test_id(42)).unwrap();
    }

    thread_local! {
        #[allow(clippy::type_complexity)]
        static EXPECTED_SWAP_CANISTER_CALLS: RefCell<HashMap<
            &'static str, // method_name
            (Vec<u8>, Vec<u8>) // (request, response)
        >> = {
            RefCell::new(hashmap! {
                "get_derived_state" => {
                    let request = Encode!(&GetDerivedStateRequest {}).unwrap();

                    let response = Encode!(&GetDerivedStateResponse {
                        buyer_total_icp_e8s: Some(321),
                        ..Default::default()
                    })
                    .unwrap();

                    (request, response)
                },

                "get_init" => {
                    let request = Encode!(&GetInitRequest {}).unwrap();

                    let response = Encode!(&GetInitResponse {
                        init: Some(SwapInit {
                            sns_token_e8s: Some(100),
                            ..Default::default()
                        }),
                    })
                    .unwrap();

                    (request, response)
                }
            })
        }
    }

    struct MockRuntime {}

    #[async_trait]
    impl Runtime for MockRuntime {
        async fn call_with_cleanup<In, Out>(
            id: CanisterId,
            method: &str,
            args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            // Inspect destination canister ID.
            assert_eq!(id, *SWAP_CANISTER_ID);

            // Based on method, determine expected request (and simulated response).
            let (expected_request, response) =
                EXPECTED_SWAP_CANISTER_CALLS.with(|expected_swap_canister_calls| {
                    expected_swap_canister_calls
                        .borrow_mut()
                        .remove(method)
                        .unwrap_or_else(|| {
                            panic!("Unexpected swap canister call to method {}.", method,)
                        })
                });
            let mut idl_builder = IDLBuilder::new();
            args.encode(&mut idl_builder).unwrap();
            assert_eq!(idl_builder.serialize_to_vec().unwrap(), expected_request,);

            // Pretend that canister returned.
            // Re-encode result as Out.
            let mut idl_deserializer = IDLDeserialize::new(&response).unwrap();
            Ok(Out::decode(&mut idl_deserializer).unwrap())
        }

        async fn call_without_cleanup<In, Out>(
            _id: CanisterId,
            _method: &str,
            _args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            unimplemented!()
        }

        async fn call_bytes_with_cleanup(
            _id: CanisterId,
            _method: &str,
            _args: &[u8],
        ) -> Result<Vec<u8>, (i32, String)> {
            unimplemented!()
        }

        fn spawn_future<F: 'static + Future<Output = ()>>(_future: F) {
            unimplemented!()
        }
    }

    let observed_icps_per_sns_token = IcpsPerSnsTokenClient::<MockRuntime>::new(*SWAP_CANISTER_ID)
        .get()
        .await
        .unwrap();

    {
        let observed = f64::try_from(observed_icps_per_sns_token).unwrap();
        let expected = 3.21;
        let relative_error = (observed - expected) / expected;
        assert!(
            relative_error.abs() < 1e-9,
            "{} vs. {} (diff: {}, relative_error: {}%)",
            observed,
            expected,
            observed - expected,
            relative_error,
        );
    }

    EXPECTED_SWAP_CANISTER_CALLS.with(|expected_swap_canister_calls| {
        assert_eq!(*expected_swap_canister_calls.borrow(), hashmap! {},)
    });
}

#[tokio::test]
async fn test_new_standard_xdrs_per_icp_client() {
    lazy_static! {
        static ref SWAP_CANISTER_ID: CanisterId =
            CanisterId::try_from(PrincipalId::new_user_test_id(42)).unwrap();
    }

    thread_local! {
        static CALL_WITHOUT_CLEANUP_CALL_COUNT: RefCell<u64> = const { RefCell::new(0) };
    }

    #[derive(Default)]
    struct MockRuntime {}

    #[async_trait]
    impl Runtime for MockRuntime {
        async fn call_with_cleanup<In, Out>(
            id: CanisterId,
            method: &str,
            args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            // Inspect arguments.
            assert_eq!(id, CYCLES_MINTING_CANISTER_ID);
            assert_eq!(method, "get_average_icp_xdr_conversion_rate");
            let mut idl_builder = IDLBuilder::new();
            args.encode(&mut idl_builder).unwrap();
            assert_eq!(
                idl_builder.serialize_to_vec().unwrap(),
                Encode!(&()).unwrap(),
            );

            // Increment call count.
            CALL_WITHOUT_CLEANUP_CALL_COUNT.with(|count| {
                let mut count = count.borrow_mut();
                *count += 1;
            });

            // Pretend that canister returned.
            let result = IcpXdrConversionRateCertifiedResponse {
                data: IcpXdrConversionRate {
                    timestamp_seconds: 42,
                    xdr_permyriad_per_icp: 32100, // 3.21 XDR / ICP
                },
                hash_tree: vec![],
                certificate: vec![],
            };
            // Re-encode result as Out.
            let result = Encode!(&result).unwrap();
            let mut idl_deserializer = IDLDeserialize::new(&result).unwrap();
            Ok(Out::decode(&mut idl_deserializer).unwrap())
        }

        async fn call_without_cleanup<In, Out>(
            _id: CanisterId,
            _method: &str,
            _args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            unimplemented!()
        }

        async fn call_bytes_with_cleanup(
            _id: CanisterId,
            _method: &str,
            _args: &[u8],
        ) -> Result<Vec<u8>, (i32, String)> {
            unimplemented!()
        }

        fn spawn_future<F: 'static + Future<Output = ()>>(_future: F) {
            unimplemented!()
        }
    }

    let observed_xdrs_per_icp = new_standard_xdrs_per_icp_client::<MockRuntime>()
        .get()
        .await
        .unwrap();

    assert_eq!(observed_xdrs_per_icp, Decimal::try_from(3.21).unwrap(),);
}
