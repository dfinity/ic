// Warning: These tests heavily rely on mocks (created by the lovely mockall library). They might
// even be considered "mockeries". This is not a big surprise, since a big (main?) part of what this
// library does is call other canisters.
//
// For higher confidence, integration tests would be good. OTOH, they are slow. Can't have your cake
// and eat it too, it seems.

use super::*;
use candid::{
    Encode,
    de::IDLDeserialize,
    decode_args, encode_args,
    ser::IDLBuilder,
    types::principal::Principal,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use cycles_minting_canister::IcpXdrConversionRate;
use ic_base_types::PrincipalId;
use icrc_ledger_types::icrc3::transactions::{
    GetTransactionsRequest, GetTransactionsResponse, Mint, Transaction,
};
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
        static ref SNS_TOKEN_LEDGER_CANISTER_ID: CanisterId =
            CanisterId::try_from(PrincipalId::new_user_test_id(43)).unwrap();
    }

    fn canister_id2name(canister_id: CanisterId) -> String {
        if canister_id == *SWAP_CANISTER_ID {
            return "swap".to_string();
        }

        if canister_id == *SNS_TOKEN_LEDGER_CANISTER_ID {
            return "sns_token_ledger".to_string();
        }

        format!("{canister_id}")
    }

    const INITIAL_ICPS_PER_SNS_TOKEN: f64 = 12.34;
    const INITIAL_SNS_TOKEN_SUPPLY_E8S: u64 = 123_456_789;
    const GENESIS_TIMESTAMP_NANOSECONDS: u64 = 42;

    thread_local! {
        // HashMap is used, because calls are made concurrently; therefore, our
        // usual way of using Vec probably would not work (and wouldn't be
        // right), because we do not want to impose such ordering constraints
        // (on the code under test).
        #[allow(clippy::type_complexity)]
        static EXPECTED_CALLS: RefCell<HashMap<
            (CanisterId, String), // (canister_id, method_name)
            (Vec<u8>, Vec<u8>)     // (request, response)
        >> = {
            RefCell::new(hashmap! {
                // This is used to determine the SNS token price at genesis, as
                // determined by the SNS's initialization swap.
                (*SWAP_CANISTER_ID, "get_derived_state".to_string()) => {
                    let request = encode_args((GetDerivedStateRequest {},)).unwrap();

                    let response = encode_args((GetDerivedStateResponse {
                        sns_tokens_per_icp: Some(1.0 / INITIAL_ICPS_PER_SNS_TOKEN),
                        ..Default::default()
                    },))
                    .unwrap();

                    (request, response)
                },

                // This is used to determine the initial supply. In practice,
                // figuring that out is much more complicated than what we have
                // here (e.g. more than one transaction, archived transactions,
                // etc.), but more interesting scenarios are already covered by
                // inital_supply_e8s tests.
                (*SNS_TOKEN_LEDGER_CANISTER_ID, "get_transactions".to_string()) => {
                    let request = encode_args((GetTransactionsRequest {
                        start: Nat::from(0_u64),
                        length: Nat::from(250_u64), // This is from the default batch size.
                    },)).unwrap();

                    let response = encode_args((GetTransactionsResponse {
                        transactions: vec![
                            Transaction {
                                mint: Some(Mint {
                                    amount: Nat::from(INITIAL_SNS_TOKEN_SUPPLY_E8S),
                                    to: Account {
                                        owner: PrincipalId::new_user_test_id(711_452_149).0,
                                        subaccount: None,
                                    },
                                    created_at_time: Some(GENESIS_TIMESTAMP_NANOSECONDS),
                                    memo: None,
                                    fee: None,
                                }),
                                timestamp: GENESIS_TIMESTAMP_NANOSECONDS,
                                kind: "mint".to_string(),

                                burn: None,
                                approve: None,
                                transfer: None,
                                fee_collector: None,
                            },
                        ],

                        first_index: Nat::from(0_u64),
                        log_length: Nat::from(1_u64),

                        archived_transactions: vec![],
                    },)).unwrap();

                    (request, response)
                },

                // Along with initial supply (above), this is used to determine
                // the total inflation of the SNS token (that is the inflation
                // that has occurred throughout its _entire_ life, not just one
                // year or something like that). Because the current amount is
                // 2x the original, the total inflation is +100%, and therefore,
                // the current ICPs per SNS token should be half the initial
                // amount, i.e. 0.5 * 12.34 = 6.17.
                (*SNS_TOKEN_LEDGER_CANISTER_ID, "icrc1_total_supply".to_string()) => {
                    let request = encode_args(()).unwrap();

                    let response = encode_args((Nat::from(2 * INITIAL_SNS_TOKEN_SUPPLY_E8S),)).unwrap();

                    (request, response)
                },
            })
        }
    }

    struct MockRuntime {}

    #[async_trait]
    impl Runtime for MockRuntime {
        async fn call_with_cleanup<In, Out>(
            callee_canister_id: CanisterId,
            method_name: &str,
            args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            Self::call_bytes_with_cleanup(
                callee_canister_id,
                method_name,
                &encode_args(args).unwrap(),
            )
            .await
            .map(|response| decode_args(&response).unwrap())
        }

        async fn call_bytes_with_cleanup(
            callee_canister_id: CanisterId,
            method_name: &str,
            args: &[u8],
        ) -> Result<Vec<u8>, (i32, String)> {
            // Pop from EXPECTED_CALLS.
            let (expected_args, response) = EXPECTED_CALLS.with(|expected_calls| {
                expected_calls
                    .borrow_mut()
                    .remove(&(callee_canister_id, method_name.to_string()))
                    .unwrap_or_else(|| {
                        panic!(
                            "Unexpected call: {} {} {:?}",
                            canister_id2name(callee_canister_id),
                            method_name,
                            args
                        );
                    })
            });

            assert_eq!(
                args,
                expected_args,
                "{} {}",
                canister_id2name(callee_canister_id),
                method_name
            );

            Ok(response)
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

        fn spawn_future<F: 'static + Future<Output = ()>>(_future: F) {
            unimplemented!()
        }

        fn canister_version() -> u64 {
            unimplemented!()
        }
    }

    // Step 2: Call code under test.

    let observed_icps_per_sns_token =
        IcpsPerSnsTokenClient::<MockRuntime>::new(*SWAP_CANISTER_ID, *SNS_TOKEN_LEDGER_CANISTER_ID)
            .get()
            .await
            .unwrap();

    // Step 3: Inspect results.

    {
        let observed = f64::try_from(observed_icps_per_sns_token).unwrap();
        // The 0.5 factor here is because of inflation. (This is explained in
        // greater detail in earlier comments.)
        let expected = 0.5 * INITIAL_ICPS_PER_SNS_TOKEN;
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

    // Assert that all expected calls took place.
    EXPECTED_CALLS.with(|expected_swap_canister_calls| {
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

        fn canister_version() -> u64 {
            unimplemented!()
        }
    }

    let observed_xdrs_per_icp = new_standard_xdrs_per_icp_client::<MockRuntime>()
        .get()
        .await
        .unwrap();

    assert_eq!(observed_xdrs_per_icp, Decimal::try_from(3.21).unwrap(),);
}
