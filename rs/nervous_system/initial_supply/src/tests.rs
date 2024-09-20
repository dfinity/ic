use super::*;
use async_trait::async_trait;
use candid::{
    decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use icrc_ledger_types::{icrc1::account::Account, icrc3::transactions::Mint};
use lazy_static::lazy_static;
use std::{cell::RefCell, collections::VecDeque, future::Future};

fn i2nat(i: u64) -> Nat {
    Nat(BigUint::from(i))
}

#[tokio::test]
async fn test_initial_supply() {
    // Step 1: Prepare the world.

    const BATCH_SIZE: u64 = 4;

    lazy_static! {
        static ref LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(42);
        static ref ARCHIVE_CANISTER_ID: CanisterId = CanisterId::from_u64(43);
        static ref FIRST_TRANSACTION_TIMESTAMP_NANOSECONDS: u64 = 1_669_073_904_187_044_208;
        static ref LEDGER_REQUEST_1: Vec<u8> = encode_args((GetTransactionsRequest {
            start: i2nat(0),
            length: i2nat(BATCH_SIZE),
        },))
        .unwrap();
        static ref ARCHIVE_REQUEST_1: Vec<u8> = encode_args((GetTransactionsRequest {
            start: i2nat(2),
            length: i2nat(2),
        },))
        .unwrap();
        static ref LEDGER_REQUEST_2: Vec<u8> = encode_args((GetTransactionsRequest {
            start: i2nat(4),
            length: i2nat(BATCH_SIZE),
        },))
        .unwrap();
    }

    println!("\n");
    println!("LEDGER: {}", *LEDGER_CANISTER_ID);
    println!("ARCHIVE: {}", *ARCHIVE_CANISTER_ID);
    println!("\n");

    type Call = (
        (CanisterId, &'static str, &'static [u8]), // Call Arguments
        Result<Vec<u8>, (i32, String)>,            // Return Value
    );
    thread_local! {
        static EXPECTED_CALLS: RefCell<VecDeque<Call>> = {
            let ledger_request_1: &[u8] = &LEDGER_REQUEST_1;
            let archive_request_1: &[u8] = &ARCHIVE_REQUEST_1;
            let ledger_request_2: &[u8] = &LEDGER_REQUEST_2;

            let mut garbage = 531_157_996;
            let mut new_mint = |amount: u64| {
                garbage += 1;

                Transaction {
                    timestamp: *FIRST_TRANSACTION_TIMESTAMP_NANOSECONDS,
                    mint: Some(Mint {
                        amount: i2nat(amount),
                        created_at_time: Some(*FIRST_TRANSACTION_TIMESTAMP_NANOSECONDS),
                        to: Account {
                            owner: PrincipalId::new_user_test_id(garbage).0,
                            subaccount: None,
                        },
                        memo: None,
                    }),

                    kind: "mint".to_string(),

                    burn: None,
                    approve: None,
                    transfer: None,
                }
            };

            fn increase_timestamp(mut transaction: Transaction, nanoseconds: u64) -> Transaction {
                transaction.timestamp += nanoseconds;

                if let Some(created_at_time) = transaction
                    .mint
                    .as_mut()
                    .unwrap()
                    .created_at_time
                    .as_mut()
                {
                    *created_at_time += nanoseconds;
                }

                transaction
            }

            type Redirect = QueryArchiveFn<GetTransactionsRequest, TransactionRange>;
            type Range = ArchivedRange<Redirect>;

            let ledger_response_1 = encode_args((GetTransactionsResponse {
                transactions: vec![
                    new_mint(1),
                    new_mint(20),
                ],
                archived_transactions: vec![
                    Range {
                        start: i2nat(0),
                        length: i2nat(2),
                        callback: Redirect {
                            canister_id: PrincipalId::from(*ARCHIVE_CANISTER_ID).0,
                            method: "foo".to_string(),
                            _marker: Default::default(),
                        },
                    }
                ],
                first_index: i2nat(2),
                log_length: i2nat(7),
            },)).unwrap();

            let archive_response_1 = encode_args((TransactionRange {
                transactions: vec![
                    new_mint(300),
                    new_mint(4000),
                ],
            },)).unwrap();

            let ledger_response_2 = encode_args((GetTransactionsResponse {
                transactions: vec![
                    new_mint(50_000),
                    new_mint(600_000),
                    increase_timestamp(new_mint(7_000_000), 7),
                ],
                archived_transactions: vec![],
                first_index: i2nat(4),
                log_length: i2nat(7),
            },)).unwrap();

            RefCell::new(VecDeque::from([
                // 1
                (
                    (*LEDGER_CANISTER_ID, "get_transactions", ledger_request_1),
                    Ok(ledger_response_1),
                ),

                // 2
                (
                    (*ARCHIVE_CANISTER_ID, "foo", archive_request_1),
                    Ok(archive_response_1)
                ),

                // 3
                (
                    (*LEDGER_CANISTER_ID, "get_transactions", ledger_request_2),
                    Ok(ledger_response_2),
                ),
            ]))
        };
    }

    struct MockRuntime {}

    #[async_trait]
    impl Runtime for MockRuntime {
        async fn call_without_cleanup<In, Out>(
            _callee: CanisterId,
            _method: &str,
            _args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            unimplemented!()
        }

        async fn call_with_cleanup<In, Out>(
            callee: CanisterId,
            method: &str,
            args: In,
        ) -> Result<Out, (i32, String)>
        where
            In: ArgumentEncoder + Send,
            Out: for<'a> ArgumentDecoder<'a>,
        {
            let response =
                Self::call_bytes_with_cleanup(callee, method, &encode_args(args).unwrap()).await?;

            Ok(decode_args(&response).unwrap())
        }

        async fn call_bytes_with_cleanup(
            callee: CanisterId,
            method: &str,
            args: &[u8],
        ) -> Result<Vec<u8>, (i32, String)> {
            let (call_arguments, return_value) = EXPECTED_CALLS.with(|expected_calls| {
                expected_calls.borrow_mut().pop_front().unwrap_or_else(|| {
                    panic!("Unexpected call: {:?}", (callee, method, args));
                })
            });

            let args: &[u8] = call_arguments.2;
            let call_arguments = (call_arguments.0, call_arguments.1, args);
            assert_eq!((callee, method, args), call_arguments,);

            return_value
        }

        // Spawns a future.
        fn spawn_future<F: 'static + Future<Output = ()>>(_future: F) {
            unimplemented!()
        }
    }

    // Step 2: Call the code under test.

    let total_e8s: u64 = initial_supply_e8s::<MockRuntime>(
        *LEDGER_CANISTER_ID,
        InitialSupplyOptions {
            batch_size: BATCH_SIZE,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Step 3: Inspect results.

    assert_eq!(total_e8s, 654_321);

    EXPECTED_CALLS.with(|expected_calls| {
        assert_eq!(*expected_calls.borrow(), VecDeque::new());
    });
}
