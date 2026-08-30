use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icrc1_test_utils::basic_identity_strategy;
use ic_icrc1_test_utils::{DEFAULT_TRANSFER_FEE, minter_identity};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::models::ConstructionDeriveRequest;
use ic_rosetta_api::models::ConstructionMetadataRequest;
use ic_rosetta_api::models::ConstructionMetadataResponse;
use ic_rosetta_api::models::OperationIdentifier;
use ic_types::PrincipalId;
use icp_ledger::{AccountIdentifier, Block, Tokens};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use num_bigint::BigInt;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::PartialBlockIdentifier;
use rosetta_core::models::CurveType;
use rosetta_core::objects::Amount;
use rosetta_core::objects::Currency;
use rosetta_core::objects::Operation;
use rosetta_core::objects::PublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

/// Test that a transfer to the minting account (which the ledger converts to a
/// burn) produces a transaction hash mismatch between the Rosetta construction
/// API and the ledger block.
///
/// Rosetta is unaware of the minting account. It constructs a `Transfer`
/// operation, computes the transaction hash from that `Transfer`, and returns it
/// from `/construction/submit`. The ledger, however, converts the transfer into
/// a `Burn` operation when the destination is the minting account. Because the
/// hash is computed over the CBOR-serialized `Transaction` (which includes the
/// operation variant), the two hashes differ.
///
/// There is a related issue: a standard Rosetta integrator cannot construct a
/// burn at all using the documented flow. `build_transfer_operations` (and by
/// extension the `transfer` helper) always fetches the suggested fee from
/// `/construction/metadata` — which is the standard transfer fee (10_000 e8s) —
/// and embeds it in the FEE operation. The ledger, however, requires `fee == 0`
/// for burns (`assert_eq!(fee, Tokens::ZERO, …)` in `send`), so the call traps.
/// Even a custom integrator who follows the Rosetta spec (use the fee from
/// `/construction/metadata`) would hit the same rejection. The only workaround
/// is to manually construct operations with `fee = 0`, which requires out-of-band
/// knowledge that the destination is the minting account — information Rosetta
/// does not expose. This test uses the manual workaround.
///
/// This test documents the current (buggy) behavior.
#[test]
fn test_burn_via_construction_api_transaction_hash_mismatch() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let minting_identity = minter_identity();
        let minting_account: Account = minting_identity.sender().unwrap().into();
        let user_identity = Arc::new(test_identity());
        let user_principal = user_identity.sender().unwrap();
        let user_account_id = AccountIdentifier::new(PrincipalId(user_principal), None);

        // Give user1 enough ICP to cover the burn amount.
        let initial_balance = 1_000_000_000_u64; // 10 ICP
        let env = RosettaTestingEnvironment::builder()
            .with_minting_account(minting_account)
            .with_initial_balances(HashMap::from([(
                user_account_id,
                Tokens::from_e8s(initial_balance),
            )]))
            .build()
            .await;

        let network_id = env.network_identifier.clone();

        // Build transfer operations that target the minting account.
        // Burns require fee = 0 on the ledger side, so we construct the
        // operations manually rather than using `build_transfer_operations`
        // (which would include the standard transfer fee).
        let burn_amount = 100_000_000_u64; // 1 ICP
        let minting_account_id: AccountIdentifier = minting_account.into();
        let currency = Currency {
            symbol: "ICP".to_string(),
            decimals: 8,
            metadata: None,
        };

        let transfer_from_op = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSACTION".to_string(),
            status: None,
            account: Some(user_account_id.into()),
            amount: Some(Amount::new(
                BigInt::from(-(burn_amount as i128)),
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        let transfer_to_op = Operation {
            operation_identifier: OperationIdentifier {
                index: 1,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSACTION".to_string(),
            status: None,
            account: Some(minting_account_id.into()),
            amount: Some(Amount::new(
                BigInt::from(burn_amount as i128),
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        let fee_op = Operation {
            operation_identifier: OperationIdentifier {
                index: 2,
                network_index: None,
            },
            related_operations: None,
            type_: "FEE".to_string(),
            status: None,
            account: Some(user_account_id.into()),
            amount: Some(Amount::new(BigInt::from(0), currency.clone())),
            coin_change: None,
            metadata: None,
        };

        let operations = vec![transfer_from_op, transfer_to_op, fee_op];

        // Submit the transaction through the full construction flow.
        let submit_response = env
            .rosetta_client
            .make_submit_and_wait_for_transaction(
                &user_identity,
                network_id.clone(),
                operations,
                Some(0_u64), // memo
                None,        // created_at_time (Rosetta will generate one)
            )
            .await
            .expect("Failed to submit burn transaction via Rosetta construction API");

        let rosetta_returned_hash = submit_response.transaction_identifier.hash.clone();

        // Wait for Rosetta to sync the new block.
        // The ledger starts with a genesis mint block (index 0), so the burn
        // will land at block index 1.
        let burn_block_index = 1_u64;
        wait_for_rosetta_to_sync_up_to_block(
            &env.rosetta_client,
            network_id.clone(),
            burn_block_index,
        )
        .await
        .expect("Rosetta did not sync up to the burn block");

        // Fetch the block from Rosetta and extract the transaction hash.
        let block_response = env
            .rosetta_client
            .block(
                network_id.clone(),
                PartialBlockIdentifier {
                    index: Some(burn_block_index),
                    hash: None,
                },
            )
            .await
            .expect("Failed to fetch burn block from Rosetta");

        let block = block_response.block.expect("Block should be present");
        assert_eq!(
            block.transactions.len(),
            1,
            "Burn block should contain exactly one transaction"
        );
        let ledger_tx_hash = block.transactions[0].transaction_identifier.hash.clone();

        // Verify that the block contains a BURN operation (not a transfer).
        let ops = &block.transactions[0].operations;
        assert_eq!(ops.len(), 1, "A burn should have exactly one operation");
        assert_eq!(
            ops[0].type_, "BURN",
            "The operation type should be BURN, not TRANSACTION"
        );

        // Query the raw block from the ledger to get the actual transaction
        // (including memo and created_at_time) for hash verification.
        let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;
        let encoded_blocks = query_encoded_blocks(&agent, burn_block_index, 1).await;
        let raw_block = Block::decode(encoded_blocks.blocks[0].clone()).unwrap();
        let ledger_tx = raw_block.transaction.clone();

        // The ledger must have stored this as a Burn, not a Transfer.
        assert!(
            matches!(ledger_tx.operation, icp_ledger::Operation::Burn { .. }),
            "Ledger should have stored the transaction as a Burn, got: {:?}",
            ledger_tx.operation
        );

        // The hash from the Rosetta block endpoint must match the hash we
        // compute locally from the ledger transaction.
        let expected_burn_hash = format!("{}", ledger_tx.hash());
        assert_eq!(
            ledger_tx_hash, expected_burn_hash,
            "The transaction hash in the Rosetta block should match the hash \
             computed from the raw ledger transaction"
        );

        // Build what Rosetta *thinks* the hash should be (a Transfer, not a
        // Burn). Transaction::new always creates Operation::Transfer.
        let created_at_time = ledger_tx
            .created_at_time
            .expect("created_at_time should be set");
        let rosetta_expected_tx = icp_ledger::Transaction::new(
            user_account_id,
            minting_account_id,
            None, // spender
            Tokens::from_e8s(burn_amount),
            Tokens::ZERO, // fee
            ledger_tx.memo,
            created_at_time,
        );
        let rosetta_computed_hash = format!("{}", rosetta_expected_tx.hash());

        // Confirm that the Rosetta-returned hash matches the Transfer-based
        // hash (i.e., Rosetta computed a hash assuming Transfer).
        assert_eq!(
            rosetta_returned_hash, rosetta_computed_hash,
            "Rosetta should have returned a hash computed from a Transfer \
             operation"
        );

        // Verify that the hash Rosetta returned (based on Transfer) does NOT match
        // the hash in the ledger block (based on Burn).
        assert_ne!(
            rosetta_returned_hash, ledger_tx_hash,
            "BUG: Rosetta's transaction hash (Transfer-based) should differ \
             from the ledger's transaction hash (Burn-based). If this \
             assertion fails, the bug has been fixed and this test should be \
             updated to assert_eq!"
        );
    });
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
                    value: format!("{DEFAULT_TRANSFER_FEE}"),
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
