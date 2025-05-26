use candid::{Nat, Principal};
use ic_icrc_rosetta::common::storage::schema;
use ic_icrc_rosetta::common::storage::storage_operations::*;
use ic_icrc_rosetta::common::storage::types::{
    IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
};
use icrc_ledger_types::icrc1::account::Account;
use rusqlite::Connection;
use tempfile::tempdir;

// Helper function to create a test block with a specific timestamp and data
fn create_test_rosetta_block(
    index: u64,
    timestamp: u64,
    principal: &[u8],
    amount: u64,
) -> RosettaBlock {
    // Create owner account
    let owner = Account {
        owner: Principal::from_slice(principal),
        subaccount: None,
    };

    // Create recipient account (just use a different principal)
    let mut recipient_principal = principal.to_vec();
    if !recipient_principal.is_empty() {
        recipient_principal[0] = recipient_principal[0].wrapping_add(1);
    }
    let recipient = Account {
        owner: Principal::from_slice(&recipient_principal),
        subaccount: None,
    };

    // Create a transfer transaction
    let transaction = IcrcTransaction {
        operation: IcrcOperation::Transfer {
            from: owner,
            to: recipient,
            amount: Nat::from(amount),
            fee: Some(Nat::from(1u64)),
            spender: None,
        },
        memo: None,
        created_at_time: Some(timestamp),
    };

    // Create a block with the transaction
    let icrc_block = IcrcBlock {
        parent_hash: None,
        transaction,
        timestamp,
        effective_fee: None,
        fee_collector: None,
        fee_collector_block_index: None,
    };

    RosettaBlock {
        index,
        block: icrc_block,
    }
}

// Helper function to create a test block with an approve operation and specified timestamps
fn create_test_approve_block(
    index: u64,
    block_timestamp: u64,
    created_at_time: u64,
    expires_at: u64,
    principal: &[u8],
) -> RosettaBlock {
    // Create owner account
    let owner = Account {
        owner: Principal::from_slice(principal),
        subaccount: None,
    };

    // Create spender account (just use a different principal)
    let mut spender_principal = principal.to_vec();
    if !spender_principal.is_empty() {
        spender_principal[0] = spender_principal[0].wrapping_add(1);
    }
    let spender = Account {
        owner: Principal::from_slice(&spender_principal),
        subaccount: None,
    };

    // Create an approve transaction
    let transaction = IcrcTransaction {
        operation: IcrcOperation::Approve {
            from: owner,
            spender,
            amount: Nat::from(1000u64),
            expected_allowance: None,
            expires_at: Some(expires_at),
            fee: Some(Nat::from(1u64)),
        },
        memo: None,
        created_at_time: Some(created_at_time),
    };

    // Create a block with the transaction
    let icrc_block = IcrcBlock {
        parent_hash: None,
        transaction,
        timestamp: block_timestamp,
        effective_fee: None,
        fee_collector: None,
        fee_collector_block_index: None,
    };

    RosettaBlock {
        index,
        block: icrc_block,
    }
}

#[test]
fn test_store_and_read_blocks() -> anyhow::Result<()> {
    // Create a temporary directory and database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_blocks_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;

    // Create the database tables using the centralized schema
    schema::create_basic_tables(&connection)?;

    // Create test data
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];

    // Create timestamps of different sizes
    let normal_timestamp = 1000000000u64;
    let max_timestamp = i64::MAX as u64;
    let beyond_max_timestamp = max_timestamp + 1;
    let very_large_timestamp = u64::MAX;

    // Create blocks with transfer operations and different block timestamps
    let block0 = create_test_rosetta_block(0, normal_timestamp, &principal1, 100);
    let block1 = create_test_rosetta_block(1, max_timestamp, &principal1, 200);
    let block2 = create_test_rosetta_block(2, beyond_max_timestamp, &principal2, 300);
    let block3 = create_test_rosetta_block(3, very_large_timestamp, &principal2, 400);

    // Create a block with an approve operation that has approval_expires_at timestamp
    let block4 = create_test_approve_block(
        4,
        normal_timestamp,     // block timestamp
        beyond_max_timestamp, // created_at_time
        very_large_timestamp, // expires_at
        &principal1,
    );

    // Test storing blocks
    store_blocks(
        &mut connection,
        vec![
            block0.clone(),
            block1.clone(),
            block2.clone(),
            block3.clone(),
            block4.clone(),
        ],
    )?;

    // Test get_block_at_idx
    let retrieved_block0 = get_block_at_idx(&connection, 0)?.unwrap();
    let retrieved_block1 = get_block_at_idx(&connection, 1)?.unwrap();
    let retrieved_block2 = get_block_at_idx(&connection, 2)?.unwrap();
    let retrieved_block3 = get_block_at_idx(&connection, 3)?.unwrap();
    let retrieved_block4 = get_block_at_idx(&connection, 4)?.unwrap();

    // Verify all blocks were retrieved correctly - block timestamps
    assert_eq!(retrieved_block0.index, block0.index);
    assert_eq!(retrieved_block0.get_timestamp(), normal_timestamp);

    assert_eq!(retrieved_block1.index, block1.index);
    assert_eq!(retrieved_block1.get_timestamp(), max_timestamp);

    assert_eq!(retrieved_block2.index, block2.index);
    assert_eq!(retrieved_block2.get_timestamp(), beyond_max_timestamp);

    assert_eq!(retrieved_block3.index, block3.index);
    assert_eq!(retrieved_block3.get_timestamp(), very_large_timestamp);

    // Verify transaction_created_at_time is preserved for all blocks
    assert_eq!(
        retrieved_block0.block.transaction.created_at_time,
        block0.block.transaction.created_at_time
    );

    assert_eq!(
        retrieved_block2.block.transaction.created_at_time,
        block2.block.transaction.created_at_time
    );

    assert_eq!(
        retrieved_block3.block.transaction.created_at_time,
        block3.block.transaction.created_at_time
    );

    // Verify approve operation specific fields on block4
    match &retrieved_block4.block.transaction.operation {
        IcrcOperation::Approve { expires_at, .. } => {
            // Verify approval_expires_at timestamp is preserved
            assert_eq!(
                *expires_at,
                Some(very_large_timestamp),
                "approval_expires_at timestamp not preserved correctly"
            );
        }
        _ => panic!("Expected Approve operation for block4"),
    }

    // Verify created_at_time is preserved for the approve block
    assert_eq!(
        retrieved_block4.block.transaction.created_at_time,
        Some(beyond_max_timestamp),
        "transaction_created_at_time not preserved correctly for approve block"
    );

    Ok(())
}

#[test]
fn test_hash_consistency() -> anyhow::Result<()> {
    // Create a temporary directory and database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_hash_db.sqlite");

    // Initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;

    // Create the database tables using the centralized schema
    schema::create_basic_tables(&connection)?;

    // Create test data - blocks with different timestamp values and operations
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];

    // Create blocks with different timestamps and operations
    let normal_timestamp = 1000000000u64;
    let max_timestamp = i64::MAX as u64;
    let beyond_max_timestamp = max_timestamp + 1;

    // Create blocks for testing
    let blocks = vec![
        create_test_rosetta_block(0, normal_timestamp, &principal1, 100),
        create_test_rosetta_block(1, max_timestamp, &principal1, 200),
        create_test_rosetta_block(2, beyond_max_timestamp, &principal2, 300),
        create_test_approve_block(
            3,
            normal_timestamp,
            beyond_max_timestamp,
            max_timestamp,
            &principal1,
        ),
    ];

    // Record original hashes for comparison
    let original_block_hashes: Vec<_> = blocks
        .iter()
        .map(|block| block.clone().get_block_hash())
        .collect();

    let original_tx_hashes: Vec<_> = blocks
        .iter()
        .map(|block| block.clone().get_transaction_hash())
        .collect();

    // Store blocks in the database
    store_blocks(&mut connection, blocks.clone())?;

    // Retrieve blocks from the database
    let retrieved_blocks: Vec<_> = (0..blocks.len())
        .map(|idx| get_block_at_idx(&connection, idx as u64).unwrap().unwrap())
        .collect();

    // Verify block hashes match the original values
    for (i, block) in retrieved_blocks.iter().enumerate() {
        assert_eq!(
            block.clone().get_block_hash(),
            original_block_hashes[i],
            "Block hash mismatch for block index {}",
            i
        );

        assert_eq!(
            block.clone().get_transaction_hash(),
            original_tx_hashes[i],
            "Transaction hash mismatch for block index {}",
            i
        );
    }

    // Test retrieving blocks by hash
    for (i, original_hash) in original_block_hashes.iter().enumerate() {
        let block_by_hash = get_block_by_hash(&connection, original_hash.clone())?
            .unwrap_or_else(|| panic!("Block with hash {:?} not found", original_hash));

        assert_eq!(
            block_by_hash.index, i as u64,
            "Retrieved wrong block by hash for index {}",
            i
        );

        assert_eq!(
            block_by_hash.clone().get_block_hash(),
            original_block_hashes[i],
            "Block hash doesn't match for block retrieved by hash, index {}",
            i
        );
    }

    // Test retrieving blocks by transaction hash
    for (i, original_tx_hash) in original_tx_hashes.iter().enumerate() {
        let blocks_by_tx = get_blocks_by_transaction_hash(&connection, original_tx_hash.clone())?;

        assert_eq!(
            blocks_by_tx.len(),
            1,
            "Expected exactly one block with transaction hash {:?}",
            original_tx_hash
        );

        assert_eq!(
            blocks_by_tx[0].index, i as u64,
            "Retrieved wrong block by transaction hash for index {}",
            i
        );

        assert_eq!(
            blocks_by_tx[0].clone().get_block_hash(),
            original_block_hashes[i],
            "Block hash doesn't match for block retrieved by transaction hash, index {}",
            i
        );

        assert_eq!(
            blocks_by_tx[0].clone().get_transaction_hash(),
            original_tx_hashes[i],
            "Transaction hash doesn't match for block retrieved by transaction hash, index {}",
            i
        );
    }

    Ok(())
}

#[test]
fn test_fee_collector_block_index_resolution() -> anyhow::Result<()> {
    // Create a temporary directory and database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_fee_collector_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;

    // Create the database tables using the centralized schema
    schema::create_basic_tables(&connection)?;

    // Create test accounts
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];
    let fee_collector_principal = vec![9, 10, 11, 12];

    let _from_account = Account {
        owner: Principal::from_slice(&principal1),
        subaccount: None,
    };
    let _to_account = Account {
        owner: Principal::from_slice(&principal2),
        subaccount: None,
    };
    let fee_collector_account = Account {
        owner: Principal::from_slice(&fee_collector_principal),
        subaccount: None,
    };

    // Create block 0 with direct fee collector specification
    let mut block0 = create_test_rosetta_block(0, 1000000000, &principal1, 100);
    block0.block.fee_collector = Some(fee_collector_account);

    // Create block 1 with fee_collector_block_index pointing to block 0
    let mut block1 = create_test_rosetta_block(1, 1000000001, &principal1, 200);
    block1.block.fee_collector = None;
    block1.block.fee_collector_block_index = Some(0);

    // Create block 2 with no fee collector
    let block2 = create_test_rosetta_block(2, 1000000002, &principal1, 300);

    // Store the blocks
    store_blocks(&mut connection, vec![block0.clone(), block1.clone(), block2.clone()])?;

    // Test the fee collector resolution function directly
    let resolved_collector_0 = get_fee_collector_from_block(&block0, &connection)?;
    let resolved_collector_1 = get_fee_collector_from_block(&block1, &connection)?;
    let resolved_collector_2 = get_fee_collector_from_block(&block2, &connection)?;

    // Verify that block 0 returns its direct fee collector
    assert_eq!(resolved_collector_0, Some(fee_collector_account));

    // Verify that block 1 resolves the fee collector from block 0
    assert_eq!(resolved_collector_1, Some(fee_collector_account));

    // Verify that block 2 has no fee collector
    assert_eq!(resolved_collector_2, None);

    // Test with a block that references a non-existent block
    let mut block3 = create_test_rosetta_block(3, 1000000003, &principal1, 400);
    block3.block.fee_collector = None;
    block3.block.fee_collector_block_index = Some(999); // Non-existent block

    store_blocks(&mut connection, vec![block3.clone()])?;

    // This should return an error
    let result = get_fee_collector_from_block(&block3, &connection);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no block at that index"));

    // Test with a block that references a block without a fee collector
    let mut block4 = create_test_rosetta_block(4, 1000000004, &principal1, 500);
    block4.block.fee_collector = None;
    block4.block.fee_collector_block_index = Some(2); // Block 2 has no fee collector

    store_blocks(&mut connection, vec![block4.clone()])?;

    // This should return an error
    let result = get_fee_collector_from_block(&block4, &connection);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("has no fee_collector set"));

    Ok(())
}
