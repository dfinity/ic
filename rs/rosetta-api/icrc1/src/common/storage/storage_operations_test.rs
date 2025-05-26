use candid::{Nat, Principal};
use ic_icrc_rosetta::common::storage::schema;
use ic_icrc_rosetta::common::storage::storage_operations::*;
use ic_icrc_rosetta::common::storage::types::{
    IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
};
use icrc_ledger_types::icrc1::account::Account;
use rusqlite::{params, Connection};
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
    schema::create_tables(&connection)?;

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
    schema::create_tables(&connection)?;

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
    schema::create_tables(&connection)?;

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
    store_blocks(
        &mut connection,
        vec![block0.clone(), block1.clone(), block2.clone()],
    )?;

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
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("no block at that index"));

    // Test with a block that references a block without a fee collector
    let mut block4 = create_test_rosetta_block(4, 1000000004, &principal1, 500);
    block4.block.fee_collector = None;
    block4.block.fee_collector_block_index = Some(2); // Block 2 has no fee collector

    store_blocks(&mut connection, vec![block4.clone()])?;

    // This should return an error
    let result = get_fee_collector_from_block(&block4, &connection);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("has no fee_collector set"));

    Ok(())
}

#[test]
fn test_repair_fee_collector_balances() -> anyhow::Result<()> {
    // Create a temporary directory and database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_repair_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;
    schema::create_tables(&connection)?;

    // Create test accounts
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];
    let fee_collector_principal = vec![9, 10, 11, 12];

    let from_account = Account {
        owner: Principal::from_slice(&principal1),
        subaccount: None,
    };
    let to_account = Account {
        owner: Principal::from_slice(&principal2),
        subaccount: None,
    };
    let fee_collector_account = Account {
        owner: Principal::from_slice(&fee_collector_principal),
        subaccount: None,
    };

    // Create a mint block to give the from_account initial tokens
    let mut mint_block = create_test_rosetta_block(0, 999999999, &principal1, 1000000000);
    mint_block.block.transaction.operation = IcrcOperation::Mint {
        to: from_account,
        amount: Nat::from(1000000000u64),
    };
    mint_block.index = 0;

    // Create block 1 with direct fee collector specification
    let mut block1 = create_test_rosetta_block(1, 1000000000, &principal1, 100);
    block1.block.fee_collector = Some(fee_collector_account);
    // Fix the transfer to go to the correct recipient
    block1.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(100u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Create block 2 with fee_collector_block_index pointing to block 1
    // This simulates a block that was processed before our fix
    let mut block2 = create_test_rosetta_block(2, 1000000001, &principal1, 200);
    block2.block.fee_collector = None;
    block2.block.fee_collector_block_index = Some(1);
    // Fix the transfer to go to the correct recipient
    block2.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(200u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Store all blocks
    store_blocks(
        &mut connection,
        vec![mint_block.clone(), block1.clone(), block2.clone()],
    )?;

    // Test that the repair function works by simply calling it
    // Since we're clearing and rebuilding all balances, we don't need to simulate broken state
    repair_fee_collector_balances(&mut connection)?;

    // Verify that all balances are correctly calculated
    // Block 0: Mint 1000000000 to from_account
    let from_balance_at_0 = get_account_balance_at_block_idx(&connection, &from_account, 0)?;
    assert_eq!(from_balance_at_0, Some(Nat::from(1000000000u64)));

    // Block 1: Transfer 100, fee 1 - fee collector should be credited
    let from_balance_at_1 = get_account_balance_at_block_idx(&connection, &from_account, 1)?;
    assert_eq!(from_balance_at_1, Some(Nat::from(999999899u64))); // -101

    let to_balance_at_1 = get_account_balance_at_block_idx(&connection, &to_account, 1)?;
    assert_eq!(to_balance_at_1, Some(Nat::from(100u64)));

    let fee_collector_balance_at_1 =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 1)?;
    assert_eq!(fee_collector_balance_at_1, Some(Nat::from(1u64))); // Fee correctly credited

    // Block 2: Transfer 200, fee 1 - fee collector should be credited via fee_collector_block_index
    let from_balance_at_2 = get_account_balance_at_block_idx(&connection, &from_account, 2)?;
    assert_eq!(from_balance_at_2, Some(Nat::from(999999698u64))); // -201 more

    let to_balance_at_2 = get_account_balance_at_block_idx(&connection, &to_account, 2)?;
    assert_eq!(to_balance_at_2, Some(Nat::from(300u64))); // +200 more

    let fee_collector_balance_at_2 =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 2)?;
    assert_eq!(fee_collector_balance_at_2, Some(Nat::from(2u64))); // Fee correctly credited via block index resolution

    // Verify that running the repair again doesn't change anything (idempotent)
    repair_fee_collector_balances(&mut connection)?;

    let fee_collector_balance_after_second_repair =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 2)?;
    assert_eq!(
        fee_collector_balance_after_second_repair,
        Some(Nat::from(2u64))
    ); // Still 2

    Ok(())
}

#[test]
fn test_repair_fee_collector_balances_counter_check() -> anyhow::Result<()> {
    // Create a temporary directory and database
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_repair_counter_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;
    schema::create_tables(&connection)?;

    // Create test accounts
    let principal1 = vec![1, 2, 3, 4];
    let from_account = Account {
        owner: Principal::from_slice(&principal1),
        subaccount: None,
    };

    // Create a mint block to give the from_account initial tokens
    let mut mint_block = create_test_rosetta_block(0, 999999999, &principal1, 1000000000);
    mint_block.block.transaction.operation = IcrcOperation::Mint {
        to: from_account,
        amount: Nat::from(1000000000u64),
    };
    mint_block.index = 0;

    // Store the block
    store_blocks(&mut connection, vec![mint_block.clone()])?;

    // Verify that the counter doesn't exist initially
    let counter_exists_before = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(!counter_exists_before, "Counter should not exist initially");

    // Run the repair function for the first time
    repair_fee_collector_balances(&mut connection)?;

    // Verify that the counter now exists
    let counter_exists_after = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(
        counter_exists_after,
        "Counter should exist after first repair"
    );

    // Verify that the account balance was created
    let from_balance = get_account_balance_at_block_idx(&connection, &from_account, 0)?;
    assert_eq!(from_balance, Some(Nat::from(1000000000u64)));

    // Clear the account balances to simulate what would happen if repair ran again
    connection.execute("DELETE FROM account_balances", params![])?;

    // Verify that account balance is now empty
    let from_balance_after_clear = get_account_balance_at_block_idx(&connection, &from_account, 0)?;
    assert_eq!(from_balance_after_clear, None);

    // Run the repair function again - it should skip the repair due to the counter
    repair_fee_collector_balances(&mut connection)?;

    // Verify that the account balance is still empty (repair was skipped)
    let from_balance_after_second_repair =
        get_account_balance_at_block_idx(&connection, &from_account, 0)?;
    assert_eq!(
        from_balance_after_second_repair, None,
        "Repair should have been skipped due to counter"
    );

    Ok(())
}

#[test]
fn test_repair_fee_collector_balances_empty_db() -> anyhow::Result<()> {
    // Test scenario: Empty database (no blocks, no account balances)
    // This should complete successfully without doing anything

    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_empty_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;
    schema::create_tables(&connection)?;

    // Verify database is empty
    let block_count = connection
        .prepare_cached("SELECT COUNT(*) FROM blocks")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .unwrap()?;
    assert_eq!(block_count, 0, "Database should be empty initially");

    let balance_count = connection
        .prepare_cached("SELECT COUNT(*) FROM account_balances")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .unwrap()?;
    assert_eq!(
        balance_count, 0,
        "Account balances should be empty initially"
    );

    // Verify that the counter doesn't exist initially
    let counter_exists_before = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(!counter_exists_before, "Counter should not exist initially");

    // Run the repair function on empty database
    repair_fee_collector_balances(&mut connection)?;

    // Verify that the counter now exists (repair completed successfully)
    let counter_exists_after = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(
        counter_exists_after,
        "Counter should exist after repair on empty DB"
    );

    // Verify database is still empty (no blocks or balances were created)
    let block_count_after = connection
        .prepare_cached("SELECT COUNT(*) FROM blocks")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .unwrap()?;
    assert_eq!(
        block_count_after, 0,
        "Database should still be empty after repair"
    );

    let balance_count_after = connection
        .prepare_cached("SELECT COUNT(*) FROM account_balances")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .unwrap()?;
    assert_eq!(
        balance_count_after, 0,
        "Account balances should still be empty after repair"
    );

    // Run repair again to verify it's skipped
    repair_fee_collector_balances(&mut connection)?;

    // Verify counter still exists and database is still empty
    let counter_exists_final = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(
        counter_exists_final,
        "Counter should still exist after second repair"
    );

    Ok(())
}

#[test]
fn test_repair_fee_collector_balances_already_fixed_db() -> anyhow::Result<()> {
    // Test scenario: Database that already has the fix applied (counter exists)
    // This should skip the repair entirely

    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_already_fixed_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;
    schema::create_tables(&connection)?;

    // Create test accounts
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];
    let fee_collector_principal = vec![9, 10, 11, 12];

    let from_account = Account {
        owner: Principal::from_slice(&principal1),
        subaccount: None,
    };
    let to_account = Account {
        owner: Principal::from_slice(&principal2),
        subaccount: None,
    };
    let fee_collector_account = Account {
        owner: Principal::from_slice(&fee_collector_principal),
        subaccount: None,
    };

    // Create a mint block and a transfer block with fee_collector_block_index
    let mut mint_block = create_test_rosetta_block(0, 999999999, &principal1, 1000000000);
    mint_block.block.transaction.operation = IcrcOperation::Mint {
        to: from_account,
        amount: Nat::from(1000000000u64),
    };
    mint_block.index = 0;

    let mut block1 = create_test_rosetta_block(1, 1000000000, &principal1, 100);
    block1.block.fee_collector = Some(fee_collector_account);
    block1.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(100u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    let mut block2 = create_test_rosetta_block(2, 1000000001, &principal1, 200);
    block2.block.fee_collector = None;
    block2.block.fee_collector_block_index = Some(1); // References block 1 for fee collector
    block2.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(200u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Store all blocks
    store_blocks(
        &mut connection,
        vec![mint_block.clone(), block1.clone(), block2.clone()],
    )?;

    // Manually set up correct account balances (simulating a database that was already fixed)
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (0, ?1, ?2, '1000000000')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '999999899')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '100')", 
        params![to_account.owner.as_slice(), to_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '1')", 
        params![fee_collector_account.owner.as_slice(), fee_collector_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (2, ?1, ?2, '999999698')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (2, ?1, ?2, '300')", 
        params![to_account.owner.as_slice(), to_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (2, ?1, ?2, '2')", 
        params![fee_collector_account.owner.as_slice(), fee_collector_account.effective_subaccount().as_slice()])?;

    // Manually add the "already fixed" counter to simulate a database that was already repaired
    connection.execute(
        "INSERT INTO counters (name, value) VALUES ('collector_balances_fixed', 1)",
        params![],
    )?;

    // Verify the counter exists before repair
    let counter_exists_before = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(
        counter_exists_before,
        "Counter should exist (simulating already fixed DB)"
    );

    // Verify the correct balances exist before repair
    let fee_collector_balance_before =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 2)?;
    assert_eq!(
        fee_collector_balance_before,
        Some(Nat::from(2u64)),
        "Fee collector should have correct balance before repair"
    );

    // Run the repair function - it should skip the repair due to existing counter
    repair_fee_collector_balances(&mut connection)?;

    // Verify that the balances are unchanged (repair was skipped)
    let fee_collector_balance_after =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 2)?;
    assert_eq!(
        fee_collector_balance_after,
        Some(Nat::from(2u64)),
        "Fee collector balance should be unchanged (repair skipped)"
    );

    let from_balance_after = get_account_balance_at_block_idx(&connection, &from_account, 2)?;
    assert_eq!(
        from_balance_after,
        Some(Nat::from(999999698u64)),
        "From account balance should be unchanged"
    );

    let to_balance_after = get_account_balance_at_block_idx(&connection, &to_account, 2)?;
    assert_eq!(
        to_balance_after,
        Some(Nat::from(300u64)),
        "To account balance should be unchanged"
    );

    // Verify counter still exists
    let counter_exists_after = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(
        counter_exists_after,
        "Counter should still exist after repair"
    );

    Ok(())
}

#[test]
fn test_repair_fee_collector_balances_broken_state() -> anyhow::Result<()> {
    // Test scenario: Database with broken fee collector balances (simulating pre-fix state)
    // This should detect and fix the missing fee collector credits

    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_broken_state_db.sqlite");

    // Create and initialize database with necessary tables
    let mut connection = Connection::open(&db_path)?;
    schema::create_tables(&connection)?;

    // Create test accounts
    let principal1 = vec![1, 2, 3, 4];
    let principal2 = vec![5, 6, 7, 8];
    let fee_collector_principal = vec![9, 10, 11, 12];

    let from_account = Account {
        owner: Principal::from_slice(&principal1),
        subaccount: None,
    };
    let to_account = Account {
        owner: Principal::from_slice(&principal2),
        subaccount: None,
    };
    let fee_collector_account = Account {
        owner: Principal::from_slice(&fee_collector_principal),
        subaccount: None,
    };

    // Create blocks that would have been processed before the fix
    let mut mint_block = create_test_rosetta_block(0, 999999999, &principal1, 1000000000);
    mint_block.block.transaction.operation = IcrcOperation::Mint {
        to: from_account,
        amount: Nat::from(1000000000u64),
    };
    mint_block.index = 0;

    // Block 1: Direct fee collector (this would have worked correctly before the fix)
    let mut block1 = create_test_rosetta_block(1, 1000000000, &principal1, 100);
    block1.block.fee_collector = Some(fee_collector_account);
    block1.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(100u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Block 2: Uses fee_collector_block_index (this would have been broken before the fix)
    let mut block2 = create_test_rosetta_block(2, 1000000001, &principal1, 200);
    block2.block.fee_collector = None;
    block2.block.fee_collector_block_index = Some(1); // References block 1 for fee collector
    block2.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(200u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Block 3: Another block using fee_collector_block_index
    let mut block3 = create_test_rosetta_block(3, 1000000002, &principal1, 300);
    block3.block.fee_collector = None;
    block3.block.fee_collector_block_index = Some(1); // References block 1 for fee collector
    block3.block.transaction.operation = IcrcOperation::Transfer {
        from: from_account,
        to: to_account,
        amount: Nat::from(300u64),
        fee: Some(Nat::from(1u64)),
        spender: None,
    };

    // Store all blocks
    store_blocks(
        &mut connection,
        vec![
            mint_block.clone(),
            block1.clone(),
            block2.clone(),
            block3.clone(),
        ],
    )?;

    // Manually set up BROKEN account balances (simulating the pre-fix state)
    // The bug was that fee collectors weren't credited for blocks using fee_collector_block_index

    // Block 0: Mint - this would be correct
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (0, ?1, ?2, '1000000000')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;

    // Block 1: Transfer with direct fee collector - this would be correct
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '999999899')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '100')", 
        params![to_account.owner.as_slice(), to_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (1, ?1, ?2, '1')", 
        params![fee_collector_account.owner.as_slice(), fee_collector_account.effective_subaccount().as_slice()])?;

    // Block 2: Transfer with fee_collector_block_index - BROKEN (fee collector not credited)
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (2, ?1, ?2, '999999698')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (2, ?1, ?2, '300')", 
        params![to_account.owner.as_slice(), to_account.effective_subaccount().as_slice()])?;
    // NOTE: Fee collector balance is NOT updated here - this is the bug!

    // Block 3: Another transfer with fee_collector_block_index - BROKEN (fee collector not credited)
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (3, ?1, ?2, '999999397')", 
        params![from_account.owner.as_slice(), from_account.effective_subaccount().as_slice()])?;
    connection.execute("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (3, ?1, ?2, '600')", 
        params![to_account.owner.as_slice(), to_account.effective_subaccount().as_slice()])?;
    // NOTE: Fee collector balance is NOT updated here either - this is the bug!

    // Verify the broken state before repair
    let fee_collector_balance_before =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 3)?;
    assert_eq!(
        fee_collector_balance_before,
        Some(Nat::from(1u64)),
        "Fee collector should only have 1 token (broken state)"
    );

    let from_balance_before = get_account_balance_at_block_idx(&connection, &from_account, 3)?;
    assert_eq!(
        from_balance_before,
        Some(Nat::from(999999397u64)),
        "From account should have incorrect balance (broken state)"
    );

    // Verify that the counter doesn't exist initially
    let counter_exists_before = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(!counter_exists_before, "Counter should not exist initially");

    // Run the repair function - this should fix the broken state
    repair_fee_collector_balances(&mut connection)?;

    // Verify that the balances are now CORRECT after repair
    let fee_collector_balance_after =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 3)?;
    assert_eq!(
        fee_collector_balance_after,
        Some(Nat::from(3u64)),
        "Fee collector should now have 3 tokens (1+1+1 fees)"
    );

    let from_balance_after = get_account_balance_at_block_idx(&connection, &from_account, 3)?;
    assert_eq!(
        from_balance_after,
        Some(Nat::from(999999397u64)),
        "From account balance should be correct"
    );

    let to_balance_after = get_account_balance_at_block_idx(&connection, &to_account, 3)?;
    assert_eq!(
        to_balance_after,
        Some(Nat::from(600u64)),
        "To account balance should be correct"
    );

    // Verify that the counter now exists (repair completed)
    let counter_exists_after = connection
        .prepare_cached("SELECT value FROM counters WHERE name = 'collector_balances_fixed'")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .is_some();
    assert!(counter_exists_after, "Counter should exist after repair");

    // Run repair again to verify it's skipped and balances remain correct
    repair_fee_collector_balances(&mut connection)?;

    let fee_collector_balance_final =
        get_account_balance_at_block_idx(&connection, &fee_collector_account, 3)?;
    assert_eq!(
        fee_collector_balance_final,
        Some(Nat::from(3u64)),
        "Fee collector balance should remain correct after second repair"
    );

    Ok(())
}
