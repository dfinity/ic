use ic_icrc1::blocks::{
    encoded_block_to_generic_block, generic_block_to_encoded_block,
    generic_transaction_from_generic_block,
};
use ic_icrc1::{Block, Transaction};
use ic_icrc1_test_utils::blocks_strategy;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::BlockType;

use proptest::prelude::*;

proptest! {
    #[test]
    fn test_generic_block_to_encoded_block_conversion(block in blocks_strategy()) {
        // for any possible block, assert that the conversion
        // block->encoded_block->generic_block->encoded_block->block
        // returns the original block
        let generic_block = encoded_block_to_generic_block(&block.clone().encode());
        let encoded_block = generic_block_to_encoded_block(generic_block).unwrap();
        assert_eq!(block, Block::decode(encoded_block).unwrap());
    }

    #[test]
        fn test_generic_transaction_hash(block in blocks_strategy()) {

            // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
            let generic_block = encoded_block_to_generic_block(&block.clone().encode());

            //Convert generic block to generic transaction
            let generic_transaction = generic_transaction_from_generic_block(generic_block).unwrap();

            //Check that the hash of the generic transaction and the transaction object are the same
            assert_eq!(generic_transaction.hash().to_vec(), <Transaction as LedgerTransaction>::hash(&block.transaction).as_slice().to_vec());
        }
}
