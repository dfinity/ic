use ic_icrc1::blocks::{
    encoded_block_to_generic_block, generic_block_to_encoded_block,
    generic_transaction_from_generic_block,
};
use ic_icrc1::{Block, Transaction};
use ic_icrc1_test_utils::{arb_small_amount, blocks_strategy};
use ic_icrc1_tokens_u256::U256;
use ic_icrc1_tokens_u64::U64;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::BlockType;
use proptest::prelude::*;

fn arb_u256() -> impl Strategy<Value = U256> {
    (any::<u128>(), any::<u128>()).prop_map(|(hi, lo)| U256::from_words(hi, lo))
}

proptest! {
    #[test]
    fn test_generic_block_to_encoded_block_conversion(block in blocks_strategy(arb_small_amount())) {
        // for any possible block, assert that the conversion
        // block->encoded_block->generic_block->encoded_block->block
        // returns the original block
        let generic_block = encoded_block_to_generic_block(&block.clone().encode());
        let encoded_block = generic_block_to_encoded_block(generic_block.clone()).unwrap();
        assert_eq!(generic_block, encoded_block_to_generic_block(&encoded_block));
        assert_eq!(block, Block::<U64>::decode(encoded_block.clone()).unwrap());
        assert_eq!(Block::<U64>::try_from(generic_block.clone()).unwrap(), block);
        assert_eq!(Transaction::<U64>::try_from(generic_block.clone()).unwrap(), block.transaction);
        assert_eq!(generic_block.hash(), Block::<U64>::block_hash(&encoded_block).as_slice());
    }

    #[test]
    fn test_generic_transaction_hash(block in blocks_strategy(arb_small_amount())) {

        // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
        let generic_block = encoded_block_to_generic_block(&block.clone().encode());

        //Convert generic block to generic transaction
        let generic_transaction = generic_transaction_from_generic_block(generic_block).unwrap();

        //Check that the hash of the generic transaction and the transaction object are the same
        assert_eq!(generic_transaction.hash().to_vec(), <Transaction<U64> as LedgerTransaction>::hash(&block.transaction).as_slice().to_vec());
    }

    #[test]
    fn test_generic_transaction_hash_u256(block in blocks_strategy(arb_u256())) {

        // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
        let generic_block = encoded_block_to_generic_block(&block.clone().encode());

        //Convert generic block to generic transaction
        let generic_transaction = generic_transaction_from_generic_block(generic_block).unwrap();

        //Check that the hash of the generic transaction and the transaction object are the same
        assert_eq!(generic_transaction.hash().to_vec(), <Transaction<U256> as LedgerTransaction>::hash(&block.transaction).as_slice().to_vec());
    }
}
