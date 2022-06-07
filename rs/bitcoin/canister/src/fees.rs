use crate::utxos::UtxosTrait;
use crate::{state::State, unstable_blocks};
use bitcoin::Block;
use bitcoin::{Transaction, TxIn};
use ic_btc_types::Satoshi;

pub type MillisatoshiPerByte = u64;

/// Returns the 100 fee percentiles, measured in millisatoshi/byte, of the chain's most recent transactions.
///
/// The `number_of_transactions` parameter configures the number of recent transactions to use for computing the percentiles.
/// Note that only unstable transactions (i.e. transactions in unstable blocks) are inspected.
/// If `number_of_transactions` exceeds the number of unstable transactions,
/// then all the unstable transactions are used.
pub fn get_current_fee_percentiles(
    state: &State,
    number_of_transactions: u32,
) -> Vec<MillisatoshiPerByte> {
    percentiles(get_fees_per_byte(state, number_of_transactions), 100)
}

// Computes the fees per byte of the last `number_of_transactions` transactions on the main chain.
// Fees are returned in a reversed order, starting with the most recent ones, followed by the older ones.
// Eg. for transactions [..., Tn-2, Tn-1, Tn] fees would be [Fn, Fn-1, Fn-2, ...].
fn get_fees_per_byte(state: &State, number_of_transactions: u32) -> Vec<MillisatoshiPerByte> {
    let mut fees = Vec::new();
    let main_chain = unstable_blocks::get_main_chain(&state.unstable_blocks).into_chain();
    let mut tx_i = 0;
    for block in main_chain.iter().rev() {
        if tx_i >= number_of_transactions {
            break;
        }
        for tx in &block.txdata {
            if tx_i >= number_of_transactions {
                break;
            }
            tx_i += 1;
            if let Some(fee) = get_tx_fee_per_byte(tx, &state.utxos, &main_chain) {
                fees.push(fee);
            }
        }
    }
    fees
}

// Computes the fees per byte of the given transaction.
fn get_tx_fee_per_byte(
    tx: &Transaction,
    utxo_set: &crate::state::UtxoSet,
    main_chain: &[&Block],
) -> Option<MillisatoshiPerByte> {
    if tx.is_coin_base() {
        // Coinbase transactions do not have a fee.
        return None;
    }

    let mut satoshi = 0;
    for tx_in in &tx.input {
        satoshi += match get_tx_input_value(tx_in, utxo_set, main_chain) {
            Some(value) => value,
            None => {
                // Calculating fee is not possible when tx input value was not found.
                // NOTE: This should be impossible if the block is valid.
                return None;
            }
        }
    }
    for tx_out in &tx.output {
        satoshi -= tx_out.value;
    }

    if tx.size() > 0 {
        // Don't use floating point division to avoid non-determinism.
        Some(((1000 * satoshi) / tx.size() as u64) as MillisatoshiPerByte)
    } else {
        // Calculating fee is not possible for a zero-size invalid transaction.
        None
    }
}

// Looks up the value in Satoshis of a transaction input.
// A transaction input's value can either be found in the UTXO set if
// it's part of a stable block, or in one of the unstable blocks.
fn get_tx_input_value(
    tx_in: &TxIn,
    utxo_set: &crate::state::UtxoSet,
    main_chain: &[&Block],
) -> Option<Satoshi> {
    // Look up transaction's input value in the UTXO set first.
    let result = utxo_set.utxos.get(&tx_in.previous_output);
    match result {
        Some((txout, _height)) => Some(txout.value as Satoshi),
        None => {
            // The input's value wasn't found in the UTXO set.
            // Look it up in the unstable blocks.
            for block in main_chain.iter() {
                for tx in &block.txdata {
                    if tx.txid() == tx_in.previous_output.txid {
                        let idx = tx_in.previous_output.vout as usize;
                        return Some(tx.output[idx].value as Satoshi);
                    }
                }
            }
            None
        }
    }
}

// Returns a requested number of percentile buckets from an initial vector of values.
fn percentiles(mut values: Vec<u64>, buckets: u16) -> Vec<u64> {
    if values.is_empty() {
        return vec![];
    }
    values.sort_unstable();
    (0..buckets)
        .map(|i| {
            // Don't use floating point division to avoid non-determinism.
            let mut index = (i as usize * values.len()) / buckets as usize;
            index = std::cmp::min(index, values.len() - 1);
            values[index]
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::insert_block;
    use bitcoin::Network;
    use ic_btc_test_utils::{random_p2pkh_address, BlockBuilder, TransactionBuilder};

    #[test]
    fn percentiles_empty_input() {
        assert_eq!(percentiles(vec![], 10).len(), 0);
    }

    #[test]
    fn percentiles_small_input_0_buckets() {
        let buckets = 0;
        let result = percentiles(vec![5, 4, 3, 2, 1], buckets);
        assert_eq!(result.len(), buckets as usize);
    }

    #[test]
    fn percentiles_small_input_10_buckets() {
        let buckets = 10;
        let result = percentiles(vec![5, 4, 3, 2, 1], buckets);
        assert_eq!(result.len(), buckets as usize);
        assert_eq!(result, Vec::<u64>::from([1, 1, 2, 2, 3, 3, 4, 4, 5, 5]));
    }

    #[test]
    fn percentiles_small_input_100_buckets() {
        let buckets = 100;
        let result = percentiles(vec![5, 4, 3, 2, 1], buckets);
        assert_eq!(result.len(), buckets as usize);
        assert_eq!(result[0..20], [1; 20]);
        assert_eq!(result[20..40], [2; 20]);
        assert_eq!(result[40..60], [3; 20]);
        assert_eq!(result[60..80], [4; 20]);
        assert_eq!(result[80..100], [5; 20]);
    }

    #[test]
    fn percentiles_big_input_100_buckets() {
        let mut input = vec![];
        input.extend(vec![5; 1000]);
        input.extend(vec![4; 1000]);
        input.extend(vec![3; 1000]);
        input.extend(vec![2; 1000]);
        input.extend(vec![1; 1000]);
        let buckets = 100;
        let result = percentiles(input, buckets);
        assert_eq!(result.len(), buckets as usize);
        assert_eq!(result[0..20], [1; 20]);
        assert_eq!(result[20..40], [2; 20]);
        assert_eq!(result[40..60], [3; 20]);
        assert_eq!(result[60..80], [4; 20]);
        assert_eq!(result[80..100], [5; 20]);
    }

    // Generates a chain of blocks:
    // - genesis block receives a coinbase transaction on address_1 with initial_balance
    // - follow-up blocks transfer payments from address_1 to address_2 with a specified fee
    // Fee is choosen to be a multiple of transaction size to have round values of fee.
    fn generate_blocks(
        initial_balance: Satoshi,
        number_of_blocks: u32,
        network: Network,
    ) -> Vec<Block> {
        let mut blocks = Vec::new();

        let pay: Satoshi = 1;
        let address_1 = random_p2pkh_address(network);
        let address_2 = random_p2pkh_address(network);

        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, initial_balance)
            .build();
        let block_0 = BlockBuilder::genesis()
            .with_transaction(coinbase_tx.clone())
            .build();
        blocks.push(block_0.clone());

        let mut balance = initial_balance;
        let mut previous_tx = coinbase_tx;
        let mut previous_block = block_0;

        for i in 0..number_of_blocks {
            // For testing purposes every transaction has 1 Satoshi higher fee than the previous one, starting with 0 satoshi.
            // Each fake transaction is 119 bytes in size.
            // I.e. a sequence of fees [0, 1, 2, 3] satoshi converts to [0, 8, 16, 25] milisatoshi per byte.
            // To estimate initial balance:
            // number_of_blocks * (number_of_blocks + 1) / 2
            let fee = i as Satoshi;
            let change = match balance.checked_sub(pay + fee) {
                Some(value) => value,
                None => panic!(
                    "There is not enough balance of {} Satoshi to perform transaction #{} with fee of {} satoshi",
                    balance, i, fee
                ),
            };

            let tx = TransactionBuilder::new()
                .with_input(bitcoin::OutPoint::new(previous_tx.txid(), 0))
                .with_output(&address_1, change)
                .with_output(&address_2, pay)
                .build();
            let block = BlockBuilder::with_prev_header(previous_block.header)
                .with_transaction(tx.clone())
                .build();
            blocks.push(block.clone());

            balance = change;
            previous_tx = tx;
            previous_block = block;
        }

        blocks
    }

    fn convert_blocks_to_state(
        blocks: Vec<Block>,
        network: Network,
        stability_threshold: u32,
    ) -> State {
        let mut state = State::new(stability_threshold, network, blocks[0].clone());
        for (i, block) in blocks.iter().skip(1).enumerate() {
            insert_block(&mut state, block.clone()).unwrap();
            if i % 1000 == 0 {
                println!("processed block: {}", i);
            }
        }
        state
    }

    #[test]
    fn get_current_fee_percentiles_requested_number_of_txs_is_greater_than_number_of_actual_txs() {
        let number_of_blocks = 5;
        let network = Network::Bitcoin;
        let blocks = generate_blocks(10_000, number_of_blocks, network);
        let stability_threshold = blocks.len() as u32;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 10_000;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        // Initial transactions' fees [0, 1, 2, 3, 4] satoshi, with 119 bytes of transaction size
        // transfer into [0, 8, 16, 25, 33] millisatoshi per byte fees in chronological order.
        assert_eq!(fees.len(), number_of_blocks as usize);
        // Fees are in a reversed order, in millisatoshi per byte units.
        assert_eq!(fees, vec![33, 25, 16, 8, 0]);

        assert_eq!(percentiles.len(), 100);
        // Percentiles distributed evenly.
        assert_eq!(percentiles[0..20], [0; 20]);
        assert_eq!(percentiles[20..40], [8; 20]);
        assert_eq!(percentiles[40..60], [16; 20]);
        assert_eq!(percentiles[60..80], [25; 20]);
        assert_eq!(percentiles[80..100], [33; 20]);
    }

    #[test]
    fn get_current_fee_percentiles_requested_number_of_txs_is_less_than_number_of_actual_txs() {
        let number_of_blocks = 8;
        let network = Network::Bitcoin;
        let blocks = generate_blocks(10_000, number_of_blocks, network);
        let stability_threshold = blocks.len() as u32;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 4;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        // Initial transactions' fees [0, 1, 2, 3, 4, 5, 6, 7, 8] satoshi, with 119 bytes of transaction size
        // transfer into [0, 8, 16, 25, 33, 42, 50, 58] millisatoshi per byte fees in chronological order.
        // Extracted fees contain only last 4 transaction fees in a reversed order.
        assert_eq!(fees.len(), number_of_transactions as usize);
        // Fees are in a reversed order, in millisatoshi per byte units.
        assert_eq!(fees, vec![58, 50, 42, 33]);

        assert_eq!(percentiles.len(), 100);
        // Percentiles distributed evenly.
        assert_eq!(percentiles[0..25], [33; 25]);
        assert_eq!(percentiles[25..50], [42; 25]);
        assert_eq!(percentiles[50..75], [50; 25]);
        assert_eq!(percentiles[75..100], [58; 25]);
    }

    #[test]
    fn get_current_fee_percentiles_requested_number_of_txs_is_equal_to_the_number_of_actual_txs() {
        let number_of_blocks = 5;
        let network = Network::Bitcoin;
        let blocks = generate_blocks(10_000, number_of_blocks, network);
        let stability_threshold = blocks.len() as u32;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 5;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        // Initial transactions' fees [0, 1, 2, 3, 4] satoshi, with 119 bytes of transaction size
        // transfer into [0, 8, 16, 25, 33] millisatoshi per byte fees in chronological order.
        assert_eq!(fees.len(), number_of_blocks as usize);
        // Fees are in a reversed order, in millisatoshi per byte units.
        assert_eq!(fees, vec![33, 25, 16, 8, 0]);

        assert_eq!(percentiles.len(), 100);
        // Percentiles distributed evenly.
        assert_eq!(percentiles[0..20], [0; 20]);
        assert_eq!(percentiles[20..40], [8; 20]);
        assert_eq!(percentiles[40..60], [16; 20]);
        assert_eq!(percentiles[60..80], [25; 20]);
        assert_eq!(percentiles[80..100], [33; 20]);
    }

    #[test]
    fn get_current_fee_percentiles_big_input() {
        let number_of_blocks = 1_000;
        let initial_balance = 500_500; // number_of_blocks * (number_of_blocks + 1) / 2
        let network = Network::Bitcoin;
        let blocks = generate_blocks(initial_balance, number_of_blocks, network);
        let stability_threshold = blocks.len() as u32;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 5;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        // Initial transactions' fees [0, 1, 2, 3, ...] satoshi, with 119 bytes of transaction size
        // transfer into [0, 8, 16, 25, ...] millisatoshi per byte fees in chronological order.
        assert_eq!(fees.len(), number_of_transactions as usize);
        // Fees are in a reversed order, in millisatoshi per byte units.
        // Eg. the fee of 999 satoshi for transaction of 119 bytes converts to
        // 1000 * 999 / 119 = 8394 millisatosi/bite.
        assert_eq!(fees, vec![8394, 8386, 8378, 8369, 8361]);

        assert_eq!(percentiles.len(), 100);
        // Percentiles distributed evenly.
        assert_eq!(percentiles[0..20], [8361; 20]);
        assert_eq!(percentiles[20..40], [8369; 20]);
        assert_eq!(percentiles[40..60], [8378; 20]);
        assert_eq!(percentiles[60..80], [8386; 20]);
        assert_eq!(percentiles[80..100], [8394; 20]);
    }

    #[test]
    fn get_current_fee_percentiles_no_transactions() {
        let number_of_blocks = 0;
        let network = Network::Bitcoin;
        let blocks = generate_blocks(10_000, number_of_blocks, network);
        let stability_threshold = blocks.len() as u32;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 10_000;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        assert_eq!(fees.len(), 0);
        assert_eq!(percentiles.len(), 0);
    }

    #[test]
    fn get_current_fee_percentiles_from_utxos() {
        let number_of_blocks = 5;
        let network = Network::Bitcoin;
        let blocks = generate_blocks(10_000, number_of_blocks, network);
        let stability_threshold = 1;
        let state = convert_blocks_to_state(blocks, network, stability_threshold);

        let number_of_transactions = 10_000;
        let fees = get_fees_per_byte(&state, number_of_transactions);
        let percentiles = get_current_fee_percentiles(&state, number_of_transactions);

        // Initial transactions' fees [0, 1, 2, 3, 4] satoshi, with 119 bytes of transaction size
        // transfer into [0, 8, 16, 25, 33] millisatoshi per byte fees in chronological order.
        // But only 2 last transactions are placed in unstable blocks that form a main chain.
        // All the rest of the blocks are partially stored in UTXO set, which does not have information
        // about the sequence and input values, which does not allow to compute the fee.
        assert_eq!(fees.len(), 2);
        // Fees are in a reversed order, in millisatoshi per byte units.
        assert_eq!(fees, vec![33, 25]);

        assert_eq!(percentiles.len(), 100);
        // Percentiles distributed evenly.
        assert_eq!(percentiles[0..50], [25; 50]);
        assert_eq!(percentiles[50..100], [33; 50]);
    }
}
