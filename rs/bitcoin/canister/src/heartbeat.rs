use crate::{blocktree::BlockDoesNotExtendTree, state::State, store};
use bitcoin::{
    hash_types::{BlockHash, TxMerkleNode},
    hashes::Hash,
};
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, Block, GetSuccessorsRequest,
    Transaction,
};
use ic_logger::{debug, error, info, ReplicaLogger};
use ic_registry_subnet_features::BitcoinFeature;
use ic_replicated_state::bitcoin_state::{
    BitcoinState as ReplicatedBitcoinState, BitcoinStateError,
};

/// The heartbeat of the Bitcoin canister.
///
/// The heartbeat sends and processes `GetSuccessor` requests/responses, which
/// is needed to fetch new blocks from the network.
pub fn heartbeat(
    bitcoin_state: ReplicatedBitcoinState,
    bitcoin_feature: BitcoinFeature,
    log: &ReplicaLogger,
) -> ReplicatedBitcoinState {
    let mut state: State = State::from(bitcoin_state);

    // Process all incoming responses from the adapter.
    let height = process_adapter_responses(&mut state, log);

    match bitcoin_feature {
        BitcoinFeature::Enabled => {
            info!(log, "Bitcoin testnet chain height: {}", height);
            info!(log, "# UTXOs: {}", state.utxos.utxos.len());
            info!(
                log,
                "# Address outpoints: {}",
                state.utxos.address_to_outpoints.len()
            );

            if !state.adapter_queues.has_in_flight_get_successors_requests() {
                let request = get_successors_request(&mut state);
                info!(log, "Sending GetSuccessorsRequest: {:?}", request);

                match state
                    .adapter_queues
                    .push_request(BitcoinAdapterRequestWrapper::GetSuccessorsRequest(request))
                {
                    Ok(()) => {}
                    Err(err @ BitcoinStateError::QueueFull { .. }) => {
                        error!(log, "Could not push GetSuccessorsRequest because the adapter queues are full. Error: {:?}", err);
                    }
                    // TODO(EXC-1098): Refactor the `push_request` method to not return these
                    // errors to avoid this `unreachable` statement.
                    Err(BitcoinStateError::TestnetFeatureNotEnabled)
                    | Err(BitcoinStateError::NonMatchingResponse { .. }) => unreachable!(),
                }
            }
        }
        BitcoinFeature::Paused | BitcoinFeature::Disabled => {
            // Don't send requests to the adapter.
        }
    }

    state.into()
}

// Retrieves a `GetSuccessorsRequest` to send to the adapter.
fn get_successors_request(state: &mut State) -> GetSuccessorsRequest {
    let mut processed_block_hashes: Vec<Vec<u8>> = store::get_unstable_blocks(state)
        .iter()
        .map(|b| b.block_hash().to_vec())
        .collect();

    // This is safe as there will always be at least 1 unstable block.
    let anchor = processed_block_hashes.remove(0);

    GetSuccessorsRequest {
        anchor,
        processed_block_hashes,
    }
}

// Processes responses received from the Bitcoin Adapter.
// Returns the height of the chain after the response is processed.
fn process_adapter_responses(state: &mut State, log: &ReplicaLogger) -> u32 {
    while let Some(response) = state.adapter_queues.pop_response() {
        match response.response {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) => {
                let block_hashes: Vec<BlockHash> = r
                    .blocks
                    .iter()
                    .map(|x| to_btc_block(x).block_hash())
                    .collect();
                debug!(
                    log,
                    "Received new blocks: {:?}, next headers {:?}", block_hashes, r.next
                );
                for block in r.blocks.into_iter() {
                    let btc_block = to_btc_block(&block);
                    let block_hash = btc_block.block_hash();
                    match store::insert_block(state, btc_block) {
                        Ok(()) => {}
                        Err(BlockDoesNotExtendTree(_)) => {
                            error!(
                                log,
                                "Received block that doesn't extend existing blocks: {}",
                                block_hash
                            );
                        }
                    }
                }
            }
            BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => {
                // TODO(EXC-911): Handle these responses too.
            }
        }
    }

    store::main_chain_height(state)
}

fn to_btc_transaction(transaction: &Transaction) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: transaction.version,
        lock_time: transaction.lock_time,
        input: transaction
            .input
            .iter()
            .map(|x| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_hash(
                        Hash::from_slice(&x.previous_output.txid).unwrap(),
                    ),
                    vout: x.previous_output.vout,
                },
                script_sig: bitcoin::Script::from(x.script_sig.to_vec()),
                sequence: x.sequence,
                witness: x.witness.iter().map(|w| w.to_vec()).collect(),
            })
            .collect(),
        output: transaction
            .output
            .iter()
            .map(|x| bitcoin::TxOut {
                value: x.value,
                script_pubkey: bitcoin::Script::from(x.script_pubkey.to_vec()),
            })
            .collect(),
    }
}

fn to_btc_block(block: &Block) -> bitcoin::Block {
    bitcoin::Block {
        header: bitcoin::BlockHeader {
            version: block.header.version,
            prev_blockhash: BlockHash::from_hash(
                Hash::from_slice(&block.header.prev_blockhash).unwrap(),
            ),
            merkle_root: TxMerkleNode::from_hash(
                Hash::from_slice(&block.header.merkle_root).unwrap(),
            ),
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        },
        txdata: block.txdata.iter().map(to_btc_transaction).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;

    #[test]
    fn does_not_push_requests_to_adapter_if_feature_is_disabled() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let state = heartbeat(state, BitcoinFeature::Disabled, &no_op_logger());
        assert_eq!(state.adapter_queues.num_requests(), 0);
    }

    #[test]
    fn does_not_push_requests_to_adapter_if_feature_is_paused() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let state = heartbeat(state, BitcoinFeature::Paused, &no_op_logger());
        assert_eq!(state.adapter_queues.num_requests(), 0);
    }

    #[test]
    fn pushes_requests_to_adapter_if_feature_is_enabled() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let state = heartbeat(state, BitcoinFeature::Enabled, &no_op_logger());
        assert_eq!(state.adapter_queues.num_requests(), 1);
    }
}
