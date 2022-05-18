use crate::{blocktree::BlockDoesNotExtendTree, state::State, store, BitcoinCanister};
use bitcoin::{
    hash_types::{BlockHash, TxMerkleNode},
    hashes::Hash,
    Network,
};
use ic_btc_types::Network as BitcoinNetwork;
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, Block, GetSuccessorsRequest,
    Transaction,
};
use ic_logger::{debug, error, ReplicaLogger};
use ic_registry_subnet_features::{BitcoinFeature, BitcoinFeatureStatus};
use ic_replicated_state::bitcoin_state::{
    BitcoinState as ReplicatedBitcoinState, BitcoinStateError,
};

impl BitcoinCanister {
    /// The heartbeat of the Bitcoin canister.
    ///
    /// The heartbeat sends and processes `GetSuccessor` requests/responses, which
    /// is needed to fetch new blocks from the network.
    pub fn heartbeat(
        &self,
        bitcoin_state: ReplicatedBitcoinState,
        bitcoin_feature: BitcoinFeature,
    ) -> ReplicatedBitcoinState {
        // Possibly reset the state if the feature has been disabled or if the configured
        // network has changed.
        let bitcoin_state = maybe_reset_state(bitcoin_state, bitcoin_feature);

        if bitcoin_feature.status == BitcoinFeatureStatus::Disabled {
            // Exit early if the feature is disabled to avoid needless type conversions below.
            return bitcoin_state;
        }

        let mut state: State = State::from(bitcoin_state);

        // Process all incoming responses from the adapter.
        let height = process_adapter_responses(&mut state, &self.log);

        match bitcoin_feature.status {
            BitcoinFeatureStatus::Enabled | BitcoinFeatureStatus::Syncing => {
                let network_label = state.utxos.network.to_string();
                self.metrics.observe_chain_height(height, &network_label);
                self.metrics
                    .observe_utxos_length(state.utxos.utxos.len(), &network_label);
                self.metrics.observe_address_to_outpoints_length(
                    state.utxos.address_to_outpoints.len(),
                    &network_label,
                );

                if !state.adapter_queues.has_in_flight_get_successors_requests() {
                    let request = get_successors_request(&mut state);

                    match state
                        .adapter_queues
                        .push_request(BitcoinAdapterRequestWrapper::GetSuccessorsRequest(request))
                    {
                        Ok(()) => {}
                        Err(err @ BitcoinStateError::QueueFull { .. }) => {
                            error!(self.log, "Could not push GetSuccessorsRequest because the adapter queues are full. Error: {:?}", err);
                        }
                        // TODO(EXC-1098): Refactor the `push_request` method to not return these
                        // errors to avoid this `unreachable` statement.
                        Err(BitcoinStateError::FeatureNotEnabled)
                        | Err(BitcoinStateError::NonMatchingResponse { .. }) => unreachable!(),
                    }
                }
            }
            BitcoinFeatureStatus::Paused | BitcoinFeatureStatus::Disabled => {
                // Don't send requests to the adapter.
            }
        }

        state.into()
    }
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

fn maybe_reset_state(
    state: ReplicatedBitcoinState,
    feature: BitcoinFeature,
) -> ReplicatedBitcoinState {
    let feature_network = match feature.network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
    };

    // If the bitcoin feature is set for a different network than what's in the state
    // or if the feature has been disabled, reset the state.
    if state.utxo_set.network != feature_network || feature.status == BitcoinFeatureStatus::Disabled
    {
        ReplicatedBitcoinState::new(feature.network)
    } else {
        // Return state as-is.
        state
    }
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
    use ic_metrics::MetricsRegistry;

    #[test]
    fn does_not_push_requests_to_adapter_if_feature_is_disabled() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let bitcoin_canister = BitcoinCanister::new(&MetricsRegistry::new(), no_op_logger());
        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Disabled,
            },
        );
        assert_eq!(state.adapter_queues.num_requests(), 0);

        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Mainnet,
                status: BitcoinFeatureStatus::Disabled,
            },
        );
        assert_eq!(state.adapter_queues.num_requests(), 0);
    }

    #[test]
    fn does_not_push_requests_to_adapter_if_feature_is_paused() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let bitcoin_canister = BitcoinCanister::new(&MetricsRegistry::new(), no_op_logger());
        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Paused,
            },
        );
        assert_eq!(state.adapter_queues.num_requests(), 0);

        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Mainnet,
                status: BitcoinFeatureStatus::Paused,
            },
        );
        assert_eq!(state.adapter_queues.num_requests(), 0);
    }

    #[test]
    fn pushes_requests_to_adapter_if_feature_is_enabled() {
        let state = ReplicatedBitcoinState::default();
        assert_eq!(state.adapter_queues.num_requests(), 0);
        let bitcoin_canister = BitcoinCanister::new(&MetricsRegistry::new(), no_op_logger());
        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Enabled,
            },
        );
        assert_eq!(state.adapter_queues.num_requests(), 1);
    }

    #[test]
    fn state_is_reset_if_feature_is_disabled() {
        let mut state = ReplicatedBitcoinState::new(BitcoinNetwork::Mainnet);
        // Mutate the state in some way to later verify that the state has been reset.
        state.stable_height = 17;

        let bitcoin_canister = BitcoinCanister::new(&MetricsRegistry::new(), no_op_logger());
        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Mainnet,
                status: BitcoinFeatureStatus::Disabled,
            },
        );
        assert_eq!(state, ReplicatedBitcoinState::new(BitcoinNetwork::Mainnet));

        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Disabled,
            },
        );
        assert_eq!(state, ReplicatedBitcoinState::new(BitcoinNetwork::Testnet));
    }

    #[test]
    fn state_is_reset_if_network_is_changed() {
        let mut state = ReplicatedBitcoinState::new(BitcoinNetwork::Mainnet);
        // Mutate the state in some way to later verify that the state has been reset.
        state.stable_height = 17;

        let bitcoin_canister = BitcoinCanister::new(&MetricsRegistry::new(), no_op_logger());
        let new_state = bitcoin_canister.heartbeat(
            state.clone(),
            BitcoinFeature {
                network: BitcoinNetwork::Mainnet,
                status: BitcoinFeatureStatus::Paused,
            },
        );

        // State is unchanged.
        assert_eq!(new_state.stable_height, state.stable_height);

        // Change the network, but keep the feature paused.
        let state = bitcoin_canister.heartbeat(
            state,
            BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Paused,
            },
        );

        // The state has been reset.
        assert_eq!(
            state,
            State::from(ReplicatedBitcoinState::new(BitcoinNetwork::Testnet)).into()
        );
    }
}
