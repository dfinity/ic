use crate::page_map::PageMap;
use bitcoin::{blockdata::constants::genesis_block, Block, Network, OutPoint, TxOut};
use ic_btc_types_internal::{
    BitcoinAdapterRequest, BitcoinAdapterRequestWrapper, BitcoinAdapterResponse,
};
use ic_protobuf::{
    bitcoin::v1 as pb_bitcoin,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::TryFrom,
};

mod block;

/// A constant to determine whether a block is stable or unstable.
/// See [UnstableBlocks] for more documentation.
// This number is set to a small value at the moment until `get_utxos` is optimized.
const STABILITY_THRESHOLD: u32 = 6;

/// Maximum number of requests to Bitcoin Adapter that can be present in the queue.
const REQUEST_QUEUE_CAPACITY: u32 = 500;

/// Errors that can be returned when handling the `BitcoinState`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BitcoinStateError {
    /// Bitcoin testnet feature not enabled.
    TestnetFeatureNotEnabled,
    /// No corresponding request found when trying to push a response.
    NonMatchingResponse { callback_id: u64 },
    /// Enqueueing a request failed due to full queue to the Bitcoin adapter.
    QueueFull { capacity: u32 },
}

impl std::error::Error for BitcoinStateError {}

impl std::fmt::Display for BitcoinStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinStateError::TestnetFeatureNotEnabled => {
                write!(f, "Bitcoin testnet feature not enabled.")
            }
            BitcoinStateError::NonMatchingResponse { callback_id } => {
                write!(
                    f,
                    "Attempted to push a response for callback id {} without an in-flight corresponding request",
                    callback_id
                )
            }
            BitcoinStateError::QueueFull { capacity } => {
                write!(
                    f,
                    "Request can not be enqueued because the queue has reached its capacity of {}.",
                    capacity
                )
            }
        }
    }
}

/// Represents the queues for requests to and responses from the Bitcoin Adapter.
/// See `ic_protobuf::bitcoin::v1` for documentation of the fields.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterQueues {
    next_callback_id: u64,
    requests: BTreeMap<u64, BitcoinAdapterRequest>,
    responses: VecDeque<BitcoinAdapterResponse>,
    requests_queue_capacity: u32,
    in_flight_get_successors_requests_num: u32,
}

impl Default for AdapterQueues {
    fn default() -> Self {
        Self::new(REQUEST_QUEUE_CAPACITY)
    }
}

impl AdapterQueues {
    pub fn new(requests_queue_capacity: u32) -> Self {
        Self {
            next_callback_id: 0,
            requests: BTreeMap::new(),
            responses: VecDeque::new(),
            requests_queue_capacity,
            in_flight_get_successors_requests_num: 0,
        }
    }

    /// Returns true iff there's at least an in-flight `GetSuccessorsRequest`.
    pub fn has_in_flight_get_successors_requests(&self) -> bool {
        self.in_flight_get_successors_requests_num > 0
    }

    /// Pushes a `BitcoinAdapterRequestWrapper` to the `BitcoinState`.
    ///
    /// Returns a `BitcoinStateError` if there's no room left in the queue for new requests.
    pub fn push_request(
        &mut self,
        request: BitcoinAdapterRequestWrapper,
    ) -> Result<(), BitcoinStateError> {
        if self.requests.len() as u32 >= self.requests_queue_capacity {
            return Err(BitcoinStateError::QueueFull {
                capacity: self.requests_queue_capacity,
            });
        }

        if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) = request {
            self.in_flight_get_successors_requests_num += 1;
        }
        self.requests.insert(
            self.next_callback_id,
            BitcoinAdapterRequest {
                request,
                callback_id: self.next_callback_id,
            },
        );
        self.next_callback_id += 1;
        Ok(())
    }

    pub fn pop_response(&mut self) -> Option<BitcoinAdapterResponse> {
        self.responses.pop_front()
    }

    /// Returns the number of requests to the Bitcoin Adapter.
    pub fn num_requests(&self) -> usize {
        self.requests.len()
    }

    /// Returns the number of responses from the Bitcoin Adapter.
    pub fn num_responses(&self) -> usize {
        self.responses.len()
    }
}

/// The Bitcoin network's UTXO set.
/// See `ic_btc_canister::state` for more documentation.
#[derive(Clone, Debug, PartialEq)]
pub struct UtxoSet {
    /// PageMap storing all the UTXOs that are small in size.
    pub utxos_small: PageMap,

    /// PageMap storing all the UTXOs that are medium in size.
    pub utxos_medium: PageMap,

    /// UTXOs that are large in size - these are very rare, so a PageMap isn't needed here.
    pub utxos_large: BTreeMap<OutPoint, (TxOut, u32)>,

    /// PageMap storing an index mapping a Bitcoin address to its UTXOs.
    pub address_outpoints: PageMap,

    /// The bitcoin network that this UtxoSet belongs to.
    pub network: Network,
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            utxos_small: PageMap::default(),
            utxos_medium: PageMap::default(),
            utxos_large: BTreeMap::default(),
            address_outpoints: PageMap::default(),
        }
    }
}

/// A data structure for maintaining all unstable blocks.
///
/// A block `b` is considered stable if:
///   depth(block) ≥ stability_threshold
///   ∀ b', height(b') = height(b): depth(b) - depth(b’) ≥ stability_threshold
#[derive(Clone, Debug, PartialEq)]
pub struct UnstableBlocks {
    pub stability_threshold: u32,
    pub tree: BlockTree,
}

impl UnstableBlocks {
    pub fn new(stability_threshold: u32, anchor: Block) -> Self {
        Self {
            stability_threshold,
            tree: BlockTree::new(anchor),
        }
    }
}

impl Default for UnstableBlocks {
    fn default() -> Self {
        UnstableBlocks::new(STABILITY_THRESHOLD, genesis_block(Network::Testnet))
    }
}

/// Maintains a tree of connected blocks.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockTree {
    pub root: Block,
    pub children: Vec<BlockTree>,
}

impl BlockTree {
    /// Creates a new `BlockTree` with the given block as its root.
    pub fn new(root: Block) -> Self {
        Self {
            root,
            children: vec![],
        }
    }
}

/// Represents the bitcoin state of the subnet.
/// See `ic_protobuf::bitcoin::v1` for documentation of the fields.
#[derive(Clone, Debug, PartialEq)]
pub struct BitcoinState {
    pub adapter_queues: AdapterQueues,
    pub utxo_set: UtxoSet,
    pub unstable_blocks: UnstableBlocks,
    pub stable_height: u32,
}

impl Default for BitcoinState {
    fn default() -> Self {
        Self::new(REQUEST_QUEUE_CAPACITY)
    }
}

impl BitcoinState {
    pub fn new(requests_queue_capacity: u32) -> Self {
        Self {
            adapter_queues: AdapterQueues::new(requests_queue_capacity),
            utxo_set: UtxoSet::default(),
            unstable_blocks: UnstableBlocks::default(),
            stable_height: 0,
        }
    }

    /// Returns an iterator over the existing requests to the Bitcoin Adapter.
    pub fn adapter_requests_iter(
        &self,
    ) -> std::collections::btree_map::Iter<'_, u64, BitcoinAdapterRequest> {
        self.adapter_queues.requests.iter()
    }

    /// Pushes a `BitcoinAdapterResponse` onto the `BitcoinState`. It also clears
    /// the in-flight request that corresponds to this response.
    ///
    /// Returns a `BitcoinStateError::NonMatchingResponse` error if there is no
    /// corresponding in-flight request when the response is pushed.
    pub(crate) fn push_response(
        &mut self,
        response: BitcoinAdapterResponse,
    ) -> Result<(), BitcoinStateError> {
        match self.adapter_queues.requests.remove(&response.callback_id) {
            None => Err(BitcoinStateError::NonMatchingResponse {
                callback_id: response.callback_id,
            }),
            Some(r) => {
                if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) = r.request {
                    self.adapter_queues.in_flight_get_successors_requests_num -= 1;
                }
                self.adapter_queues.responses.push_back(response);
                Ok(())
            }
        }
    }
}

impl From<&AdapterQueues> for pb_bitcoin::AdapterQueues {
    fn from(queues: &AdapterQueues) -> pb_bitcoin::AdapterQueues {
        pb_bitcoin::AdapterQueues {
            next_callback_id: queues.next_callback_id,
            requests: queues.requests.iter().map(|(_, v)| v.into()).collect(),
            responses: queues.responses.iter().map(|x| x.into()).collect(),
            requests_queue_capacity: queues.requests_queue_capacity,
        }
    }
}

impl TryFrom<pb_bitcoin::AdapterQueues> for AdapterQueues {
    type Error = ProxyDecodeError;

    fn try_from(queues: pb_bitcoin::AdapterQueues) -> Result<Self, Self::Error> {
        let mut requests = BTreeMap::new();
        let mut in_flight_get_successors_requests_num = 0;
        for r in queues.requests.into_iter() {
            let bitcoin_adapter_request = BitcoinAdapterRequest::try_from(r)?;
            if let BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) =
                bitcoin_adapter_request.request
            {
                in_flight_get_successors_requests_num += 1;
            }
            requests.insert(bitcoin_adapter_request.callback_id, bitcoin_adapter_request);
        }

        let mut responses = VecDeque::new();
        for r in queues.responses.into_iter() {
            responses.push_back(BitcoinAdapterResponse::try_from(r)?);
        }

        Ok(AdapterQueues {
            next_callback_id: queues.next_callback_id,
            requests,
            responses,
            requests_queue_capacity: queues.requests_queue_capacity,
            in_flight_get_successors_requests_num,
        })
    }
}

impl From<&BlockTree> for pb_bitcoin::BlockTree {
    fn from(item: &BlockTree) -> pb_bitcoin::BlockTree {
        pb_bitcoin::BlockTree {
            root: Some(block::to_proto(&item.root)),
            children: item
                .children
                .iter()
                .map(pb_bitcoin::BlockTree::from)
                .collect(),
        }
    }
}

impl TryFrom<pb_bitcoin::BlockTree> for BlockTree {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_bitcoin::BlockTree) -> Result<Self, Self::Error> {
        let mut children = vec![];
        for child_res in item.children.into_iter().map(BlockTree::try_from) {
            children.push(child_res?);
        }

        Ok(Self {
            root: block::from_proto(&try_from_option_field(item.root, "BlockTree::root")?),
            children,
        })
    }
}

impl From<&UnstableBlocks> for pb_bitcoin::UnstableBlocks {
    fn from(item: &UnstableBlocks) -> pb_bitcoin::UnstableBlocks {
        pb_bitcoin::UnstableBlocks {
            stability_threshold: item.stability_threshold,
            tree: Some(pb_bitcoin::BlockTree::from(&item.tree)),
        }
    }
}

impl TryFrom<pb_bitcoin::UnstableBlocks> for UnstableBlocks {
    type Error = ProxyDecodeError;

    fn try_from(item: pb_bitcoin::UnstableBlocks) -> Result<Self, Self::Error> {
        Ok(Self {
            stability_threshold: item.stability_threshold,
            tree: BlockTree::try_from(try_from_option_field::<_, pb_bitcoin::BlockTree, _>(
                item.tree,
                "UnstableBlocks::tree",
            )?)?,
        })
    }
}

#[cfg(test)]
mod tests;
