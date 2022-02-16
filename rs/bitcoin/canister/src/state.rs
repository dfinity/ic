use crate::{block, proto, utxoset};
use bitcoin::{hashes::Hash, Block, Network, OutPoint, Script, TxOut, Txid};
use std::collections::{BTreeMap, HashMap, HashSet};

pub type Height = u32;

/// A structure used to maintain the entire state.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct State {
    // The height of the latest block marked as stable.
    pub height: Height,

    // The UTXOs of all stable blocks since genesis.
    pub utxos: UtxoSet,

    // Blocks inserted, but are not considered stable yet.
    pub unstable_blocks: UnstableBlocks,
}

impl State {
    /// Create a new blockchain.
    ///
    /// The `stability_threshold` parameter specifies how many confirmations a
    /// block needs before it is considered stable. Stable blocks are assumed
    /// to be final and are never removed.
    pub fn new(stability_threshold: u64, network: Network, genesis_block: Block) -> Self {
        Self {
            height: 0,
            utxos: UtxoSet::new(true, network),
            unstable_blocks: UnstableBlocks::new(stability_threshold, genesis_block),
        }
    }

    pub fn to_proto(&self) -> proto::State {
        proto::State {
            height: self.height,
            utxos: Some(self.utxos.to_proto()),
            unstable_blocks: Some(self.unstable_blocks.to_proto()),
        }
    }

    pub fn from_proto(proto_state: proto::State) -> Self {
        Self {
            height: proto_state.height,
            utxos: UtxoSet::from_proto(proto_state.utxos.unwrap()),
            unstable_blocks: UnstableBlocks::from_proto(proto_state.unstable_blocks.unwrap()),
        }
    }
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub struct UtxoSet {
    pub utxos: HashMap<OutPoint, (TxOut, Height)>,
    pub network: Network,
    // An index for fast retrievals of an address's UTXOs.
    pub address_to_outpoints: BTreeMap<String, Vec<OutPoint>>,
    // If true, a transaction's inputs must all be present in the UTXO for it to be accepted.
    pub strict: bool,
}

impl UtxoSet {
    pub fn new(strict: bool, network: Network) -> Self {
        Self {
            utxos: HashMap::default(),
            address_to_outpoints: BTreeMap::default(),
            strict,
            network,
        }
    }

    pub fn into_set(self) -> HashSet<(OutPoint, TxOut, Height)> {
        self.utxos.into_iter().map(|(k, v)| (k, v.0, v.1)).collect()
    }

    pub fn to_proto(&self) -> proto::UtxoSet {
        proto::UtxoSet {
            utxos: self
                .utxos
                .iter()
                .map(|(outpoint, (txout, height))| proto::Utxo {
                    outpoint: Some(proto::OutPoint {
                        txid: outpoint.txid.to_vec(),
                        vout: outpoint.vout,
                    }),
                    txout: Some(proto::TxOut {
                        value: txout.value,
                        script_pubkey: txout.script_pubkey.to_bytes(),
                    }),
                    height: *height,
                })
                .collect(),
            strict: self.strict,
            network: match self.network {
                Network::Bitcoin => 0,
                Network::Testnet => 1,
                Network::Signet => 2,
                Network::Regtest => 3,
            },
        }
    }

    pub fn from_proto(utxos_proto: proto::UtxoSet) -> Self {
        let mut utxo_set = Self {
            utxos: HashMap::default(),
            address_to_outpoints: BTreeMap::default(),
            strict: utxos_proto.strict,
            network: match utxos_proto.network {
                0 => Network::Bitcoin,
                1 => Network::Testnet,
                2 => Network::Signet,
                3 => Network::Regtest,
                _ => panic!("Invalid network ID"),
            },
        };

        for utxo in utxos_proto.utxos.into_iter() {
            let outpoint = utxo
                .outpoint
                .map(|o| OutPoint::new(Txid::from_hash(Hash::from_slice(&o.txid).unwrap()), o.vout))
                .unwrap();

            let tx_out = utxo
                .txout
                .map(|t| TxOut {
                    value: t.value,
                    script_pubkey: Script::from(t.script_pubkey),
                })
                .unwrap();

            utxoset::insert_utxo(&mut utxo_set, outpoint, tx_out, utxo.height);
        }

        utxo_set
    }
}

/// A data structure for maintaining all unstable blocks.
///
/// A block `b` is considered stable if:
///   depth(block) ≥ stability_threshold
///   ∀ b', height(b') = height(b): depth(b) - depth(b’) ≥ stability_threshold
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct UnstableBlocks {
    pub stability_threshold: u64,
    pub tree: BlockTree,
}

impl UnstableBlocks {
    pub fn new(stability_threshold: u64, anchor: Block) -> Self {
        Self {
            stability_threshold,
            tree: BlockTree::new(anchor),
        }
    }

    pub fn to_proto(&self) -> proto::UnstableBlocks {
        proto::UnstableBlocks {
            stability_threshold: self.stability_threshold,
            tree: Some(self.tree.to_proto()),
        }
    }

    pub fn from_proto(block_forest_proto: proto::UnstableBlocks) -> Self {
        Self {
            stability_threshold: block_forest_proto.stability_threshold,
            tree: BlockTree::from_proto(
                block_forest_proto
                    .tree
                    .expect("BlockTree must be present in the proto"),
            ),
        }
    }
}

/// Maintains a tree of connected blocks.
#[cfg_attr(test, derive(Debug, PartialEq))]
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

    pub fn to_proto(&self) -> proto::BlockTree {
        proto::BlockTree {
            root: Some(block::to_proto(&self.root)),
            children: self.children.iter().map(|t| t.to_proto()).collect(),
        }
    }

    pub fn from_proto(block_tree_proto: proto::BlockTree) -> Self {
        Self {
            root: block::from_proto(&block_tree_proto.root.unwrap()),
            children: block_tree_proto
                .children
                .into_iter()
                .map(BlockTree::from_proto)
                .collect(),
        }
    }
}
