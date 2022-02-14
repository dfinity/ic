use crate::{block, proto};
use bitcoin::{Block, BlockHash};

pub type BlockChain<'a> = Vec<&'a Block>;

/// Maintains a tree of connected blocks.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct BlockTree {
    pub root: Block,
    pub children: Vec<BlockTree>,
}

/// An error thrown when trying to add a block that isn't a successor
/// of any block in the tree.
#[derive(Debug)]
pub struct BlockDoesNotExtendTree(pub Block);

impl BlockTree {
    /// Creates a new `BlockTree` with the given block as its root.
    pub fn new(root: Block) -> Self {
        Self {
            root,
            children: vec![],
        }
    }

    /// Extends the tree with the given block.
    ///
    /// Blocks can extend the tree in the following cases:
    ///   * The block is already present in the tree (no-op).
    ///   * The block is a successor of a block already in the tree.
    pub fn extend(&mut self, block: Block) -> Result<(), BlockDoesNotExtendTree> {
        if self.contains(&block) {
            // The block is already present in the tree. Nothing to do.
            return Ok(());
        }

        // Check if the block is a successor to any of the blocks in the tree.
        match self.find_mut(&block.header.prev_blockhash) {
            Some(block_tree) => {
                assert_eq!(block_tree.root.block_hash(), block.header.prev_blockhash);
                // Add the block as a successor.
                block_tree.children.push(BlockTree::new(block));
                Ok(())
            }
            None => Err(BlockDoesNotExtendTree(block)),
        }
    }

    /// Returns a `BlockTree` where the hash of the root block matches the provided `block_hash`
    /// if it exists, and `None` otherwise.
    pub fn find_mut(&mut self, blockhash: &BlockHash) -> Option<&mut BlockTree> {
        if self.root.block_hash() == *blockhash {
            return Some(self);
        }

        for child in self.children.iter_mut() {
            if let res @ Some(_) = child.find_mut(blockhash) {
                return res;
            }
        }

        None
    }

    /// Returns all the blockchains in the tree.
    pub fn blockchains(&self) -> Vec<BlockChain> {
        if self.children.is_empty() {
            return vec![vec![&self.root]];
        }

        let mut tips = vec![];
        for child in self.children.iter() {
            tips.extend(
                child
                    .blockchains()
                    .into_iter()
                    .map(|bc| concat(vec![&self.root], bc))
                    .collect::<Vec<BlockChain>>(),
            );
        }

        tips
    }

    pub fn depth(&self) -> u64 {
        if self.children.is_empty() {
            return 0;
        }

        let mut max_child_depth = 0;

        for child in self.children.iter() {
            max_child_depth = std::cmp::max(1 + child.depth(), max_child_depth);
        }

        max_child_depth
    }

    // Returns true if a block exists in the tree, false otherwise.
    fn contains(&self, block: &Block) -> bool {
        if self.root.block_hash() == block.block_hash() {
            return true;
        }

        for child in self.children.iter() {
            if child.contains(block) {
                return true;
            }
        }

        false
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

fn concat<T>(mut a: Vec<T>, b: Vec<T>) -> Vec<T> {
    a.extend(b);
    a
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_builder::BlockBuilder;

    #[test]
    fn tree_single_block() {
        let block_tree = BlockTree::new(BlockBuilder::genesis().build());

        assert_eq!(block_tree.depth(), 0);
        assert_eq!(block_tree.blockchains(), vec![vec![&block_tree.root]]);
    }

    #[test]
    fn tree_multiple_forks() {
        let genesis_block = BlockBuilder::genesis().build();
        let genesis_block_header = genesis_block.header;
        let mut block_tree = BlockTree::new(genesis_block);

        for i in 1..5 {
            // Create different blocks extending the genesis block.
            // Each one of these should be a separate fork.
            block_tree
                .extend(BlockBuilder::with_prev_header(genesis_block_header).build())
                .unwrap();
            assert_eq!(block_tree.blockchains().len(), i);
        }

        assert_eq!(block_tree.depth(), 1);
    }
}
