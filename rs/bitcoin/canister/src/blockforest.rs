use crate::{block, proto};
use bitcoin::{Block, BlockHash};

/// A data structure for maintaining all unstable blocks.
///
/// A block `b` is considered stable if:
///   depth(block) ≥ delta
///   ∀ b', height(b') = height(b): depth(b) - depth(b’) ≥ delta
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct BlockForest {
    delta: u64,
    tree: BlockTree,
}

impl BlockForest {
    pub fn new(delta: u64, anchor: Block) -> Self {
        Self {
            delta,
            tree: BlockTree::new(anchor),
        }
    }

    /// Pops the `anchor` block iff ∃ a child `C` of the `anchor` block that
    /// is delta-stable. The child `C` becomes the new `anchor` block, and all
    /// its siblings are discarded.
    pub fn pop(&mut self) -> Option<Block> {
        // Take all the children of the anchor.
        let mut anchor_child_trees = std::mem::take(&mut self.tree.children);

        // Sort them by depth.
        anchor_child_trees.sort_by_key(|a| a.depth());

        match anchor_child_trees.last() {
            Some(deepest_child_tree) => {
                // The deepest child tree must have a depth >= delta.
                if deepest_child_tree.depth() < self.delta {
                    // Need a depth of at least >= delta
                    self.tree.children = anchor_child_trees;
                    return None;
                }

                // If there is more than one child, the difference in depth
                // between the deepest child and all the others must be >= delta.
                if anchor_child_trees.len() >= 2 {
                    if let Some(second_deepest_child_tree) =
                        anchor_child_trees.get(anchor_child_trees.len() - 2)
                    {
                        if deepest_child_tree.depth() - second_deepest_child_tree.depth()
                            < self.delta
                        {
                            // Difference must be >= delta
                            self.tree.children = anchor_child_trees;
                            return None;
                        }
                    }
                }

                // The deepest child tree is delta-stable. This becomes the new
                // tree, with its root being the new `anchor` block.
                // All its siblings are discarded.
                let deepest_child_tree = anchor_child_trees.pop().unwrap();
                let old_anchor = self.tree.root.clone();
                self.tree = deepest_child_tree;
                Some(old_anchor)
            }
            None => {
                // The anchor has no children. Nothing to return.
                None
            }
        }
    }

    /// Push a new block into the store.
    pub fn push(&mut self, block: Block) -> Result<(), BlockNotPartOfTreeError> {
        self.tree.extend(block)
    }

    /// Returns the best guess on what the "current" blockchain is.
    ///
    /// The most likely chain to be "current", we hypothesize, is the longest
    /// chain of blocks with an "uncontested" tip. As in, there exists no other
    /// block at the same height as the tip.
    pub fn get_current_chain(&self) -> BlockChain {
        // Get all the blockchains that extend the anchor.
        let blockchains: Vec<BlockChain> = self.tree.blockchains();

        // Find the length of the longest blockchain.
        let mut longest_blockchain_len = 0;
        for blockchain in blockchains.iter() {
            longest_blockchain_len = longest_blockchain_len.max(blockchain.len());
        }

        // Get all the longest blockchains.
        let longest_blockchains: Vec<BlockChain> = blockchains
            .into_iter()
            .filter(|bc| bc.len() == longest_blockchain_len)
            .collect();

        let mut current_chain = vec![];
        for height_idx in 0..longest_blockchain_len {
            // If all the blocks on the same height are identical, then this block is part of the
            // "current" chain.
            let block = longest_blockchains[0][height_idx];
            let block_hash = block.block_hash();

            for chain in longest_blockchains.iter().skip(1) {
                if chain[height_idx].block_hash() != block_hash {
                    return current_chain;
                }
            }

            current_chain.push(block);
        }

        current_chain
    }

    pub fn get_blocks(&self) -> Vec<&Block> {
        self.tree.blockchains().into_iter().flatten().collect()
    }

    pub fn to_proto(&self) -> proto::BlockForest {
        proto::BlockForest {
            delta: self.delta,
            tree: Some(self.tree.to_proto()),
        }
    }

    pub fn from_proto(block_forest_proto: proto::BlockForest) -> Self {
        Self {
            delta: block_forest_proto.delta,
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
struct BlockTree {
    root: Block,
    children: Vec<BlockTree>,
}

type BlockChain<'a> = Vec<&'a Block>;

/// An error thrown when trying to add a block that is not part of the tree.
/// See `BlockTree.insert` for more information.
#[derive(Debug)]
pub struct BlockNotPartOfTreeError(pub Block);

impl BlockTree {
    // Create a new `BlockTree` with the given block as its root.
    fn new(root: Block) -> Self {
        Self {
            root,
            children: vec![],
        }
    }

    // Extends the tree with the given block.
    //
    // Blocks can extend the tree in the following cases:
    //   * The block is already present in the tree (no-op).
    //   * The block is a successor of a block already in the tree.
    fn extend(&mut self, block: Block) -> Result<(), BlockNotPartOfTreeError> {
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
            None => Err(BlockNotPartOfTreeError(block)),
        }
    }

    // Returns a `BlockTree` where the hash of the root block matches the provided `block_hash`
    // if it exists, and `None` otherwise.
    fn find_mut(&mut self, blockhash: &BlockHash) -> Option<&mut BlockTree> {
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

    // Returns all the blockchains in the tree.
    fn blockchains(&self) -> Vec<BlockChain> {
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

    fn depth(&self) -> u64 {
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

    fn to_proto(&self) -> proto::BlockTree {
        proto::BlockTree {
            root: Some(block::to_proto(&self.root)),
            children: self.children.iter().map(|t| t.to_proto()).collect(),
        }
    }

    fn from_proto(block_tree_proto: proto::BlockTree) -> Self {
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
    fn empty() {
        let anchor = BlockBuilder::genesis().build();

        let mut forest = BlockForest::new(1, anchor);
        assert_eq!(forest.pop(), None);
    }

    #[test]
    fn single_chain() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1).unwrap();
        assert_eq!(forest.pop(), None);

        forest.push(block_2).unwrap();

        // Block 0 (the anchor) now has one stable child (Block 1).
        // Block 0 should be returned when calling `pop`.
        assert_eq!(forest.pop(), Some(block_0));

        // Block 1 is now the anchor. It doesn't have children yet,
        // so calling `pop` should return `None`.
        assert_eq!(forest.pop(), None);
    }

    #[test]
    fn forks() {
        let genesis_block = BlockBuilder::genesis().build();
        let block = BlockBuilder::with_prev_header(genesis_block.header).build();
        let forked_block = BlockBuilder::with_prev_header(genesis_block.header).build();

        let mut forest = BlockForest::new(1, genesis_block.clone());

        forest.push(block).unwrap();
        forest.push(forked_block.clone()).unwrap();

        // Neither forks are 1-stable, so we shouldn't get anything.
        assert_eq!(forest.pop(), None);

        // Extend fork2 by another block.
        forest
            .push(BlockBuilder::with_prev_header(forked_block.header).build())
            .unwrap();

        // Now fork2 should be 1-stable. The anchor should be returned on `pop`
        // and fork2 becomes the new anchor.
        assert_eq!(forest.pop(), Some(genesis_block));
        assert_eq!(forest.tree.root, forked_block);

        // No stable children for fork 2
        assert_eq!(forest.pop(), None);
    }

    #[test]
    fn insert_in_order() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(0, block_0.clone());
        forest.push(block_1.clone()).unwrap();
        forest.push(block_2).unwrap();

        assert_eq!(forest.pop(), Some(block_0));
        assert_eq!(forest.pop(), Some(block_1));
        assert_eq!(forest.pop(), None);
    }

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

    // Creating a forest that looks like this:
    //
    // * -> 1 -> 2
    //
    // Both blocks 1 and 2 are part of the current chain.
    #[test]
    fn get_current_chain_single_blockchain() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1.clone()).unwrap();
        forest.push(block_2.clone()).unwrap();
        assert_eq!(
            forest.get_current_chain(),
            vec![&block_0, &block_1, &block_2]
        );
    }

    // Creating a forest that looks like this:
    //
    // * -> 1
    // * -> 2
    //
    // Both blocks 1 and 2 contest with each other -> current chain is empty.
    #[test]
    fn get_current_chain_two_contesting_trees() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_0.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1).unwrap();
        forest.push(block_2).unwrap();
        assert_eq!(forest.get_current_chain(), vec![&block_0]);
    }

    // Creating the following forest:
    //
    // * -> 1
    // * -> 2 -> 3
    //
    // "2 -> 3" is the longest blockchain and is should be considered "current".
    #[test]
    fn get_current_chain_longer_fork() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1).unwrap();
        forest.push(block_2.clone()).unwrap();
        forest.push(block_3.clone()).unwrap();
        assert_eq!(
            forest.get_current_chain(),
            vec![&block_0, &block_2, &block_3]
        );
    }

    // Creating the following forest:
    //
    // * -> 1 -> 2 -> 3
    //       \-> a -> b
    //
    // "1" should be returned in this case, as its the longest chain
    // without a contested tip.
    #[test]
    fn get_current_chain_fork_at_first_block() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1.clone()).unwrap();
        forest.push(block_2).unwrap();
        forest.push(block_3).unwrap();
        forest.push(block_a).unwrap();
        forest.push(block_b).unwrap();
        assert_eq!(forest.get_current_chain(), vec![&block_0, &block_1]);
    }

    // Creating the following forest:
    //
    // * -> 1 -> 2 -> 3
    //       \-> a -> b
    //   -> x -> y -> z
    //
    // All blocks are contested.
    //
    // Then add block `c` that extends block `b`, at that point
    // `1 -> a -> b -> c` becomes the only longest chain, and therefore
    // the "current" chain.
    #[test]
    fn get_current_chain_multiple_forks() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();
        let block_x = BlockBuilder::with_prev_header(block_0.header).build();
        let block_y = BlockBuilder::with_prev_header(block_x.header).build();
        let block_z = BlockBuilder::with_prev_header(block_y.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_x).unwrap();
        forest.push(block_y).unwrap();
        forest.push(block_z).unwrap();
        forest.push(block_1.clone()).unwrap();
        forest.push(block_2).unwrap();
        forest.push(block_3).unwrap();
        forest.push(block_a.clone()).unwrap();
        forest.push(block_b.clone()).unwrap();
        assert_eq!(forest.get_current_chain(), vec![&block_0]);

        // Now add block c to b.
        let block_c = BlockBuilder::with_prev_header(block_b.header).build();
        forest.push(block_c.clone()).unwrap();

        // Now the current chain should be "1 -> a -> b -> c"
        assert_eq!(
            forest.get_current_chain(),
            vec![&block_0, &block_1, &block_a, &block_b, &block_c]
        );
    }

    // Same as the above test, with a different insertion order.
    #[test]
    fn get_current_chain_multiple_forks_2() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();
        let block_a = BlockBuilder::with_prev_header(block_1.header).build();
        let block_b = BlockBuilder::with_prev_header(block_a.header).build();
        let block_x = BlockBuilder::with_prev_header(block_0.header).build();
        let block_y = BlockBuilder::with_prev_header(block_x.header).build();
        let block_z = BlockBuilder::with_prev_header(block_y.header).build();

        let mut forest = BlockForest::new(1, block_0.clone());

        forest.push(block_1).unwrap();
        forest.push(block_2).unwrap();
        forest.push(block_3).unwrap();
        forest.push(block_a).unwrap();
        forest.push(block_b).unwrap();
        forest.push(block_x).unwrap();
        forest.push(block_y).unwrap();
        forest.push(block_z).unwrap();
        assert_eq!(forest.get_current_chain(), vec![&block_0]);
    }

    #[test]
    fn get_current_chain_anchor_only() {
        let block_0 = BlockBuilder::genesis().build();
        let forest = BlockForest::new(1, block_0.clone());

        assert_eq!(forest.get_current_chain(), vec![&block_0]);
    }
}
