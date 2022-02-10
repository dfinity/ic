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
    trees: Vec<BlockTree>,
}

impl BlockForest {
    pub fn new(delta: u64) -> Self {
        Self {
            delta,
            trees: vec![],
        }
    }

    /// Pop a block that is a successor to the `anchor` iff the block is stable.
    pub fn pop(&mut self, anchor: &BlockHash) -> Option<Block> {
        let (mut attached_trees, detached_trees): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.trees)
                .into_iter()
                .partition(|t| t.root().header.prev_blockhash == *anchor);

        // Sort the attached trees by depth.
        attached_trees.sort_by(|a, b| a.depth().partial_cmp(&b.depth()).unwrap());

        match attached_trees.last() {
            Some(deepest_tree) => {
                if deepest_tree.depth() < self.delta {
                    // Need a depth of at least >= delta
                    self.trees = concat(attached_trees, detached_trees);
                    return None;
                }

                if attached_trees.len() >= 2 {
                    if let Some(second_deepest_tree) = attached_trees.get(attached_trees.len() - 2)
                    {
                        if deepest_tree.depth() - second_deepest_tree.depth() < self.delta {
                            // Difference must be >= delta
                            self.trees = concat(attached_trees, detached_trees);
                            return None;
                        }
                    }
                }

                // The deepest tree is delta-stable.
                // Pop the root of the tree, remove all other attached_trees.
                let deepest_tree = attached_trees.pop().unwrap();
                let (stable_block, subtrees) = deepest_tree.pop();

                self.trees = concat(detached_trees, subtrees);
                Some(stable_block)
            }
            None => {
                self.trees = concat(attached_trees, detached_trees);
                None
            }
        }
    }

    /// Push a new block into the store.
    pub fn push(&mut self, mut block: Block) {
        let block_hash = block.block_hash();
        let successor_tree = self.take_tree(&block_hash);

        for i in 0..self.trees.len() {
            match self.trees[i].extend(block) {
                Ok(()) => {
                    if let Some(successor_tree) = successor_tree {
                        let block = self.trees[i].find_mut(&block_hash).unwrap();
                        block.children.push(successor_tree);
                    }

                    return;
                }
                Err(BlockNotPartOfTreeError(block_)) => {
                    block = block_;
                }
            }
        }

        let mut new_block_tree = BlockTree::new(block);
        if let Some(successor_tree) = successor_tree {
            new_block_tree.children.push(successor_tree);
        }
        self.trees.push(new_block_tree);
    }

    /// Returns the best guess on what the "current" blockchain is.
    ///
    /// The most likely chain to be "current", we hypothesize, is the longest
    /// chain of blocks with an "uncontested" tip. As in, there exists no other
    /// block at the same height as the tip.
    pub fn get_current_chain(&self, anchor: &BlockHash) -> BlockChain {
        // Get all the blockchains that extend the anchor.
        let blockchains: Vec<BlockChain> = self
            .trees
            .iter()
            .filter(|t| t.root().header.prev_blockhash == *anchor)
            .map(|t| t.blockchains())
            .flatten()
            .collect();

        if blockchains.is_empty() {
            // No attached blockchains found.
            // NOTE: this if condition isn't strictly required, as the following code should
            // handle the empty case gracefully. Nonetheless, it's added out of paranoia.
            return vec![];
        }

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

    fn take_tree(&mut self, root_block_hash: &BlockHash) -> Option<BlockTree> {
        for i in 0..self.trees.len() {
            if &self.trees[i].root().header.prev_blockhash == root_block_hash {
                return Some(self.trees.remove(i));
            }
        }
        None
    }

    pub fn get_blocks(&self) -> Vec<&Block> {
        self.trees
            .iter()
            .map(|t| t.blockchains())
            .flatten()
            .flatten()
            .collect()
    }

    pub fn to_proto(&self) -> proto::BlockForest {
        proto::BlockForest {
            delta: self.delta,
            trees: self.trees.iter().map(|t| t.to_proto()).collect(),
        }
    }

    pub fn from_proto(block_forest_proto: proto::BlockForest) -> Self {
        Self {
            delta: block_forest_proto.delta,
            trees: block_forest_proto
                .trees
                .into_iter()
                .map(BlockTree::from_proto)
                .collect(),
        }
    }
}

// Maintains a tree of connected blocks.
#[cfg_attr(test, derive(Debug, PartialEq))]
struct BlockTree {
    root: Block,
    children: Vec<BlockTree>,
}

type BlockChain<'a> = Vec<&'a Block>;

// An error thrown when trying to add a block that is not part of the tree.
// See `BlockTree.insert` for more information.
#[derive(Debug)]
struct BlockNotPartOfTreeError(pub Block);

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

    fn root(&self) -> &Block {
        &self.root
    }

    fn pop(self) -> (Block, Vec<BlockTree>) {
        (self.root, self.children)
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
        let block_0 = BlockBuilder::genesis().build();

        let mut forest = BlockForest::new(1);
        assert_eq!(forest.pop(&block_0.block_hash()), None);
    }

    #[test]
    fn single_chain() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(1);

        forest.push(block_1.clone());
        assert_eq!(forest.pop(&block_0.block_hash()), None);

        forest.push(block_2);
        assert_eq!(forest.pop(&block_0.block_hash()), Some(block_1));
    }

    #[test]
    fn forks() {
        let genesis_block = BlockBuilder::genesis().build();
        let fork_1 = BlockBuilder::with_prev_header(genesis_block.header).build();
        let fork_2 = BlockBuilder::with_prev_header(genesis_block.header).build();

        let mut forest = BlockForest::new(1);

        forest.push(fork_1);
        forest.push(fork_2.clone());

        // Neither blocks are 1-stable, so we shouldn't get anything.
        assert_eq!(forest.pop(&genesis_block.block_hash()), None);

        // Extend fork2 by another block.
        forest.push(BlockBuilder::with_prev_header(fork_2.header).build());

        // Now fork2 should be 1-stable.
        assert_eq!(
            forest.pop(&genesis_block.block_hash()),
            Some(fork_2.clone())
        );

        // No more 1-stable blocks
        assert_eq!(forest.pop(&fork_2.block_hash()), None);
    }

    // Test creating a forest that looks like this, where `i` is the successor of block `i - 1`:
    //
    // * -> 3
    // * -> 1
    //
    // And then we add "2". We expect the trees 1, 2, and 3 to all get merged.
    #[test]
    fn detached_blocks() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();

        let mut forest = BlockForest::new(1);

        forest.push(block_3);
        forest.push(block_1.clone());
        assert_eq!(forest.pop(&block_0.block_hash()), None);

        // There are two trees in the forest.
        assert_eq!(forest.trees.len(), 2);

        // Add block2, which should result in all the blocks merging into a single tree.
        forest.push(block_2.clone());
        assert_eq!(forest.trees.len(), 1);

        // Getting the blocks should work as expected.
        assert_eq!(forest.pop(&block_0.block_hash()), Some(block_1.clone()));
        assert_eq!(forest.pop(&block_1.block_hash()), Some(block_2.clone()));
        assert_eq!(forest.pop(&block_2.block_hash()), None);
    }

    // Test creating a forest that looks like this:
    //
    // * -> 3
    // * -> 0
    //
    // And then we add "1" and "2". All the trees should be merged into one.
    #[test]
    fn detached_blocks_2() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();
        let block_3 = BlockBuilder::with_prev_header(block_2.header).build();

        let mut forest = BlockForest::new(1);

        forest.push(block_3);
        forest.push(block_0);
        forest.push(block_1);
        forest.push(block_2);

        // There is only one tree in the forest.
        assert_eq!(forest.trees.len(), 1);
    }

    #[test]
    fn insert_predecessor() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();

        let mut forest = BlockForest::new(1);

        forest.push(block_1);
        forest.push(block_0);

        // There is only one tree in the forest.
        assert_eq!(forest.trees.len(), 1);
    }

    #[test]
    fn insert_in_order() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(0);
        forest.push(block_1.clone());
        forest.push(block_2.clone());

        // There is only one tree in the forest.
        assert_eq!(forest.trees.len(), 1);
        assert_eq!(forest.pop(&block_0.block_hash()), Some(block_1.clone()));
        assert_eq!(forest.pop(&block_1.block_hash()), Some(block_2.clone()));
        assert_eq!(forest.pop(&block_2.block_hash()), None);
    }

    #[test]
    fn insert_in_reverse_order() {
        let block_0 = BlockBuilder::genesis().build();
        let block_1 = BlockBuilder::with_prev_header(block_0.header).build();
        let block_2 = BlockBuilder::with_prev_header(block_1.header).build();

        let mut forest = BlockForest::new(0);
        forest.push(block_2.clone());
        forest.push(block_1.clone());

        // There is only one tree in the forest.
        assert_eq!(forest.trees.len(), 1);
        assert_eq!(forest.pop(&block_0.block_hash()), Some(block_1.clone()));
        assert_eq!(forest.pop(&block_1.block_hash()), Some(block_2.clone()));
        assert_eq!(forest.pop(&block_2.block_hash()), None);
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

        let mut forest = BlockForest::new(1);

        forest.push(block_1.clone());
        forest.push(block_2.clone());
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            vec![&block_1, &block_2]
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

        let mut forest = BlockForest::new(1);

        forest.push(block_1);
        forest.push(block_2);
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            Vec::<&Block>::new()
        );
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

        let mut forest = BlockForest::new(1);

        forest.push(block_1);
        forest.push(block_2.clone());
        forest.push(block_3.clone());
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            vec![&block_2, &block_3]
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

        let mut forest = BlockForest::new(1);

        forest.push(block_1.clone());
        forest.push(block_2);
        forest.push(block_3);
        forest.push(block_a);
        forest.push(block_b);
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            vec![&block_1]
        );
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

        let mut forest = BlockForest::new(1);

        forest.push(block_x);
        forest.push(block_y);
        forest.push(block_z);
        forest.push(block_1.clone());
        forest.push(block_2);
        forest.push(block_3);
        forest.push(block_a.clone());
        forest.push(block_b.clone());
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            Vec::<&Block>::new()
        );

        // Now add block c to b.
        let block_c = BlockBuilder::with_prev_header(block_b.header).build();
        forest.push(block_c.clone());

        // Now the current chain should be "1 -> a -> b -> c"
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            vec![&block_1, &block_a, &block_b, &block_c]
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

        let mut forest = BlockForest::new(1);

        forest.push(block_1);
        forest.push(block_2);
        forest.push(block_3);
        forest.push(block_a);
        forest.push(block_b);
        forest.push(block_x);
        forest.push(block_y);
        forest.push(block_z);
        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            Vec::<&Block>::new()
        );
    }

    #[test]
    fn get_current_chain_empty() {
        let block_0 = BlockBuilder::genesis().build();
        let forest = BlockForest::new(1);

        assert_eq!(
            forest.get_current_chain(&block_0.block_hash()),
            Vec::<&Block>::new()
        );
    }
}
