use bitcoin::{Block, BlockHash};
use ic_replicated_state::bitcoin_state::BlockTree;

pub type BlockChain<'a> = Vec<&'a Block>;

/// Extends the tree with the given block.
///
/// Blocks can extend the tree in the following cases:
///   * The block is already present in the tree (no-op).
///   * The block is a successor of a block already in the tree.
pub fn extend(block_tree: &mut BlockTree, block: Block) -> Result<(), BlockDoesNotExtendTree> {
    if contains(block_tree, &block) {
        // The block is already present in the tree. Nothing to do.
        return Ok(());
    }

    // Check if the block is a successor to any of the blocks in the tree.
    match find_mut(block_tree, &block.header.prev_blockhash) {
        Some(block_subtree) => {
            assert_eq!(block_subtree.root.block_hash(), block.header.prev_blockhash);
            // Add the block as a successor.
            block_subtree.children.push(BlockTree::new(block));
            Ok(())
        }
        None => Err(BlockDoesNotExtendTree(block)),
    }
}

/// Returns all the blockchains in the tree.
pub fn blockchains(block_tree: &BlockTree) -> Vec<BlockChain> {
    if block_tree.children.is_empty() {
        return vec![vec![&block_tree.root]];
    }

    let mut tips = vec![];
    for child in block_tree.children.iter() {
        tips.extend(
            blockchains(child)
                .into_iter()
                .map(|bc| concat(vec![&block_tree.root], bc))
                .collect::<Vec<BlockChain>>(),
        );
    }

    tips
}

/// Returns the depth of the tree.
pub fn depth(block_tree: &BlockTree) -> u32 {
    if block_tree.children.is_empty() {
        return 0;
    }

    let mut max_child_depth = 0;

    for child in block_tree.children.iter() {
        max_child_depth = std::cmp::max(1 + depth(child), max_child_depth);
    }

    max_child_depth
}

// Returns a `BlockTree` where the hash of the root block matches the provided `block_hash`
// if it exists, and `None` otherwise.
fn find_mut<'a>(block_tree: &'a mut BlockTree, blockhash: &BlockHash) -> Option<&'a mut BlockTree> {
    if block_tree.root.block_hash() == *blockhash {
        return Some(block_tree);
    }

    for child in block_tree.children.iter_mut() {
        if let res @ Some(_) = find_mut(child, blockhash) {
            return res;
        }
    }

    None
}

// Returns true if a block exists in the tree, false otherwise.
fn contains(block_tree: &BlockTree, block: &Block) -> bool {
    if block_tree.root.block_hash() == block.block_hash() {
        return true;
    }

    for child in block_tree.children.iter() {
        if contains(child, block) {
            return true;
        }
    }

    false
}

/// An error thrown when trying to add a block that isn't a successor
/// of any block in the tree.
#[derive(Debug)]
pub struct BlockDoesNotExtendTree(pub Block);

fn concat<T>(mut a: Vec<T>, b: Vec<T>) -> Vec<T> {
    a.extend(b);
    a
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_btc_test_utils::BlockBuilder;

    #[test]
    fn tree_single_block() {
        let block_tree = BlockTree::new(BlockBuilder::genesis().build());

        assert_eq!(depth(&block_tree), 0);
        assert_eq!(blockchains(&block_tree), vec![vec![&block_tree.root]]);
    }

    #[test]
    fn tree_multiple_forks() {
        let genesis_block = BlockBuilder::genesis().build();
        let genesis_block_header = genesis_block.header;
        let mut block_tree = BlockTree::new(genesis_block);

        for i in 1..5 {
            // Create different blocks extending the genesis block.
            // Each one of these should be a separate fork.
            extend(
                &mut block_tree,
                BlockBuilder::with_prev_header(genesis_block_header).build(),
            )
            .unwrap();
            assert_eq!(blockchains(&block_tree).len(), i);
        }

        assert_eq!(depth(&block_tree), 1);
    }
}
