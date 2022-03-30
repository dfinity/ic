mod allocator;
mod node;
use crate::{
    read_struct,
    types::{Address, Bytes, NULL},
    write_struct, Memory,
};
use allocator::Allocator;
use node::{Key, Node, NodeType, Value, B};

const LAYOUT_VERSION: u8 = 1;
const MAGIC: &[u8; 3] = b"BTR";

/// A "stable" map based on a B-tree.
///
/// The implementation is based on the algorithm outlined in "Introduction to Algorithms"
/// by Cormen et al.
pub struct StableBTreeMap<M: Memory> {
    // The address of the root node. If a root node doesn't exist, the address
    // is set to NULL.
    root_addr: Address,

    // The maximum size a key can have.
    max_key_size: u32,

    // The maximum size a value can have.
    max_value_size: u32,

    // An allocator used for managing memory and allocating nodes.
    allocator: Allocator<M>,

    // The number of elements in the map.
    length: u64,

    memory: M,
}

#[repr(packed)]
struct BTreeHeader {
    magic: [u8; 3],
    version: u8,
    max_key_size: u32,
    max_value_size: u32,
    root_addr: Address,
    length: u64,
    // Additional space reserved to add new fields without breaking backward-compatibility.
    _buffer: [u8; 24],
}

impl BTreeHeader {
    fn size() -> Bytes {
        Bytes::from(core::mem::size_of::<Self>() as u64)
    }
}

impl<M: Memory + Clone> StableBTreeMap<M> {
    /// Initializes a `StableBTreeMap`.
    ///
    /// The given `memory` is assumed to be exclusively reserved for this data
    /// structure and that it starts at address zero. Typically `memory` will
    /// be an instance of `RestrictedMemory`.
    ///
    /// When initialized, the data structure has the following memory layout:
    ///
    ///    |  BTreeHeader  |  Allocator | ... free memory for nodes |
    ///
    /// See [`Allocator`] for more details on its own memory layout.
    pub fn new(memory: M, max_key_size: u32, max_value_size: u32) -> Self {
        // Because we assume that we have exclusive access to the memory,
        // we can store the `BTreeHeader` at address zero, and the allocator is
        // stored directly after the `BTreeHeader`.
        let allocator_addr = Address::from(0) + BTreeHeader::size();

        let btree = Self {
            memory: memory.clone(),
            root_addr: NULL,
            allocator: Allocator::new(
                memory,
                allocator_addr,
                Node::size(max_key_size, max_value_size),
            ),
            max_key_size,
            max_value_size,
            length: 0,
        };

        btree.save();
        btree
    }

    /// Loads the map from memory.
    pub fn load(memory: M) -> Self {
        // Read the header from memory.
        let header: BTreeHeader = read_struct(Address::from(0), &memory);
        assert_eq!(&header.magic, MAGIC, "Bad magic.");
        assert_eq!(header.version, LAYOUT_VERSION, "Unsupported version.");

        let allocator_addr = Address::from(0) + BTreeHeader::size();
        Self {
            memory: memory.clone(),
            root_addr: header.root_addr,
            allocator: Allocator::load(memory, allocator_addr),
            max_key_size: header.max_key_size,
            max_value_size: header.max_value_size,
            length: header.length,
        }
    }

    /// Inserts a key-value pair into the map.
    ///
    /// The previous value of the key, if present, is returned.
    ///
    /// The size of the key/value must be <= the max key/value sizes configured
    /// for the map. Otherwise, an `InsertError` is returned.
    pub fn insert(&mut self, key: Key, value: Value) -> Result<Option<Value>, InsertError> {
        // Verify the size of the key.
        if key.len() > self.max_key_size as usize {
            return Err(InsertError::KeyTooLarge {
                given: key.len(),
                max: self.max_key_size as usize,
            });
        }

        // Verify the size of the value.
        if value.len() > self.max_value_size as usize {
            return Err(InsertError::ValueTooLarge {
                given: value.len(),
                max: self.max_value_size as usize,
            });
        }

        let root = if self.root_addr == NULL {
            // No root present. Allocate one.
            let node = self.allocate_node(NodeType::Leaf);
            self.root_addr = node.address;
            self.save();
            node
        } else {
            // Load the root from memory.
            let root = self.load_node(self.root_addr);

            // If the root is full, we need to introduce a new node as the root.
            //
            // NOTE: In the case where we are overwriting an existing key, then introducing
            // a new root node isn't strictly necessary. However, that's a micro-optimization
            // that adds more complexity than it's worth.
            if root.is_full() {
                // The root is full. Allocate a new node that will be used as the new root.
                let mut new_root = self.allocate_node(NodeType::Internal);

                // The new root has the old root as its only child.
                new_root.children.push(self.root_addr);

                // Update the root address.
                self.root_addr = new_root.address;
                self.save();

                // Split the old (full) root.
                self.split_child(&mut new_root, 0);

                new_root
            } else {
                root
            }
        };

        Ok(self.insert_nonfull(root, key, value))
    }

    // Inserts an entry into a node that is *not full*.
    fn insert_nonfull(&mut self, mut node: Node, key: Key, value: Value) -> Option<Value> {
        // We're guaranteed by the caller that the provided node is not full.
        assert!(!node.is_full());

        // Look for the key in the node.
        match node.entries.binary_search_by(|e| e.0.cmp(&key)) {
            Ok(idx) => {
                // The key is already in the node.
                // Overwrite it and return the previous value.
                let (_, previous_value) = node.swap_entry(idx, (key, value));

                node.save(&self.memory);
                Some(previous_value)
            }
            Err(idx) => {
                // The key isn't in the node. `idx` is where that key should be inserted.

                match node.node_type {
                    NodeType::Leaf => {
                        // The node is a non-full leaf.
                        // Insert the entry at the proper location.
                        node.entries.insert(idx, (key, value));
                        node.save(&self.memory);

                        // Update the length.
                        self.length += 1;
                        self.save();

                        // No previous value to return.
                        None
                    }
                    NodeType::Internal => {
                        // The node is an internal node.
                        // Load the child that we should add the entry to.
                        let mut child = self.load_node(node.children[idx]);
                        if child.is_full() {
                            // The child is full. Split the child.
                            self.split_child(&mut node, idx);

                            // The children have now changed. Search again for
                            // the child where we need to store the entry in.
                            let idx = node
                                .entries
                                .binary_search_by(|e| e.0.cmp(&key))
                                .unwrap_or_else(|idx| idx);
                            child = self.load_node(node.children[idx]);
                        }

                        // The child should now be not full.
                        assert!(!child.is_full());

                        self.insert_nonfull(child, key, value)
                    }
                }
            }
        }
    }

    // Takes as input a nonfull internal `node` and index to its full child, then
    // splits this child into two, adding an additional child to `node`.
    //
    // Example:
    //
    //                          [ ... M   Y ... ]
    //                                  |
    //                 [ N  O  P  Q  R  S  T  U  V  W  X ]
    //
    //
    // After splitting becomes:
    //
    //                         [ ... M  S  Y ... ]
    //                                 / \
    //                [ N  O  P  Q  R ]   [ T  U  V  W  X ]
    //
    fn split_child(&mut self, node: &mut Node, full_child_idx: usize) {
        // The node must not be full.
        assert!(!node.is_full());

        // The node's child must be full.
        let mut full_child = self.load_node(node.children[full_child_idx]);
        assert!(full_child.is_full());

        // Create a sibling to this full child (which has to be the same type).
        let mut sibling = self.allocate_node(full_child.node_type);
        assert_eq!(sibling.node_type, full_child.node_type);

        // Move the values above the median into the new sibling.
        sibling.entries = full_child.entries.split_off(B as usize);

        if full_child.node_type == NodeType::Internal {
            sibling.children = full_child.children.split_off(B as usize);
        }

        // Add sibling as a new child in the node.
        node.children.insert(full_child_idx + 1, sibling.address);

        // Move the median entry into the node.
        let (median_key, median_value) = full_child
            .entries
            .pop()
            .expect("A full child cannot be empty");
        node.entries
            .insert(full_child_idx, (median_key, median_value));

        sibling.save(&self.memory);
        full_child.save(&self.memory);
        node.save(&self.memory);
    }

    /// Returns the value associated with the given key if it exists.
    pub fn get(&self, key: &Key) -> Option<Value> {
        if self.root_addr == NULL {
            return None;
        }

        self.get_helper(self.root_addr, key)
    }

    fn get_helper(&self, node_addr: Address, key: &Key) -> Option<Value> {
        let node = self.load_node(node_addr);
        match node.entries.binary_search_by(|e| e.0.cmp(key)) {
            Ok(idx) => Some(node.entries[idx].1.clone()),
            Err(idx) => {
                match node.node_type {
                    NodeType::Leaf => None, // Key not found.
                    NodeType::Internal => {
                        // The key isn't in the node. Look for the key in the child.
                        self.get_helper(node.children[idx], key)
                    }
                }
            }
        }
    }

    /// Returns `true` if the key exists in the map, `false` otherwise.
    pub fn contains_key(&self, key: &Key) -> bool {
        self.get(key).is_some()
    }

    /// Returns `true` if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Removes a key from the map, returning the previous value at the key if it exists.
    pub fn remove(&mut self, key: &Key) -> Option<Value> {
        if self.root_addr == NULL {
            return None;
        }

        self.remove_helper(self.root_addr, key)
    }

    // A helper method for recursively removing a key from the B-tree.
    fn remove_helper(&mut self, node_addr: Address, key: &Key) -> Option<Value> {
        let mut node = self.load_node(node_addr);

        if node.address != self.root_addr {
            // We're guaranteed that whenever this method is called the number
            // of keys is >= `B`. Note that this is higher than the minimum required
            // in a node, which is `B - 1`, and that's because this strengthened
            // condition allows us to delete an entry in a single pass most of the
            // time without having to back up.
            assert!(node.entries.len() >= B as usize);
        }

        match node.node_type {
            NodeType::Leaf => {
                match node.entries.binary_search_by(|e| e.0.cmp(key)) {
                    Ok(idx) => {
                        // Case 1: The node is a leaf node and the key exists in it.
                        // This is the simplest case. The key is removed from the leaf.
                        let value = node.entries.remove(idx).1;
                        self.length -= 1;

                        if node.entries.is_empty() {
                            assert_eq!(
                                node.address, self.root_addr,
                                "Removal can only result in an empty leaf node if that node is the root"
                            );

                            // Deallocate the empty node.
                            self.allocator.deallocate(node.address);
                            self.root_addr = NULL;
                        } else {
                            node.save(&self.memory);
                        }

                        self.save();
                        Some(value)
                    }
                    _ => None, // Key not found.
                }
            }
            NodeType::Internal => {
                match node.entries.binary_search_by(|e| e.0.cmp(key)) {
                    Ok(idx) => {
                        // Case 2: The node is an internal node and the key exists in it.

                        // Check if the child that precedes `key` has at least `B` keys.
                        let left_child = self.load_node(node.children[idx]);
                        if left_child.entries.len() >= B as usize {
                            // Case 2.a: The node's left child has >= `B` keys.
                            //
                            //                       parent
                            //                  [..., key, ...]
                            //                       /   \
                            //            [left child]   [...]
                            //           /            \
                            //        [...]         [..., key predecessor]
                            //
                            // In this case, we replace `key` with the key's predecessor from the
                            // left child's subtree, then we recursively delete the key's
                            // predecessor for the following end result:
                            //
                            //                       parent
                            //            [..., key predecessor, ...]
                            //                       /   \
                            //            [left child]   [...]
                            //           /            \
                            //        [...]          [...]

                            // Recursively delete the predecessor.
                            // TODO(EXC-1034): Do this in a single pass.
                            let predecessor = left_child.get_max(&self.memory);
                            self.remove_helper(node.children[idx], &predecessor.0)?;

                            // Replace the `key` with its predecessor.
                            let (_, old_value) = node.swap_entry(idx, predecessor);

                            // Save the parent node.
                            node.save(&self.memory);
                            return Some(old_value);
                        }

                        // Check if the child that succeeds `key` has at least `B` keys.
                        let right_child = self.load_node(node.children[idx + 1]);
                        if right_child.entries.len() >= B as usize {
                            // Case 2.b: The node's right child has >= `B` keys.
                            //
                            //                       parent
                            //                  [..., key, ...]
                            //                       /   \
                            //                   [...]   [right child]
                            //                          /             \
                            //              [key successor, ...]     [...]
                            //
                            // In this case, we replace `key` with the key's successor from the
                            // right child's subtree, then we recursively delete the key's
                            // successor for the following end result:
                            //
                            //                       parent
                            //            [..., key successor, ...]
                            //                       /   \
                            //                  [...]   [right child]
                            //                           /            \
                            //                        [...]          [...]

                            // Recursively delete the successor.
                            // TODO(EXC-1034): Do this in a single pass.
                            let successor = right_child.get_min(&self.memory);
                            self.remove_helper(node.children[idx + 1], &successor.0)?;

                            // Replace the `key` with its successor.
                            let (_, old_value) = node.swap_entry(idx, successor);

                            // Save the parent node.
                            node.save(&self.memory);
                            return Some(old_value);
                        }

                        // Case 2.c: Both the left child and right child have B - 1 keys.
                        //
                        //                       parent
                        //                  [..., key, ...]
                        //                       /   \
                        //            [left child]   [right child]
                        //
                        // In this case, we merge (left child, key, right child) into a single
                        // node of size 2B - 1. The result will look like this:
                        //
                        //                       parent
                        //                     [...  ...]
                        //                         |
                        //          [left child, `key`, right child] <= new child
                        //
                        // We then recurse on this new child to delete `key`.
                        //
                        // If `parent` becomes empty (which can only happen if it's the root),
                        // then `parent` is deleted and `new_child` becomes the new root.
                        assert_eq!(left_child.entries.len(), B as usize - 1);
                        assert_eq!(right_child.entries.len(), B as usize - 1);

                        // Merge the right child into the left child.
                        let new_child =
                            self.merge(right_child, left_child, node.entries.remove(idx));

                        // Remove the right child from the parent node.
                        node.children.remove(idx + 1);

                        if node.entries.is_empty() {
                            // Can only happen if this node is root.
                            assert_eq!(node.address, self.root_addr);
                            assert_eq!(node.children, vec![new_child.address]);

                            self.root_addr = new_child.address;

                            // Deallocate the root node.
                            self.allocator.deallocate(node.address);
                            self.save();
                        }

                        node.save(&self.memory);
                        new_child.save(&self.memory);

                        // Recursively delete the key.
                        self.remove_helper(new_child.address, key)
                    }
                    Err(idx) => {
                        // Case 3: The node is an internal node and the key does NOT exist in it.

                        // If the key does exist in the tree, it will exist in the subtree at index
                        // `idx`.
                        let mut child = self.load_node(node.children[idx]);

                        if child.entries.len() >= B as usize {
                            // The child has enough nodes. Recurse to delete the `key` from the
                            // `child`.
                            return self.remove_helper(node.children[idx], key);
                        }

                        // The child has < `B` keys. Let's see if it has a sibling with >= `B` keys.
                        let mut left_sibling = if idx > 0 {
                            Some(self.load_node(node.children[idx - 1]))
                        } else {
                            None
                        };

                        let mut right_sibling = if idx + 1 < node.children.len() {
                            Some(self.load_node(node.children[idx + 1]))
                        } else {
                            None
                        };

                        if let Some(ref mut left_sibling) = left_sibling {
                            if left_sibling.entries.len() >= B as usize {
                                // Case 3.a (left): The child has a left sibling with >= `B` keys.
                                //
                                //                            [d] (parent)
                                //                           /   \
                                //  (left sibling) [a, b, c]     [e, f] (child)
                                //                         \
                                //                         [c']
                                //
                                // In this case, we move a key down from the parent into the child
                                // and move a key from the left sibling up into the parent
                                // resulting in the following tree:
                                //
                                //                            [c] (parent)
                                //                           /   \
                                //       (left sibling) [a, b]   [d, e, f] (child)
                                //                              /
                                //                            [c']
                                //
                                // We then recurse to delete the key from the child.

                                // Remove the last entry from the left sibling.
                                let (left_sibling_key, left_sibling_value) =
                                    left_sibling.entries.pop().unwrap();

                                // Replace the parent's entry with the one from the left sibling.
                                let (parent_key, parent_value) = node
                                    .swap_entry(idx - 1, (left_sibling_key, left_sibling_value));

                                // Move the entry from the parent into the child.
                                child.entries.insert(0, (parent_key, parent_value));

                                // Move the last child from left sibling into child.
                                if let Some(last_child) = left_sibling.children.pop() {
                                    assert_eq!(left_sibling.node_type, NodeType::Internal);
                                    assert_eq!(child.node_type, NodeType::Internal);

                                    child.children.insert(0, last_child);
                                } else {
                                    assert_eq!(left_sibling.node_type, NodeType::Leaf);
                                    assert_eq!(child.node_type, NodeType::Leaf);
                                }

                                left_sibling.save(&self.memory);
                                child.save(&self.memory);
                                node.save(&self.memory);
                                return self.remove_helper(child.address, key);
                            }
                        }

                        if let Some(right_sibling) = &mut right_sibling {
                            if right_sibling.entries.len() >= B as usize {
                                // Case 3.a (right): The child has a right sibling with >= `B` keys.
                                //
                                //                            [c] (parent)
                                //                           /   \
                                //             (child) [a, b]     [d, e, f] (left sibling)
                                //                               /
                                //                            [d']
                                //
                                // In this case, we move a key down from the parent into the child
                                // and move a key from the right sibling up into the parent
                                // resulting in the following tree:
                                //
                                //                            [d] (parent)
                                //                           /   \
                                //          (child) [a, b, c]     [e, f] (right sibling)
                                //                          \
                                //                           [d']
                                //
                                // We then recurse to delete the key from the child.

                                // Remove the first entry from the right sibling.
                                let (right_sibling_key, right_sibling_value) =
                                    right_sibling.entries.remove(0);

                                // Replace the parent's entry with the one from the right sibling.
                                let parent_entry =
                                    node.swap_entry(idx, (right_sibling_key, right_sibling_value));

                                // Move the entry from the parent into the child.
                                child.entries.push(parent_entry);

                                // Move the first child of right_sibling into `child`.
                                match right_sibling.node_type {
                                    NodeType::Internal => {
                                        assert_eq!(child.node_type, NodeType::Internal);
                                        child.children.push(right_sibling.children.remove(0));
                                    }
                                    NodeType::Leaf => {
                                        assert_eq!(child.node_type, NodeType::Leaf);
                                    }
                                }

                                right_sibling.save(&self.memory);
                                child.save(&self.memory);
                                node.save(&self.memory);
                                return self.remove_helper(child.address, key);
                            }
                        }

                        // Case 3.b: neither siblings of the child have >= `B` keys.

                        if let Some(left_sibling) = left_sibling {
                            // Merge child into left sibling if it exists.

                            let left_sibling_address = left_sibling.address;
                            self.merge(child, left_sibling, node.entries.remove(idx - 1));
                            // Removing child from parent.
                            node.children.remove(idx);

                            if node.entries.is_empty() {
                                self.allocator.deallocate(node.address);

                                if node.address == self.root_addr {
                                    // Update the root.
                                    self.root_addr = left_sibling_address;
                                    self.save();
                                }
                            } else {
                                node.save(&self.memory);
                            }

                            return self.remove_helper(left_sibling_address, key);
                        }

                        if let Some(right_sibling) = right_sibling {
                            // Merge child into right sibling.

                            let right_sibling_address = right_sibling.address;
                            self.merge(child, right_sibling, node.entries.remove(idx));

                            // Removing child from parent.
                            node.children.remove(idx);

                            if node.entries.is_empty() {
                                self.allocator.deallocate(node.address);

                                if node.address == self.root_addr {
                                    // Update the root.
                                    self.root_addr = right_sibling_address;
                                    self.save();
                                }
                            } else {
                                node.save(&self.memory);
                            }

                            return self.remove_helper(right_sibling_address, key);
                        }

                        unreachable!("At least one of the siblings must exist.");
                    }
                }
            }
        }
    }

    // Merges one node (`source`) into another (`into`), along with a median entry.
    //
    // Example (values are not included for brevity):
    //
    // Input:
    //   Source: [1, 2, 3]
    //   Into: [5, 6, 7]
    //   Median: 4
    //
    // Output:
    //   [1, 2, 3, 4, 5, 6, 7] (stored in the `into` node)
    //   `source` is deallocated.
    fn merge(&mut self, source: Node, into: Node, median: (Key, Value)) -> Node {
        assert_eq!(source.node_type, into.node_type);
        assert!(!source.entries.is_empty());
        assert!(!into.entries.is_empty());

        let into_address = into.address;
        let source_address = source.address;

        // Figure out which node contains lower values than the other.
        let (mut lower, mut higher) = if source.entries[0].0 < into.entries[0].0 {
            (source, into)
        } else {
            (into, source)
        };

        lower.entries.push(median);

        lower.entries.append(&mut higher.entries);

        lower.address = into_address;

        // Move the children (if any exist).
        lower.children.append(&mut higher.children);

        lower.save(&self.memory);

        self.allocator.deallocate(source_address);
        lower
    }

    fn allocate_node(&mut self, node_type: NodeType) -> Node {
        Node {
            address: self.allocator.allocate(),
            entries: vec![],
            children: vec![],
            node_type,
            max_key_size: self.max_key_size,
            max_value_size: self.max_value_size,
        }
    }

    fn load_node(&self, address: Address) -> Node {
        Node::load(
            address,
            &self.memory,
            self.max_key_size,
            self.max_value_size,
        )
    }

    // Saves the map to memory.
    fn save(&self) {
        let header = BTreeHeader {
            magic: *MAGIC,
            version: LAYOUT_VERSION,
            root_addr: self.root_addr,
            max_key_size: self.max_key_size,
            max_value_size: self.max_value_size,
            length: self.length,
            _buffer: [0; 24],
        };

        write_struct(&header, Address::from(0), &self.memory);
    }
}

/// An error returned when inserting entries into the map.
#[derive(Debug, PartialEq)]
pub enum InsertError {
    KeyTooLarge { given: usize, max: usize },
    ValueTooLarge { given: usize, max: usize },
}

impl std::fmt::Display for InsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyTooLarge { given, max } => {
                write!(
                    f,
                    "InsertError::KeyTooLarge Expected key to be <= {} bytes but received key with {} bytes.",
                    max, given
                )
            }
            Self::ValueTooLarge { given, max } => {
                write!(
                    f,
                    "InsertError::ValueTooLarge Expected value to be <= {} bytes but received value with {} bytes.",
                    max, given
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::btreemap::node::CAPACITY;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn make_memory() -> Rc<RefCell<Vec<u8>>> {
        Rc::new(RefCell::new(Vec::new()))
    }

    // A helper method to succinctly create an entry.
    fn e(x: u8) -> (Key, Value) {
        (vec![x], vec![])
    }

    #[test]
    fn insert_get() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 3, 4);

        assert_eq!(btree.insert(vec![1, 2, 3], vec![4, 5, 6]), Ok(None));
        assert_eq!(btree.get(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
    }

    #[test]
    fn insert_overwrites_previous_value() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        assert_eq!(btree.insert(vec![1, 2, 3], vec![4, 5, 6]), Ok(None));
        assert_eq!(
            btree.insert(vec![1, 2, 3], vec![7, 8, 9]),
            Ok(Some(vec![4, 5, 6]))
        );
        assert_eq!(btree.get(&vec![1, 2, 3]), Some(vec![7, 8, 9]));
    }

    #[test]
    fn insert_get_multiple() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        assert_eq!(btree.insert(vec![1, 2, 3], vec![4, 5, 6]), Ok(None));
        assert_eq!(btree.insert(vec![4, 5], vec![7, 8, 9, 10]), Ok(None));
        assert_eq!(btree.insert(vec![], vec![11]), Ok(None));
        assert_eq!(btree.get(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(btree.get(&vec![4, 5]), Some(vec![7, 8, 9, 10]));
        assert_eq!(btree.get(&vec![]), Some(vec![11]));
    }

    #[test]
    fn allocations() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 0..CAPACITY as u8 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }

        // Only need a single allocation to store up to `CAPACITY` elements.
        assert_eq!(btree.allocator.num_allocated_chunks(), 1);

        assert_eq!(btree.insert(vec![255], vec![]), Ok(None));

        // The node had to be split into three nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);
    }

    #[test]
    fn allocations_2() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);
        assert_eq!(btree.allocator.num_allocated_chunks(), 0);

        assert_eq!(btree.insert(vec![], vec![]), Ok(None));
        assert_eq!(btree.allocator.num_allocated_chunks(), 1);

        assert_eq!(btree.remove(&vec![]), Some(vec![]));
        assert_eq!(btree.allocator.num_allocated_chunks(), 0);
    }

    #[test]
    fn insert_same_key_multiple() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        assert_eq!(btree.insert(vec![1], vec![2]), Ok(None));

        for i in 2..10 {
            assert_eq!(btree.insert(vec![1], vec![i + 1]), Ok(Some(vec![i])));
        }
    }

    #[test]
    fn insert_split_node() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }

        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        for i in 1..=12 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }
    }

    #[test]
    fn overwrite_test() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        let num_elements: u8 = 255;

        // Ensure that the number of elements we insert is significantly
        // higher than `CAPACITY` so that we test interesting cases (e.g.
        // overwriting the value in an internal node).
        assert!(num_elements as u64 > 10 * CAPACITY);

        for i in 0..num_elements {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }

        // Overwrite the values.
        for i in 0..num_elements {
            // Assert we retrieved the old value correctly.
            assert_eq!(btree.insert(vec![i], vec![1, 2, 3]), Ok(Some(vec![])));
            // Assert we retrieved the new value correctly.
            assert_eq!(btree.get(&vec![i]), Some(vec![1, 2, 3]));
        }
    }

    #[test]
    fn insert_split_multiple_nodes() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }
        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![6], vec![])]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(
            child_0.entries,
            vec![
                (vec![1], vec![]),
                (vec![2], vec![]),
                (vec![3], vec![]),
                (vec![4], vec![]),
                (vec![5], vec![])
            ]
        );

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(
            child_1.entries,
            vec![
                (vec![7], vec![]),
                (vec![8], vec![]),
                (vec![9], vec![]),
                (vec![10], vec![]),
                (vec![11], vec![]),
                (vec![12], vec![])
            ]
        );

        for i in 1..=12 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        // Insert more to cause more splitting.
        assert_eq!(btree.insert(vec![13], vec![]), Ok(None));
        assert_eq!(btree.insert(vec![14], vec![]), Ok(None));
        assert_eq!(btree.insert(vec![15], vec![]), Ok(None));
        assert_eq!(btree.insert(vec![16], vec![]), Ok(None));
        assert_eq!(btree.insert(vec![17], vec![]), Ok(None));
        // Should cause another split
        assert_eq!(btree.insert(vec![18], vec![]), Ok(None));

        for i in 1..=18 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![6], vec![]), (vec![12], vec![])]);
        assert_eq!(root.children.len(), 3);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(
            child_0.entries,
            vec![
                (vec![1], vec![]),
                (vec![2], vec![]),
                (vec![3], vec![]),
                (vec![4], vec![]),
                (vec![5], vec![])
            ]
        );

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(
            child_1.entries,
            vec![
                (vec![7], vec![]),
                (vec![8], vec![]),
                (vec![9], vec![]),
                (vec![10], vec![]),
                (vec![11], vec![]),
            ]
        );

        let child_2 = btree.load_node(root.children[2]);
        assert_eq!(child_2.node_type, NodeType::Leaf);
        assert_eq!(
            child_2.entries,
            vec![
                (vec![13], vec![]),
                (vec![14], vec![]),
                (vec![15], vec![]),
                (vec![16], vec![]),
                (vec![17], vec![]),
                (vec![18], vec![]),
            ]
        );
    }

    #[test]
    fn remove_simple() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        assert_eq!(btree.insert(vec![1, 2, 3], vec![4, 5, 6]), Ok(None));
        assert_eq!(btree.get(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(btree.remove(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(btree.get(&vec![1, 2, 3]), None);
    }

    #[test]
    fn remove_case_2a_and_2c() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }
        // Should now split a node.
        assert_eq!(btree.insert(vec![0], vec![]), Ok(None));

        // The result should look like this:
        //                    [6]
        //                   /   \
        // [0, 1, 2, 3, 4, 5]     [7, 8, 9, 10, 11]

        for i in 0..=11 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        // Remove node 6. Triggers case 2.a
        assert_eq!(btree.remove(&vec![6]), Some(vec![]));

        // The result should look like this:
        //                [5]
        //               /   \
        // [0, 1, 2, 3, 4]   [7, 8, 9, 10, 11]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![e(5)]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(0), e(1), e(2), e(3), e(4)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(7), e(8), e(9), e(10), e(11)]);

        // There are three allocated nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);

        // Remove node 5. Triggers case 2c
        assert_eq!(btree.remove(&vec![5]), Some(vec![]));

        // Reload the btree to verify that we saved it correctly.
        let btree = StableBTreeMap::load(mem);

        // The result should look like this:
        // [0, 1, 2, 3, 4, 7, 8, 9, 10, 11]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(
            root.entries,
            vec![e(0), e(1), e(2), e(3), e(4), e(7), e(8), e(9), e(10), e(11)]
        );

        // There is only one node allocated.
        assert_eq!(btree.allocator.num_allocated_chunks(), 1);
    }

    #[test]
    fn remove_case_2b() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }
        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        for i in 1..=12 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        // Remove node 6. Triggers case 2.b
        assert_eq!(btree.remove(&vec![6]), Some(vec![]));

        // The result should look like this:
        //                [7]
        //               /   \
        // [1, 2, 3, 4, 5]   [8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![e(7)]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(1), e(2), e(3), e(4), e(5)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(8), e(9), e(10), e(11), e(12)]);

        // Remove node 7. Triggers case 2.c
        assert_eq!(btree.remove(&vec![7]), Some(vec![]));
        // The result should look like this:
        //
        // [1, 2, 3, 4, 5, 8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Leaf);
        assert_eq!(
            root.entries,
            vec![
                e(1),
                e(2),
                e(3),
                e(4),
                e(5),
                e(8),
                e(9),
                e(10),
                e(11),
                e(12)
            ]
        );
    }

    #[test]
    fn remove_case_3a_right() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }

        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        // Remove node 3. Triggers case 3.a
        assert_eq!(btree.remove(&vec![3]), Some(vec![]));

        // The result should look like this:
        //                [7]
        //               /   \
        // [1, 2, 4, 5, 6]   [8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![7], vec![])]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(1), e(2), e(4), e(5), e(6)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(8), e(9), e(10), e(11), e(12)]);

        // There are three allocated nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);
    }

    #[test]
    fn remove_case_3a_left() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }
        // Should now split a node.
        assert_eq!(btree.insert(vec![0], vec![]), Ok(None));

        // The result should look like this:
        //                   [6]
        //                  /   \
        // [0, 1, 2, 3, 4, 5]   [7, 8, 9, 10, 11]

        // Remove node 8. Triggers case 3.a left
        assert_eq!(btree.remove(&vec![8]), Some(vec![]));

        // The result should look like this:
        //                [5]
        //               /   \
        // [0, 1, 2, 3, 4]   [6, 7, 9, 10, 11]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![5], vec![])]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(0), e(1), e(2), e(3), e(4)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(6), e(7), e(9), e(10), e(11)]);

        // There are three allocated nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);
    }

    #[test]
    fn remove_case_3b_merge_into_right() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }
        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        for i in 1..=12 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        // Remove node 6. Triggers case 2.b
        assert_eq!(btree.remove(&vec![6]), Some(vec![]));
        // The result should look like this:
        //                [7]
        //               /   \
        // [1, 2, 3, 4, 5]   [8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![7], vec![])]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(1), e(2), e(3), e(4), e(5)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(8), e(9), e(10), e(11), e(12)]);

        // There are three allocated nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);

        // Remove node 3. Triggers case 3.b
        assert_eq!(btree.remove(&vec![3]), Some(vec![]));

        // Reload the btree to verify that we saved it correctly.
        let btree = StableBTreeMap::load(mem);

        // The result should look like this:
        //
        // [1, 2, 4, 5, 7, 8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Leaf);
        assert_eq!(
            root.entries,
            vec![
                e(1),
                e(2),
                e(4),
                e(5),
                e(7),
                e(8),
                e(9),
                e(10),
                e(11),
                e(12)
            ]
        );

        // There is only one allocated node remaining.
        assert_eq!(btree.allocator.num_allocated_chunks(), 1);
    }

    #[test]
    fn remove_case_3b_merge_into_left() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        for i in 1..=11 {
            assert_eq!(btree.insert(vec![i], vec![]), Ok(None));
        }

        // Should now split a node.
        assert_eq!(btree.insert(vec![12], vec![]), Ok(None));

        // The result should look like this:
        //                [6]
        //               /   \
        // [1, 2, 3, 4, 5]   [7, 8, 9, 10, 11, 12]

        for i in 1..=12 {
            assert_eq!(btree.get(&vec![i]), Some(vec![]));
        }

        // Remove node 6. Triggers case 2.b
        assert_eq!(btree.remove(&vec![6]), Some(vec![]));

        // The result should look like this:
        //                [7]
        //               /   \
        // [1, 2, 3, 4, 5]   [8, 9, 10, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Internal);
        assert_eq!(root.entries, vec![(vec![7], vec![])]);
        assert_eq!(root.children.len(), 2);

        let child_0 = btree.load_node(root.children[0]);
        assert_eq!(child_0.node_type, NodeType::Leaf);
        assert_eq!(child_0.entries, vec![e(1), e(2), e(3), e(4), e(5)]);

        let child_1 = btree.load_node(root.children[1]);
        assert_eq!(child_1.node_type, NodeType::Leaf);
        assert_eq!(child_1.entries, vec![e(8), e(9), e(10), e(11), e(12)]);

        // There are three allocated nodes.
        assert_eq!(btree.allocator.num_allocated_chunks(), 3);

        // Remove node 10. Triggers case 3.b where we merge the right into the left.
        assert_eq!(btree.remove(&vec![10]), Some(vec![]));

        // Reload the btree to verify that we saved it correctly.
        let btree = StableBTreeMap::load(mem);

        // The result should look like this:
        //
        // [1, 2, 3, 4, 5, 7, 8, 9, 11, 12]
        let root = btree.load_node(btree.root_addr);
        assert_eq!(root.node_type, NodeType::Leaf);
        assert_eq!(
            root.entries,
            vec![e(1), e(2), e(3), e(4), e(5), e(7), e(8), e(9), e(11), e(12)]
        );

        // There is only one allocated node remaining.
        assert_eq!(btree.allocator.num_allocated_chunks(), 1);
    }

    #[test]
    fn many_insertions() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.insert(vec![i, j], vec![i, j]), Ok(None));
            }
        }

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.get(&vec![i, j]), Some(vec![i, j]));
            }
        }

        let mut btree = StableBTreeMap::load(mem);

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.remove(&vec![i, j]), Some(vec![i, j]));
            }
        }

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.get(&vec![i, j]), None);
            }
        }

        // We've deallocated everything.
        assert_eq!(btree.allocator.num_allocated_chunks(), 0);
    }

    #[test]
    fn many_insertions_2() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        for j in (0..=10).rev() {
            for i in (0..=255).rev() {
                assert_eq!(btree.insert(vec![i, j], vec![i, j]), Ok(None));
            }
        }

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.get(&vec![i, j]), Some(vec![i, j]));
            }
        }

        let mut btree = StableBTreeMap::load(mem);

        for j in (0..=10).rev() {
            for i in (0..=255).rev() {
                assert_eq!(btree.remove(&vec![i, j]), Some(vec![i, j]));
            }
        }

        for j in 0..=10 {
            for i in 0..=255 {
                assert_eq!(btree.get(&vec![i, j]), None);
            }
        }

        // We've deallocated everything.
        assert_eq!(btree.allocator.num_allocated_chunks(), 0);
    }

    #[test]
    fn reloading() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem.clone(), 5, 5);

        // The btree is initially empty.
        assert_eq!(btree.len(), 0);
        assert!(btree.is_empty());

        // Add an entry into the btree.
        assert_eq!(btree.insert(vec![1, 2, 3], vec![4, 5, 6]), Ok(None));
        assert_eq!(btree.len(), 1);
        assert!(!btree.is_empty());

        // Reload the btree. The element should still be there, and `len()`
        // should still be `1`.
        let btree = StableBTreeMap::load(mem.clone());
        assert_eq!(btree.get(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(btree.len(), 1);
        assert!(!btree.is_empty());

        // Remove an element. Length should be zero.
        let mut btree = StableBTreeMap::load(mem.clone());
        assert_eq!(btree.remove(&vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(btree.len(), 0);
        assert!(btree.is_empty());

        // Reload. Btree should still be empty.
        let btree = StableBTreeMap::load(mem);
        assert_eq!(btree.get(&vec![1, 2, 3]), None);
        assert_eq!(btree.len(), 0);
        assert!(btree.is_empty());
    }

    #[test]
    fn len() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        for i in 0..1000u32 {
            assert_eq!(btree.insert(i.to_le_bytes().to_vec(), vec![]), Ok(None));
        }

        assert_eq!(btree.len(), 1000);
        assert!(!btree.is_empty());

        for i in 0..1000u32 {
            assert_eq!(btree.remove(&i.to_le_bytes().to_vec()), Some(vec![]));
        }

        assert_eq!(btree.len(), 0);
        assert!(btree.is_empty());
    }

    #[test]
    fn contains_key() {
        let mem = make_memory();
        let mut btree = StableBTreeMap::new(mem, 5, 5);

        // Insert even numbers from 0 to 1000.
        for i in (0..1000u32).step_by(2) {
            assert_eq!(btree.insert(i.to_le_bytes().to_vec(), vec![]), Ok(None));
        }

        // Contains key should return true on all the even numbers and false on all the odd
        // numbers.
        for i in 0..1000u32 {
            assert_eq!(btree.contains_key(&i.to_le_bytes().to_vec()), i % 2 == 0);
        }
    }
}
