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

    memory: M,
}

#[repr(packed)]
struct BTreeHeader {
    magic: [u8; 3],
    version: u8,
    max_key_size: u32,
    max_value_size: u32,
    root_addr: Address,
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
                let (_, old_value) = node.swap_entry(idx, (key, value));

                node.save(&self.memory);
                Some(old_value)
            }
            Err(idx) => {
                // The key isn't in the node. `idx` is where that key should be inserted.

                match node.node_type {
                    NodeType::Leaf => {
                        // The node is a non-full leaf.
                        // Insert the entry at the proper location.
                        node.entries.insert(idx, (key, value));
                        node.save(&self.memory);
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

        // The result should looks like this:
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

        // The result should looks like this:
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
}
