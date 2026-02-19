# Certified Map

This package provides a map that can be used by Internet Computer canisters to implement _certified queries_.

## Features

  * Incremental certification.
    The canister can store thousands of entries while keeping the cost of certification relatively low.

  * Proofs of absence.
    If the requested key is not present in the map, the returned tree structure allows the caller to verify that fact.

  * Relatively small merkle proofs.
    The size overhead of the certificate is O(log N), where N is the number of entries in the map.

## Implementation Details

The canister uses an augmented Red-Black binary search tree to store the entries.
Each node of the search tree is annotated with the root hash of the hash tree built from the subtree rooted at this node.
Each time the tree is rotated or modified, the corresponding hashes are recomputed in O(1) time.
