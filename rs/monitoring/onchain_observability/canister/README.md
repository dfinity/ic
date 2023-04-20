# A Certified Blockchain

This canister holds a chain of blocks, each of which is certified by the IC Root Key and contain both a certification time and a hash of previous blocks.

The result is a irrefutable record independent of the controllers.  The certified blockchain is public and available for remote backup.  The canister can also owned by a detached canister e.g. https://github.com/ninegua/ic-blackhole or a DAO to ensure availability.

## Blockchain

The blockchain is a sequence of blocks of the format:

```
type Block = record {
  // Certificate is signed by the NNS root key and contains the root of tree.
  certificate: blob;
  // Under b"certified_blocks is a map from i as u32 BE bytes to sha256(sha256(caller{i])sha256(data[i]))
  // with an entry from "previous_hash" to previous_hash.
  tree: blob;
  // The raw data entries.
  data: vec blob;
  // Callers of prepare()/prepare_some() for corresponding "data".
  callers: vec principal;
  previous_hash: blob;
};
```

The canister smart contract provides an API to store, find entries and retrieve blocks:

```
type Auth = variant { User; Admin };
type Authorization = record {
  id: principal;
  auth: Auth;
};

service blockchain: (opt text) -> {
  // Stage a block, returning the certified data for informational purposes.
  // Traps if some data is already staged.
  prepare: (data: vec blob) -> (blob);
  // Stage some (more) data into a block, returning the hash of the root of tree for informational purposes.
  prepare_some: (data: vec blob) -> (blob);
  // Get certificate for the certified data. Returns None if nothing is staged.
  get_certificate: () -> (opt blob) query;
  // Append the staged data with certificate and tree.  Traps if the certificate is stale.
  // Returns None if there is nothing staged.
  commit: (certificate: blob) -> (opt nat64);
  // Get a certified block.
  get_block: (index: nat64) -> (Block) query;
  // Find block index with matching block hash or latest matching data entry hash.
  find: (hash: blob) -> (opt nat64) query;
  // Return the index of the first block stored.
  first: () -> (nat64) query;
  // Return the index of the start of the primary part (length of log - first() - secondary.len()).
  mid: () -> (nat64) query;
  // Return the index of the next block to be stored (the length of the log - first()).
  next: () -> (nat64) query;
  // Return hex string representing the hash of the last block or 0.
  last_hash: () -> (text) query;
  // Rotate the log by making the primary part secondary and deleting the old secondary and making it primary.
  // Returns the new first index stored if the secondary part had anything to delete.
  rotate: () -> (opt nat64);
  // Manage the set of Principals allowed to prepare and append (User) or authorize (Admin).
  authorize: (principal, Auth) -> ();
  deauthorize: (principal) -> ();
  get_authorized: () -> (vec Authorization) query;
}
```

## Certification

The certificate contains an NNS signed delegation for the canister to the subnet which certifies the canister root hash along with the date.  The canister root hash is the root of the Merkle tree containing the hashes of all the block entries.  This enables each entry to be independently certified by extracting the corresponding path from the tree.  Code to verify blocks is found in the `./verify` directory.

Additional verifications e.g. the signature of the appender should be verified at the application level.

## Storing Blocks

A block is an array of byte arrays (entries).  First the block is staged by calling `prepare()` which returns the tree root hash (for reference).  Then the certificate is retrieved via `get_certificate()` and then the block is appended by calling `append()` with the certificate.  Code to upload blocks is found in the `./store` directory.

## Blockchain Persistence

The canister smart contract stores all persistent data in stable memory.  There is no provision for deleting or rewriting blocks short of reinstalling or deleting the canister.  However, because the blocks are certified, they can be backed up remotely and validated offline.  The blocks can even be transferred to a different canister smart contract by re-storing the blocks and substituting the original certificate during the `append()` phase.

## Usage

### Single Writer

A single writer should use `prepare()` then `get_certificate()` then `append()`.  An error in `prepare()` means that there is already a prepared block which needs `get_certificate()` then `append()`.  An error in `get_certificate()` or `append()` mean that there is no prepared block or that the certificate is stale.  The client should use `get_block()` to determine if the data has already been written and retry if not.

### Multiple Writer

Multiple writers can either use the single writer workflow or they can all call `prepare_some()` and then `get_certificate()` followed by `append()` recognizing that the `get_certificate()` `append()` commit sequence might fail if there is a race.  Use of `prepare_some()` may result in higher throughput.  Clients may defer or retry the commit sequence until `get_certificate()` returns None.  Note that there is no provision in this code for DOS prevention although callers of `prepare_some()` are recorded which may be of some use.

### Log Rotation

In some use cases it may be desirable to backup and remove old blocks from the canister smart contract. Since the committed log entries are individually certified, they can be verified independent of the smart contract so the backup can be used as a primary source. Safe backup and clearing of old log entries is done via a process of log rotation. Internally the blockchain log is broken up into a primary part and a secondary part.  Periodically a backup agent should `get_block()` all blocks between `first()` and `mid()` (the first index beyond the secondary part) then call `rotate()` which makes the primary secondary, deletes the data in the old secondary and makes it primary. Note that log indexes are preserved (do not change) over time and that `find()` continues to work for entries in both the primary and secondary parts of the log.

### Dependencies

* rustup, cargo, rustc with wasm
* hash\_tree.rs is copied from github.com/dfinity/agent-rs/src/hash\_tree/mod.rs
