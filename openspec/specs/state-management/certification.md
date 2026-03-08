# State Certification

**Crates**: `ic-certification`, `ic-certification-version`

State certification ensures that the externally visible parts of a subnet's replicated state are agreed upon by a majority of replicas, using threshold signatures and Merkle hash trees.

## Requirements

### Requirement: Hash Tree Computation

A hash tree is computed from the canonical state tree for certification.

#### Scenario: Computing the hash tree from replicated state
- **WHEN** `hash_state(state, height)` is called
- **THEN** the canonical state tree is traversed using a `HashingVisitor`
- **AND** a full `HashTree` is produced by the `HashTreeBuilderImpl`
- **AND** the hash tree is a binary Merkle tree derived from the labeled rose tree

#### Scenario: HashingVisitor behavior
- **WHEN** the `HashingVisitor` traverses the canonical state
- **THEN** `start_subtree` begins a new subtree in the hash tree builder
- **AND** `enter_edge(label)` creates a new labeled edge
- **AND** `visit_blob(data)` creates a leaf with the blob's hash
- **AND** `visit_num(n)` creates a leaf with the number encoded as little-endian bytes
- **AND** `end_subtree` closes the subtree
- **AND** `finish` returns the completed hash tree builder

#### Scenario: Incremental hash tree computation
- **WHEN** the `hash_lazy_tree` function is used
- **THEN** it computes the hash tree from a `LazyTree` representation
- **AND** this avoids materializing the entire tree in memory

### Requirement: Certificate Verification

Certificates are verified to ensure authenticity of the certified state.

#### Scenario: Verifying a certificate with certified data
- **WHEN** `verify_certified_data(certificate, canister_id, root_pk, certified_data)` is called
- **THEN** the certificate is deserialized from CBOR
- **AND** if a delegation is present:
  - The delegation certificate is verified against the root public key
  - The delegation must not contain nested delegations (single level only)
  - The canister ID must be within the delegation's canister ranges
  - The delegation's public key is extracted
- **AND** the certificate signature is verified against the appropriate key
- **AND** the tree is parsed and the canister's certified data is extracted
- **AND** the certified data is compared against the expected value
- **AND** the certificate's timestamp is returned on success

#### Scenario: Certificate without delegation
- **WHEN** a certificate has no delegation
- **THEN** the signature is verified directly against the root public key

#### Scenario: Certificate with delegation
- **WHEN** a certificate has a delegation
- **THEN** the delegation certificate is verified first
- **AND** the delegation must contain the subnet's public key and canister ranges
- **AND** the canister ID must fall within the declared ranges
- **AND** the certificate's signature is verified against the delegation's public key

#### Scenario: Nested delegation rejection
- **WHEN** a delegation certificate itself contains another delegation
- **THEN** verification fails with `MultipleSubnetDelegationsNotAllowed`

#### Scenario: Canister ID out of range
- **WHEN** the canister ID is not within any range in the delegation
- **THEN** verification fails with `CanisterIdOutOfRange`

#### Scenario: Certified data mismatch
- **WHEN** the certified data in the certificate tree does not match the expected value
- **THEN** verification fails with `CertifiedDataMismatch`

#### Scenario: Invalid signature
- **WHEN** the threshold signature on the certificate is invalid
- **THEN** verification fails with `InvalidSignature`

#### Scenario: Malformed hash tree
- **WHEN** the hash tree in the certificate cannot be parsed
- **THEN** verification fails with `MalformedHashTree`

### Requirement: Certificate Verification for Subnet Read State

Certificates returned from the subnet endpoint have slightly different verification rules.

#### Scenario: Verifying a subnet read state certificate
- **WHEN** `verify_certificate_for_subnet_read_state(certificate, subnet_id, root_pk)` is called
- **THEN** if a delegation is present, the delegation subnet ID must match the provided subnet ID
- **AND** canister range checks are skipped (only subnet ID matching is required)
- **AND** the signature is verified normally

#### Scenario: Subnet ID mismatch in delegation
- **WHEN** the provided subnet ID does not match the delegation's subnet ID
- **THEN** verification fails with `SubnetIdMismatch`

### Requirement: Delegation Certificate Validation

Delegation certificates can be validated independently for subnet-level operations.

#### Scenario: Validating a subnet delegation certificate
- **WHEN** `validate_subnet_delegation_certificate(certificate, subnet_id, root_pk)` is called
- **THEN** the delegation certificate's signature is verified against the root key
- **AND** the subnet's public key and canister ranges are extracted from the tree
- **AND** no canister ID range check is performed (only structural validation)

### Requirement: Signature Verification Caching

Certificate verification supports optional caching for efficiency.

#### Scenario: Cached signature verification
- **WHEN** `verify_certified_data_with_cache` or `verify_certificate_with_cache` is called
- **THEN** previously verified signatures are cached
- **AND** subsequent verifications of the same signature return immediately
- **AND** this improves performance for repeated verification of the same certificates

### Requirement: Witness Generation

Witnesses (MixedHashTrees) are generated to prove specific values in the certified state.

#### Scenario: Generating a witness for a partial tree
- **WHEN** `hash_tree.witness(partial_tree)` is called
- **THEN** a `MixedHashTree` is produced that contains:
  - Actual values for nodes in the partial tree
  - Pruned hashes for nodes not in the partial tree
- **AND** the root digest of the witness matches the full hash tree's root digest

#### Scenario: Certified state read with witness
- **WHEN** `read_certified_state_with_exclusion(paths, exclusion)` is called on a `CertifiedStateSnapshot`
- **THEN** the requested paths are materialized as a partial tree from the lazy tree
- **AND** a `MixedHashTree` witness is generated from the full hash tree
- **AND** the witness root hash matches the certification hash

### Requirement: Tree Diff Computation

Hash trees can be compared to detect changes between states.

#### Scenario: Converting HashTree to RoseHashTree
- **WHEN** a `HashTree` is converted to a `RoseHashTree`
- **THEN** binary forks are flattened into a labeled rose tree
- **AND** each node carries its digest for comparison

#### Scenario: Computing tree diffs
- **WHEN** two `RoseHashTree` instances are compared
- **THEN** changed subtrees are identified by digest comparison
- **AND** paths to changed leaves are reported
