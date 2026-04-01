# State: Certification Capability Specification

**Source narrative**: `openspec/specs/state-management/certification.md`
**Crates**: `ic-certification`, `ic-certification-version`
**Key files**: `rs/certification/src/`, `rs/canonical_state/src/`

---

## REQ-CERT-001: Hash Tree Computation

A hash tree MUST be computed from the canonical state tree for certification.

### SCENARIO-CERT-001: Computing the hash tree
**Given** `hash_state(state, height)` is called
**When** the computation runs
**Then** the canonical state tree is traversed using a `HashingVisitor`
**And** a full `HashTree` is produced by the `HashTreeBuilderImpl`
**And** the hash tree is a binary Merkle tree derived from the labeled rose tree

### SCENARIO-CERT-002: HashingVisitor behavior
**Given** the `HashingVisitor` traverses the canonical state
**When** traversal runs
**Then** `visit_blob(data)` creates a leaf with the blob's hash
**And** `visit_num(n)` creates a leaf with the number encoded as little-endian bytes
**And** `start_subtree`/`end_subtree` delimit subtrees in the hash tree builder

---

## REQ-CERT-002: Certificate Verification

Certificates MUST be verified to ensure authenticity of the certified state.

### SCENARIO-CERT-003: Verify certificate without delegation
**Given** a certificate has no delegation
**When** `verify_certified_data` is called
**Then** the signature is verified directly against the root public key
**And** the certified data is extracted and compared against the expected value
**And** the certificate's timestamp is returned on success

### SCENARIO-CERT-004: Verify certificate with delegation
**Given** a certificate has a delegation
**When** verification runs
**Then** the delegation certificate is verified against the root public key first
**And** the canister ID must be within the delegation's canister ranges
**And** the certificate's signature is verified against the delegation's public key

### SCENARIO-CERT-005: Nested delegation rejected
**Given** a delegation certificate itself contains another delegation
**When** verification runs
**Then** verification fails with `MultipleSubnetDelegationsNotAllowed`

### SCENARIO-CERT-006: Canister ID out of range
**Given** the canister ID is not within any range in the delegation
**When** verification runs
**Then** verification fails with `CanisterIdOutOfRange`

### SCENARIO-CERT-007: Certified data mismatch
**Given** the certified data in the certificate tree does not match the expected value
**When** verification runs
**Then** verification fails with `CertifiedDataMismatch`

### SCENARIO-CERT-008: Invalid signature
**Given** the threshold signature on the certificate is invalid
**When** verification runs
**Then** verification fails with `InvalidSignature`

---

## REQ-CERT-003: Subnet Read State Verification

Certificates for subnet read state MUST use subnet-ID matching instead of canister-range checking.

### SCENARIO-CERT-009: Subnet read state certificate verification
**Given** `verify_certificate_for_subnet_read_state` is called
**When** verification runs
**Then** if a delegation is present, the delegation subnet ID must match the provided subnet ID
**And** canister range checks are skipped
**And** the signature is verified normally

### SCENARIO-CERT-010: Subnet ID mismatch in delegation
**Given** the provided subnet ID does not match the delegation's subnet ID
**When** verification runs
**Then** verification fails with `SubnetIdMismatch`

---

## REQ-CERT-004: Witness Generation

Witnesses MUST be generated to prove specific values in the certified state.

### SCENARIO-CERT-011: Generating a witness for a partial tree
**Given** `hash_tree.witness(partial_tree)` is called
**When** the witness is generated
**Then** a `MixedHashTree` is produced with actual values for nodes in the partial tree
**And** pruned hashes for nodes not in the partial tree
**And** the root digest of the witness matches the full hash tree's root digest

### SCENARIO-CERT-012: Certified state read with witness
**Given** `read_certified_state_with_exclusion(paths, exclusion)` is called
**When** the state is read
**Then** requested paths are materialized as a partial tree from the lazy tree
**And** a `MixedHashTree` witness is generated from the full hash tree
**And** the witness root hash matches the certification hash

---

## REQ-CERT-005: Signature Verification Caching

Certificate verification MUST support caching for efficiency.

### SCENARIO-CERT-013: Cached signature verification
**Given** `verify_certified_data_with_cache` is called
**When** the cache is checked
**Then** previously verified signatures are returned immediately from cache
**And** new signatures are verified and cached for subsequent calls

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-CERT-001 | Hash tree computation | narrative | rs/certification/tests/ |
| REQ-CERT-002 | Certificate verification | narrative | rs/certification/tests/ |
| REQ-CERT-003 | Subnet read state | narrative | rs/certification/tests/ |
| REQ-CERT-004 | Witness generation | narrative | rs/certification/tests/ |
| REQ-CERT-005 | Signature caching | narrative | rs/certification/tests/ |
