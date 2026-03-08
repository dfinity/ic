# Registry Sub-crates

## Overview

This specification covers the supporting sub-crates within the registry module: derive macros for `ic-admin`, the registry canister API types, the chunkification layer for large values, the common protobuf definitions, and the local store artifacts.

---

## Crate: `ic-admin-derive`

**Path:** `rs/registry/admin-derive`

### Purpose

Provides proc-macro derive macros used by the `ic-admin` CLI tool to reduce boilerplate when defining NNS proposal command structs.

### Derive Macro: `#[derive(ProposalMetadata)]`

Generates an implementation of the `ProposalMetadata` trait for the annotated struct.

**Generated implementation:**
```rust
impl ProposalMetadata for MyProposal {
    fn summary(&self) -> String {
        summary_from_string_or_file(&self.summary, &self.summary_file)
    }
    fn url(&self) -> String {
        parse_proposal_url(&self.proposal_url)
    }
    fn proposer_and_sender(&self, sender: Sender) -> (NeuronId, Sender) {
        let use_test_neuron = self.test_neuron_proposer
            || (self.dry_run && matches!(sender, Sender::Anonymous));
        get_proposer_and_sender(self.proposer.clone(), sender, use_test_neuron)
    }
    fn is_dry_run(&self) -> bool { self.dry_run }
    fn is_json(&self) -> bool { self.json }
}
```

**Required fields on the struct:** `summary`, `summary_file`, `proposal_url`, `proposer`, `test_neuron_proposer`, `dry_run`, `json`.

### Attribute Macro: `#[derive_common_proposal_fields]`

Injects a standard set of fields into any struct definition. This is an attribute macro (not a derive macro) that modifies the struct's token stream to prepend common fields.

**Injected fields:**

| Field | Type | Description |
|---|---|---|
| `proposer` | `Option<NeuronId>` | The neuron ID for proposal submission. |
| `test_neuron_proposer` | `bool` | Use a test proposer neuron (ignored if `proposer` is set). |
| `proposal_url` | `Option<Url>` | HTTPS URL for additional proposal context. |
| `proposal_title` | `Option<String>` | Human-readable proposal title. |
| `summary` | `Option<String>` | Markdown summary of the proposal. |
| `summary_file` | `Option<PathBuf>` | File containing the summary (overrides `summary`). |
| `dry_run` | `bool` | Print the payload without submitting. |
| `json` | `bool` | Output JSON format for `--dry-run`. |

All fields are annotated with `#[clap(long)]` for CLI argument parsing.

### Implementation Note

The attribute macro works by scanning the token stream for `struct` keyword followed by a braced group, then prepending the common fields into that group.

---

## Crate: `ic-registry-canister-api`

**Path:** `rs/registry/canister/api`

### Purpose

Defines the Candid API types for the registry canister, including node registration payloads, IPv4 configuration, and chunk-based data retrieval.

### Dependencies

- `attestation` -- SEV-SNP attestation verification for node registration.
- `der` -- ASN.1 DER encoding for attestation custom data.
- `ic-base-types` -- `NodeId` and other base types.
- `ic-nervous-system-chunks` -- Chunked storage for large values.
- `ic-registry-transport` -- Registry mutation protobuf types.

### Public Types

#### `NodeRegistrationAttestationCustomData`

```
#[derive(der::Sequence)]
pub struct NodeRegistrationAttestationCustomData<'a> {
    pub node_signing_pk: OctetStringRef<'a>,
}
```

DER-encoded custom data embedded in SEV-SNP attestation reports. Binds the attestation to a specific node by including the node signing public key. Implements `DerEncodedCustomData` with namespace `SevCustomDataNamespace::NodeRegistration`.

**Encoding stability:** The DER encoding is tested to be stable across versions (fixed expected byte output in tests).

#### `IPv4Config`

```
pub struct IPv4Config {
    ip_addr: String,
    gateway_ip_addr: String,
    prefix_length: u32,
}
```

**Constructors:**
- `maybe_invalid_new(ip_addr, gateway_ip_addr, prefix_length)` -- Constructs without validation (for backward compatibility).
- `try_new(ip_addr, gateway_ip_addr, prefix_length) -> Result<Self, IPv4ConfigError>` -- Validates:
  1. Both addresses are valid IPv4.
  2. Prefix length is 0-32.
  3. Both addresses are in the same subnet.
  4. The IP address is a globally routable address.

**Global address validation:** Rejects benchmarking (198.18.0.0/17), broadcast, documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), link-local, private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, reserved (240.0.0.0/4), shared (100.64.0.0/10), and unspecified addresses.

#### `IPv4ConfigError`

Error enum: `InvalidIPv4Address`, `InvalidGatewayAddress`, `InvalidPrefixLength`, `NotInSameSubnet`, `NotGlobalIPv4Address`.

#### `AddNodePayload`

The payload for `add_node` registry mutations:

| Field | Type | Description |
|---|---|---|
| `node_signing_pk` | `Vec<u8>` | Protobuf-encoded PublicKey. |
| `committee_signing_pk` | `Vec<u8>` | Protobuf-encoded PublicKey. |
| `ni_dkg_dealing_encryption_pk` | `Vec<u8>` | Protobuf-encoded PublicKey. |
| `transport_tls_cert` | `Vec<u8>` | Protobuf-encoded X509PublicKeyCert. |
| `idkg_dealing_encryption_pk` | `Option<Vec<u8>>` | Protobuf-encoded PublicKey. |
| `xnet_endpoint` | `String` | XNet endpoint URL. |
| `http_endpoint` | `String` | HTTP endpoint URL. |
| `node_registration_attestation` | `Option<SevAttestationPackage>` | SEV-SNP attestation for hardware verification. |
| `public_ipv4_config` | `Option<IPv4Config>` | Public IPv4 configuration. |
| `domain` | `Option<String>` | Domain name. |
| `p2p_flow_endpoints` | `Vec<String>` | **Deprecated.** |
| `prometheus_metrics_endpoint` | `String` | **Deprecated.** |
| `node_reward_type` | `Option<String>` | Node reward classification string. |

#### `UpdateNodeDirectlyPayload`

For updating node keys: `{ idkg_dealing_encryption_pk: Option<Vec<u8>> }`.

#### `UpdateNodeIPv4ConfigDirectlyPayload`

For updating node IPv4 config: `{ node_id: NodeId, ipv4_config: Option<IPv4Config> }`.

#### `GetChunkRequest` / `Chunk`

For retrieving large registry values stored as chunks:
- `GetChunkRequest { content_sha256: Option<Vec<u8>> }` -- Request a chunk by its SHA-256 hash.
- `Chunk { content: Option<Vec<u8>> }` -- The chunk content.

#### `GetNodeProvidersMonthlyXdrRewardsRequest`

`{ registry_version: Option<u64> }` -- Request node provider rewards at a specific registry version.

---

## Crate: `ic-registry-canister-chunkify`

**Path:** `rs/registry/canister/chunkify`

### Purpose

Handles chunking and dechunking of large registry values that exceed the registry changelog size limit. Values below `MIN_CHUNKABLE_VALUE_LEN` (10,000 bytes) are stored inline; larger values are split into chunks stored in `ic-nervous-system-chunks` and referenced by SHA-256 hashes.

### Constants

- `MIN_CHUNKABLE_VALUE_LEN: usize = 10_000` -- Threshold for chunking. Chosen as a balance between the 32-byte SHA-256 overhead and the 1.3 MiB registry changelog limit.

### Public Functions

#### `chunkify_composite_mutation<M: Memory>`

```
pub fn chunkify_composite_mutation<M: Memory>(
    original_mutation: RegistryAtomicMutateRequest,
    chunks: &mut Chunks<M>,
) -> HighCapacityRegistryAtomicMutateRequest
```

Converts a standard registry atomic mutation request into a high-capacity request:
- Each prime mutation's value is checked against `MIN_CHUNKABLE_VALUE_LEN`.
- Small values are stored inline as `Content::Value(bytes)`.
- Large values are split via `chunks.upsert_monolithic_blob()` and stored as `Content::LargeValueChunkKeys(LargeValueChunkKeys { chunk_content_sha256s })`.

#### `dechunkify_registry_value<M: Memory>`

```
pub fn dechunkify_registry_value<M: Memory>(
    content: high_capacity_registry_value::Content,
    chunks: &Chunks<M>,
) -> Option<Vec<u8>>
```

Resolves a high-capacity registry value back to raw bytes:
- `Content::Value(bytes)` -- Returns `Some(bytes)`.
- `Content::DeletionMarker(true)` -- Returns `None` (deleted key).
- `Content::DeletionMarker(false)` -- Returns `Some(vec![])` (empty value).
- `Content::LargeValueChunkKeys(keys)` -- Fetches and concatenates chunks.

#### `dechunkify_prime_mutation_value<M: Memory>`

Resolves a high-capacity mutation's new value:
- Delete mutations return `None`.
- Insert/upsert mutations return the resolved value via `Content::Value` or `Content::LargeValueChunkKeys`.

#### `dechunkify<M: Memory>`

```
pub fn dechunkify<M: Memory>(
    large_value_chunk_keys: &LargeValueChunkKeys,
    chunks: &Chunks<M>,
) -> Vec<u8>
```

Low-level helper: fetches all chunks by their SHA-256 keys and concatenates the results. **Panics** if any chunk is not found.

#### `decode_high_capacity_registry_value<R, M>`

Generic decoder that dechunkifies and then decodes the resulting bytes as a protobuf message type `R`:
- `DeletionMarker(true)` returns `None`.
- Missing content or `DeletionMarker(false)` decodes empty bytes (per protobuf convention).
- **Panics** on decode failure.

---

## Crate: `ic-registry-common-proto`

**Path:** `rs/registry/proto`

### Purpose

Defines the common protobuf types shared across registry components. The crate re-exports generated protobuf Rust code under the `pb` module.

### Module Structure

```
lib.rs -> pub mod pb
pb/mod.rs -> pub mod local_store; pub mod proto_registry; pub mod test_protos;
```

**Sub-modules:**
- `pb::local_store` -- Protobuf types for the registry local store format.
- `pb::proto_registry` -- Core registry protobuf types (versioned values, deltas, etc.).
- `pb::test_protos` -- Test-only protobuf types.

The actual protobuf Rust code is generated at build time and included from `src/gen/`.

---

## Crate: `ic-registry-local-store-artifacts`

**Path:** `rs/registry/local_store/artifacts`

### Purpose

Bundles a protobuf-encoded snapshot of the mainnet registry state as a compile-time constant. This is used for bootstrapping nodes and tests that need a realistic registry state.

### Public Constants

```
pub const MAINNET_DELTA_00_6D_C1: &[u8] = include_bytes!("../mainnet_delta_00-6d-c1.pb");
```

Contains the protobuf-encoded registry deltas from the mainnet registry, embedded as a byte array via `include_bytes!`. The suffix `00_6D_C1` corresponds to a specific registry version range.
