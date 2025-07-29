# Node Provider Reward Calculations

This document provides an overview of the Internet Computer's node provider reward calculation, including details about
node providers, operators, data centers, nodes, and the reward calculation process. The information is based on the
actual implementation in the Internet Computer codebase as of 2024 and 2025Q1, not on the plans for the upcoming
performance-based adjustments of node provider rewards.

## Table of Contents

- [Node Provider Reward Calculations](#node-provider-reward-calculations)
    - [Table of Contents](#table-of-contents)
    - [Core Components](#core-components)
        - [Node Provider (NP)](#node-provider-np)
        - [Node Operator (NO)](#node-operator-no)
        - [Data Center (DC)](#data-center-dc)
            - [Region Structure Details](#region-structure-details)
        - [Node](#node)
    - [Reward Calculation](#reward-calculation)
        - [Monthly Reward Calculation](#monthly-reward-calculation)
        - [Reward Distribution Process](#reward-distribution-process)
    - [Implementation Details](#implementation-details)
        - [Key Files:](#key-files)
        - [Important Interfaces:](#important-interfaces)
        - [Testing:](#testing)
    - [Administrative Procedures](#administrative-procedures)
        - [Changing Node Provider Wallet Address](#changing-node-provider-wallet-address)
            - [Prerequisites](#prerequisites)
            - [Instructions for MacOS](#instructions-for-macos)
            - [Instructions for Windows](#instructions-for-windows)
            - [Additional Operations](#additional-operations)
            - [Troubleshooting Tips](#troubleshooting-tips)

## Core Components

### Node Provider (NP)

A Node Provider is an entity that contributes to the Internet Computer network by providing nodes. The system tracks
Node Providers through a dedicated data structure defined in [
`ic_nns_governance_api::NodeProvider`](../nns/governance/api/src/ic_nns_governance.pb.v1.rs):

```rust
pub struct NodeProvider {
    /// The ID of the node provider (Principal ID)
    pub id: Option<PrincipalId>,
    /// Optional account where rewards are sent
    pub reward_account: Option<Account>,
}
```

Key characteristics:

- Each Node Provider has a unique principal ID for identification
- Can specify a reward account for receiving compensation
- May operate nodes across multiple data centers
- Must be registered through governance proposals before participating
- Can be updated via the `update_node_provider` API to modify settings

Source: The Node Provider management is primarily handled in the governance canister, as seen
in [governance.rs](../nns/governance/src/governance.rs).

### Node Operator (NO)

Node Operators handle the technical aspects of running nodes. They are defined through the `AddNodeOperatorPayload`
structure:

```rust
struct AddNodeOperatorPayload {
    node_operator_principal_id: Option<PrincipalId>,
    node_allowance: u64,
    node_provider_principal_id: Option<PrincipalId>,
    dc_id: String,
    rewardable_nodes: BTreeMap<String, u32>,
    ipv6: Option<String>,
    max_rewardable_nodes: Option<BTreeMap<String, u32>>
}
```

Key responsibilities:

- Technical management and maintenance of nodes
- Assignment to a specific data center
- Limited by node allowance for operation capacity
- Must be associated with a registered Node Provider
- Responsible for node health and performance

### Data Center (DC)

Data Centers are physical locations where nodes are hosted. They are defined in [
`ic_protobuf::registry::dc::v1::DataCenterRecord`](../protobuf/def/registry/dc/v1/dc.proto):

```rust
pub struct DataCenterRecord {
    pub id: String,
    pub region: String,
    pub owner: String,
    pub gps: Option<Gps>,
}
```

Important aspects:

- Unique identification through DC ID
- Hierarchical region structure (e.g., "North America,US,NY")
- Owner attribution
- Optional GPS coordinates for location verification
- Added/removed through `AddOrRemoveDataCentersProposalPayload`
- Different reward rates based on region

#### Region Structure Details

Based on the implementation code, the region structure has the following characteristics:

1. **Format and Validation**:
    - Regions follow a hierarchical structure (e.g., "North America,US,NY")
    - Region strings have a maximum length limit (`MAX_DC_REGION_LENGTH`)
    - Region values are validated during data center creation
    - There should be **no spaces after commas**

2. **Implementation Features**:
    - Regions are case-sensitive strings
    - Cannot be empty or exceed the maximum length
    - Used for reward rate calculations
    - Immutable after data center creation (based on test evidence)

3. **Security and Management**:
    - Only the governance canister can add/modify data centers
    - Region changes require removing and re-adding a data center
    - Regions are part of the immutable data center record

4. **Code References**:
    - [Region validation](../registry/canister/tests/add_or_remove_data_centers.rs)
    - [Region usage in rewards](../registry/canister/src/get_node_providers_monthly_xdr_rewards.rs)
    - [Modification controls](../nns/governance/src/governance.rs)

Reference: See [do_add_node_operator.rs](../registry/canister/src/mutations/do_add_node_operator.rs) for data center
validation logic.

### Node

Nodes are the fundamental infrastructure units of the Internet Computer:

Types:

- type0: Gen1 nodes with low storage capacity, not in use anymore
- type1: Gen1 nodes with increased storage capacity
- type1.1: Gen1 nodes with increased storage capacity and reduced rewards after the initial 48 month agreements
- type2: Not in use anymore
- type3: Currently used node types with decreasing reward scale

Reward calculation varies by:

- Node type
- Geographic location (DC region)
- For type3: Number of nodes (decreasing scale)

## Reward Calculation

### Monthly Reward Calculation

The reward calculation is implemented in [
`get_node_providers_monthly_xdr_rewards.rs`](../registry/canister/src/get_node_providers_monthly_xdr_rewards.rs). Each
node provider's monthly reward is calculated based on:

1. The node operators associated with that provider
2. The data centers where their nodes are located
3. The node reward table that defines reward rates per region and node type

The reward calculation works as follows:

1. Each node operator is associated with a node provider and manages nodes in a specific data center
2. The node reward table contains reward rates organized hierarchically by:
    - Geographic region (e.g., "North America,US,NY")
    - Node type (e.g., "type0", "type1", "type3")
    - For type3 nodes: A decay factor (e.g., 70%) that reduces rewards for additional nodes

3. Reward rates are looked up using the most specific matching region:
   ```json
   {
     "North America,US,NY":  { "type0": [240, null] },
     "North America,US":     { "type0": [677, null], "type1": [456, null] },
     "North America":        { "type0": [801, null] },
     "Europe":              { "type0": [68, null],  "type1": [11, null] }
   }
   ```
   For example, a type0 node in NY would get 240 XDR/month, while one in a different US location would get 677
   XDR/month.

4. The node rewards table is adjusted through governance proposals using `UpdateNodeRewardsTableProposalPayload`, which
   can:
    - Add new region entries
    - Update reward rates for existing regions
    - Add rates for new node types
    - Modify decay factors for type3 nodes


1. Base Calculation:

```rust
// Example reward calculation from tests
(4 * 240) + 456  // 4 'type1' nodes at 240 XDR + 1 'type3' node at 456 XDR
```

2. Type-3 Node Scaling:

```rust
// Example of type3 node reward calculation
let mut node_reward = base_reward;        // e.g., 22000000
let mut total_reward = 0;
for _ in 0..num_nodes {
total_reward += node_reward as u64;   // Add current node reward
node_reward *= 0.7;                   // Reduce by 30% for next node
}
// Each additional node of the same type in the same country gets 30% less reward
```

Important details about cross-location rewards for Type-3 node rewards:

1. Country-based Decay Sequence:
    - Each country maintains its own independent decay sequence
    - When a node provider adds nodes in a new country, rewards start fresh at the base rate
    - For example: A node provider with 14 nodes in Switzerland and 11 in Germany
      would have two separate reward calculations, each starting at the full rate

2. Data Center Consolidation:
    - Multiple data centers within the same country share a single decay sequence
    - The reward reduction continues across all data centers in that country
    - For example: If a provider has 14 nodes in Zurich (Switzerland) at 70% decay per node,
      adding 10 more nodes in Basel (Switzerland) would continue from the decay after the initial 14 nodes

3. Node Type Independence:
    - Type0 and type1 nodes always receive their full regional rate
    - Only type3 nodes are subject to the decay factor
    - Different node types are calculated independently

3. Reward Constraints:
    - Maximum monthly reward: 1M ICP (configurable)
    - Minimum XDR/ICP conversion rate enforcement
    - Region-specific rate tables

Source: The reward calculation implementation can be found
in [get_node_providers_monthly_xdr_rewards.rs](../registry/canister/src/get_node_providers_monthly_xdr_rewards.rs).

### Reward Distribution Process

Rewards are distributed through the following process:

1. Monthly Calculation:

```rust
pub struct MonthlyNodeProviderRewards {
    pub timestamp: u64,
    pub rewards: Vec<RewardNodeProvider>,
    pub xdr_conversion_rate: Option<XdrConversionRate>,
    pub minimum_xdr_permyriad_per_icp: Option<u64>,
    pub maximum_node_provider_rewards_e8s: Option<u64>,
    pub registry_version: Option<u64>,
    pub node_providers: Vec<NodeProvider>,
}
```

2. Distribution Methods:

- Direct transfer to reward account
- Neuron creation (staking)

3. Record Keeping:

```rust
pub fn record_node_provider_rewards(most_recent_rewards: MonthlyNodeProviderRewards)
```

The system maintains an archive of all reward distributions for transparency and auditing.

## Implementation Details

### Key Files:

- [node_provider_rewards.rs](../nns/governance/src/node_provider_rewards.rs) - Reward tracking and distribution
- [get_node_providers_monthly_xdr_rewards.rs](../registry/canister/src/get_node_providers_monthly_xdr_rewards.rs) -
  Reward calculation
- [governance.rs](../nns/governance/src/governance.rs) - Node Provider management
- [do_add_node_operator.rs](../registry/canister/src/mutations/do_add_node_operator.rs) - Node Operator management

### Important Interfaces:

1. Node Provider Management:

```rust
fn update_node_provider(&self, caller: &PrincipalId, update: UpdateNodeProvider)
fn get_node_provider_by_caller() -> Result<NodeProvider, GovernanceError>
fn list_node_providers() -> ListNodeProvidersResponse
```

2. Reward Management:

```rust
fn get_monthly_node_provider_rewards() -> Result<MonthlyNodeProviderRewards>
fn list_node_provider_rewards(date_filter: Option<DateRangeFilter>)
fn get_most_recent_monthly_node_provider_rewards()
```

### Testing:

The system includes comprehensive test coverage:

- Unit tests for reward calculations
- Integration tests for Node Provider management
- System tests for reward distribution

For examples, see:

- [node_provider_rewards.rs](../nns/governance/tests/node_provider_rewards.rs)
- [node_provider_remuneration.rs](../nns/integration_tests/src/node_provider_remuneration.rs)

## Administrative Procedures

### Changing Node Provider Wallet Address

This section provides detailed instructions for changing your wallet address in the NNS using an HSM (Hardware Security
Module).

#### Prerequisites

- Latest version of Quill (minimum v0.2.14)
- OpenSC installed (latest releases available at [OpenSC releases](https://github.com/OpenSC/OpenSC/releases))
- System reboot recommended before proceeding

#### Instructions for MacOS

1. **Install/Update Quill**
    - Download the latest Quill release from [Quill releases](https://github.com/dfinity/quill/releases/)
    - Open Terminal
    - Run: `install ~/Downloads/quill-macos-x86_64 /usr/local/bin/quill`
    - If prompted about security, go to System Settings → Privacy & Security → click "Allow Anyway"
    - Verify installation with `quill --version`

2. **Update Wallet Address**
    - Insert HSM stick (ensure no other security keys or storage drives are connected)
    - Run: `quill --hsm update-node-provider --reward-account YOUR_WALLET_ADDRESS > out.json`
    - Enter your 6-digit HSM PIN when prompted
    - Run: `quill send out.json`
    - Confirm by typing 'y' when prompted

Note: Some systems may work without the `--hsm` flag. If you encounter errors, try removing it from the commands.

#### Instructions for Windows

1. **Install/Update Quill**
    - Delete any old version from Program Files
    - Download latest version from [Quill releases](https://github.com/dfinity/quill/releases/)
    - Move the downloaded file to Program Files

2. **Update Wallet Address**
    - Open Command Prompt as Administrator
    - Navigate to Program Files: `cd /` then `cd Program Files`
    - Run: `quill-windows-x86_64 --hsm update-node-provider --reward-account YOUR_WALLET_ADDRESS > out.json`
    - Enter your 6-digit HSM PIN when prompted
    - Run: `quill-windows-x86_64 send out.json`
    - Confirm by typing 'y' when prompted

#### Additional Operations

1. **Sending ICP from Principal Account (MacOS)**

```
quill --hsm transfer RECEIVING_WALLET_ADDRESS --amount AMOUNT > message.json
quill send message.json
```

2. **Sending ICP from Principal Account (Windows)**

```
quill-windows-x86_64 --hsm --hsm-libpath "c:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll" transfer RECEIVING_WALLET_ADDRESS --amount AMOUNT > out.json
quill-windows-x86_64 send out.json
```

3. **Viewing Account Information**

- View transactions on [IC Dashboard](https://dashboard.internetcomputer.org/account/)
- Get HSM principal/account IDs:
    - MacOS: `quill public-ids --hsm`
    - Windows:
      `quill-windows-x86_64 public-ids --hsm --hsm-libpath "c:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll"`

#### Troubleshooting Tips

- Ensure no line breaks in commands
- Keep sufficient ICP for transaction fees (currently 0.0001 ICP)
- For Mac security issues, follow [Apple documentation](https://support.apple.com/en-us/HT202491)
- Ignore HSM error messages about "Error adding objects" - these don't affect functionality
