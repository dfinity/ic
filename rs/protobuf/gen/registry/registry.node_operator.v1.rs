/// A record for a node operator. Each node operator is associated with a
/// unique principal id, a.k.a. NOID.
///
/// Note that while a node operator might host nodes for more than
/// one funding parter, its principal ID must be unique.
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize, Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeOperatorRecord {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    ///
    /// This must be unique across NodeOperatorRecords.
    #[prost(bytes="vec", tag="1")]
    pub node_operator_principal_id: ::prost::alloc::vec::Vec<u8>,
    /// The remaining number of nodes that could be added by this node operator.
    /// This number should never go below 0.
    #[prost(uint64, tag="2")]
    pub node_allowance: u64,
    /// The principal id of this node operator's provider.
    #[prost(bytes="vec", tag="3")]
    pub node_provider_principal_id: ::prost::alloc::vec::Vec<u8>,
    /// The ID of the data center where this Node Operator hosts nodes.
    #[prost(string, tag="4")]
    pub dc_id: ::prost::alloc::string::String,
    /// A map from node type to the number of nodes for which the associated Node
    /// Provider should be rewarded.
    #[prost(btree_map="string, uint32", tag="5")]
    pub rewardable_nodes: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, u32>,
    #[prost(string, optional, tag="6")]
    pub ipv6: ::core::option::Option<::prost::alloc::string::String>,
}
//// The payload of a request to remove Node Operator records from the Registry
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize, Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveNodeOperatorsPayload {
    #[prost(bytes="vec", repeated, tag="1")]
    pub node_operators_to_remove: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
